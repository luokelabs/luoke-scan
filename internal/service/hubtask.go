package service

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	assets "github.com/luokelabs/luoke-scan"
	"github.com/luokelabs/luoke-scan/internal/core"
)

// NewModelLink is how a round reaches luoke-core's model for its three generate tasks (explain, identify, skills):
// where luoke-core's socket is, where the prompts are, and how much of the round it may take (as the Swift version's
// defaults: 180 s in all, 90 s a question, at most 10, 5 and 10 new questions a round, an answer kept 30 days unused).
func NewModelLink(socket, accessory string, prompts fs.FS) *ModelLink {
	return &ModelLink{Socket: socket, Accessory: accessory, Prompts: prompts, AskNew: true, Budget: 180 * time.Second,
		RequestTimeout: 90 * time.Second, Caps: map[string]int{core.ExplainTask: 10, core.IdentifyTask: 5, core.SkillReviewTask: 10},
		KeepFor: 30 * 24 * time.Hour}
}

// ModelForRun is the link for a run of luoke-scan on this Mac, or nil when it does not talk to luoke-core (as
// ShouldRemember: the installed app, or a development build given a luoke-core of its own).
func ModelForRun(packaged, otherData bool, version string, askNew bool, env map[string]string) *ModelLink {
	if !ShouldRemember(packaged, otherData, env) {
		return nil
	}
	prompts, ok := Prompts(packaged)
	if !ok {
		return nil
	}
	l := NewModelLink(HubSocket(env), "luoke-scan/"+version, prompts)
	l.AskNew = askNew
	return l
}

// Prompts are the prompt files: the packed build's are inside the program (assets, signed with it); in development
// the repository's prompts/, found above the program, so an edited prompt is used without building again.
func Prompts(packaged bool) (fs.FS, bool) {
	if packaged {
		p, err := fs.Sub(assets.FS, "prompts")
		if err != nil {
			return nil, false
		}
		_, err = fs.Stat(p, "explain.task.json")
		return p, err == nil
	}
	if d, ok := PromptsDirectory(); ok {
		return os.DirFS(d), true
	}
	return nil, false
}

// PromptsDirectory is the repository's prompts/ above a development build of this program.
func PromptsDirectory() (string, bool) {
	has := func(d string) bool { return core.Exists(filepath.Join(d, "explain.task.json")) }
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	dir := filepath.Dir(exe)
	for i := 0; i < 6; i++ {
		if d := filepath.Join(dir, "prompts"); has(d) {
			return d, true
		}
		dir = filepath.Dir(dir)
	}
	return "", false
}

// hubAvailable are the tasks GET /tasks says are available now; nil when luoke-core does not answer.
func hubAvailable(l *ModelLink) map[string]bool {
	tasks, ok := jsonGet(askHub(l.Socket, "/tasks", l.Accessory, 2*time.Second), "tasks").(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]bool{}
	for name, t := range tasks {
		if s, _ := jsonString(jsonGet(t, "status")); s == "available" {
			out[name] = true
		}
	}
	return out
}

// HubReply is what one generate request got: an answer, a refusal (luoke-core's code and how long it says to wait), or
// nothing (not connected, broken, too slow, not HTTP).
type HubReply struct {
	Kind         string // "answer", "refused", "failed"
	Text         string // answer: the content; failed: why
	Code         string // refused: busy, unsupported…
	RetryAfterMs *int
}

// hubGenerate is POST /tasks/<task>/v1/chat/completions with body (ModelPrompt.Body), at background priority, all of
// it within timeout.
func hubGenerate(l *ModelLink, task, body string, timeout time.Duration) HubReply {
	deadline := time.Now().Add(timeout)
	c := hubConnect(l.Socket, timeout)
	if c == nil {
		return HubReply{Kind: "failed", Text: "连不上主控"}
	}
	defer c.Close()
	head := "POST /tasks/" + task + "/v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nX-Luoke-Accessory: " + l.Accessory + "\r\n" +
		"X-Luoke-Priority: background\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n"
	reply, closed, late, sent := hubExchange(c, []byte(head+body), deadline, hubFinished)
	if !sent {
		return HubReply{Kind: "failed", Text: "没发出去"}
	}
	if late {
		return HubReply{Kind: "failed", Text: "超时"}
	}
	return hubParse(reply, closed)
}

// hubFinished says whether the reply so far holds all there is to read: a refusal with its whole body, the stream's
// end, an error event.
func hubFinished(reply []byte) bool {
	split := bytes.Index(reply, crlf2)
	if split < 0 {
		return false
	}
	head := strings.ToLower(decodeUTF8(reply[:split]))
	if !strings.HasPrefix(head, "http/1.1 200") && !strings.HasPrefix(head, "http/1.0 200") {
		return hubComplete(reply)
	}
	rest := reply[split+4:]
	if bytes.Contains(rest, []byte("data: [DONE]")) {
		return true
	}
	e := bytes.Index(rest, []byte("event: luoke.error"))
	return e >= 0 && bytes.Contains(rest[e+len("event: luoke.error"):], []byte("\n\n"))
}

func hubRefused(o any, fallback string) HubReply {
	code, ok := jsonString(jsonGet(o, "code"))
	if !ok {
		code = fallback
	}
	r := HubReply{Kind: "refused", Code: code}
	if ms, ok := jsonInt(jsonGet(o, "retry_after_ms")); ok {
		r.RetryAfterMs = &ms
	} else if s, ok := jsonInt(jsonGet(o, "retry_after")); ok {
		ms := s * 1000
		r.RetryAfterMs = &ms
	}
	return r
}

// hubParse is what a reply says: the content of the streamed chunks, or the refusal. Whatever is wrong in it gives a
// failure, never a crash.
func hubParse(reply []byte, closed bool) HubReply {
	split := bytes.Index(reply, crlf2)
	if split < 0 {
		return HubReply{Kind: "failed", Text: "不是 HTTP 答复"}
	}
	head := strings.ToLower(decodeUTF8(reply[:split]))
	status := 0
	if words := strings.FieldsFunc(head, func(r rune) bool { return r == ' ' }); len(words) > 1 {
		status, _ = strconv.Atoi(words[1])
	}
	rest := reply[split+4:]
	if strings.Contains(head, "transfer-encoding: chunked") {
		rest = dechunked(rest)
	} else if n, ok := hubContentLength(reply[:split]); status != 200 && ok && n < len(rest) {
		rest = rest[:n]
	}
	if status != 200 {
		o, _ := parseJSON(rest)
		return hubRefused(o, "http_"+strconv.Itoa(status))
	}
	var parts []string
	event, hasEvent, done := "", false, false
	for _, raw := range core.SplitCharacterLF(decodeUTF8(rest)) {
		line := strings.TrimSuffix(raw, "\r")
		switch {
		case strings.HasPrefix(line, "event: "):
			event, hasEvent = strings.Trim(line[len("event: "):], " \t"), true
		case strings.HasPrefix(line, "data: "):
			data := line[len("data: "):]
			if hasEvent && event == "luoke.error" {
				o, _ := parseJSON([]byte(data))
				return hubRefused(o, "error")
			}
			if hasEvent {
				hasEvent = false
				continue
			}
			if strings.Trim(data, " \t") == "[DONE]" {
				done = true
			} else {
				chunk, ok := parseJSON([]byte(data))
				if !ok {
					return HubReply{Kind: "failed", Text: "流里有认不出的一块"}
				}
				choices, _ := jsonGet(chunk, "choices").([]any)
				for _, ch := range choices {
					s, _ := jsonString(jsonGet(jsonGet(ch, "delta"), "content"))
					parts = append(parts, s)
				}
			}
		case line == "":
			hasEvent = false
		}
		if done {
			break
		}
	}
	if !done {
		if closed {
			return HubReply{Kind: "failed", Text: "流断了"}
		}
		return HubReply{Kind: "failed", Text: "超时"}
	}
	return HubReply{Kind: "answer", Text: strings.Join(parts, "")}
}

// dechunked is the body of a chunked reply, as far as it goes (a stream cut short gives what came).
func dechunked(d []byte) []byte {
	rest := d
	var out []byte
	for {
		line := bytes.Index(rest, []byte("\r\n"))
		if line < 0 {
			break
		}
		size, err := strconv.ParseInt(strings.Trim(firstField(decodeUTF8(rest[:line]), ";"), " \t"), 16, 64)
		if err != nil || size < 0 || size == 0 {
			break
		}
		start := line + 2
		available := int64(len(rest) - start)
		out = append(out, rest[start:start+int(min(size, available))]...)
		if available < size+2 {
			break
		}
		rest = rest[start+int(size)+2:]
	}
	return out
}

// ---------------------------------------------------------------- the round's findings, with what the model says

// withModel is the round's findings with what luoke-core's model says about them, as evidence that changes nothing
// the rules set: skills that do more than they say (SkillReview), names for folders the rules cannot name (Identify),
// plain words for what the round's card shows (Explain). Only tasks GET /tasks says are available; answers kept from
// earlier rounds (same prompt, same input) are used without asking; new questions stop at the task's cap, the link's
// budget, the round being cancelled, or the task's first refusal or failure. luoke-core not answering, a task not open
// on this Mac (in beta 2 they ship closed): the report as it was, at the cost of one quick GET /tasks.
func (s *Service) withModel(report core.Report, ctx *core.Context) core.Report {
	link := s.Config.Model
	if link == nil || ctx.IsCancelled() || len(report.Findings) == 0 {
		return report
	}
	open := hubAvailable(link)
	if len(open) == 0 {
		return report
	}
	deadline := time.Now().Add(link.Budget)
	findings := append([]core.Finding(nil), report.Findings...)
	run := func(name, task string, indices []int, input func(int) (core.Value, bool), apply func(int, string, core.Value)) {
		if !open[task] || len(indices) == 0 {
			return
		}
		prompt, err := core.LoadPromptFS(name, link.Prompts)
		if err != nil || prompt.Task != task {
			return
		}
		kept := s.Store.ModelAnswers(task)
		fresh, used := map[string]string{}, map[string]bool{}
		asked, stopped := 0, !link.AskNew
		for _, i := range indices {
			if ctx.IsCancelled() {
				stopped = true
			}
			value, ok := input(i)
			if !ok {
				continue
			}
			key := prompt.Key(value)
			if a, ok := kept[key]; ok {
				used[key] = true
				apply(i, a, value)
				continue
			}
			if a, ok := fresh[key]; ok {
				used[key] = true
				apply(i, a, value)
				continue
			}
			if stopped || asked >= link.Caps[task] || !time.Now().Before(deadline) {
				continue
			}
			body, err := prompt.Body(value)
			if err != nil {
				continue
			}
			asked++
			reply := hubGenerate(link, task, body, min(link.RequestTimeout, time.Until(deadline)))
			// One short wait when luoke-core says how long (a power step's pause, someone typing), then no more. A
			// negative wait is not one (it would end the round before its report is saved).
			if reply.Kind == "refused" && reply.Code == "busy" && reply.RetryAfterMs != nil {
				ms := *reply.RetryAfterMs
				wait := time.Duration(ms) * time.Millisecond
				if ms >= 0 && ms <= 5000 && time.Now().Add(wait).Before(deadline) {
					time.Sleep(wait)
					reply = hubGenerate(link, task, body, min(link.RequestTimeout, time.Until(deadline)))
				}
			}
			if reply.Kind != "answer" {
				stopped = true
				continue
			}
			fresh[key], used[key] = reply.Text, true
			apply(i, reply.Text, value)
		}
		now := time.Now()
		s.Store.WriteModelAnswers(task, fresh, used, now, now.Add(-link.KeepFor))
	}

	// Skills: what the rules reported, most serious first; the skill read again to give the model what the rules saw.
	var skillAsks []int
	{
		var asked []core.Finding
		for _, f := range findings {
			if core.SkillReviewAsks(f) {
				asked = append(asked, f)
			}
		}
		for _, f := range bySeverity(asked) {
			if i := firstIndexOf(findings, f); i >= 0 {
				skillAsks = append(skillAsks, i)
			}
		}
	}
	if open[core.SkillReviewTask] && len(skillAsks) > 0 {
		skills := map[string]core.Skill{}
		for _, sk := range core.FindSkills(ctx, core.SkillPlaces, core.DefaultSkillLimits(), true).Skills {
			k := sk.RealFolder + "|" + sk.Digest
			if _, seen := skills[k]; !seen {
				skills[k] = sk
			}
		}
		run("skills", core.SkillReviewTask, skillAsks, func(i int) (core.Value, bool) {
			sk, ok := skills[findings[i].Key]
			if findings[i].Key == "" || !ok {
				return core.Value{}, false
			}
			return core.SkillReviewInput(sk, core.SkillSignals(sk), core.DefaultSkillReviewLimits()), true
		}, func(i int, raw string, _ core.Value) {
			sk, ok := skills[findings[i].Key]
			if findings[i].Key == "" || !ok {
				return
			}
			if a, ok := core.SkillReviewAnswer(raw, sk); ok {
				findings[i] = core.SkillReviewAnnotate(findings[i], a)
			}
		})
	}

	// Identify: the folders the rules cannot name, the biggest first; only as many as could be asked about (each is
	// listed to make its input, kept answer or not).
	var idAsks []int
	for i, f := range findings {
		if core.IdentifyAsks(f, ctx.Home) && ctx.MayLook(f.Path) {
			idAsks = append(idAsks, i)
		}
	}
	sort.SliceStable(idAsks, func(a, b int) bool { return sizeOf(findings[idAsks[a]]) > sizeOf(findings[idAsks[b]]) })
	if n := 2 * link.Caps[core.IdentifyTask]; len(idAsks) > n {
		idAsks = idAsks[:n]
	}
	run("identify", core.IdentifyTask, idAsks, func(i int) (core.Value, bool) {
		p := findings[i].Path
		return core.IdentifyInput(p, ctx.Shown(p), findings[i].Bytes, ctx.Now, core.DefaultIdentifyLimits())
	}, func(i int, raw string, _ core.Value) {
		if a, ok := core.IdentifyAnswer(raw); ok {
			if note, ok := core.IdentifyNote(a); ok {
				findings[i] = core.WithEvidence(findings[i], core.IdentifyNoteKey, note)
			}
		}
	})

	// Explain: what the round's card puts before the user, the most serious and biggest first.
	var exAsks []int
	for i, f := range findings {
		if core.ExplainAsks(f) {
			exAsks = append(exAsks, i)
		}
	}
	sort.SliceStable(exAsks, func(a, b int) bool {
		x, y := findings[exAsks[a]], findings[exAsks[b]]
		if x.Severity.Rank() != y.Severity.Rank() {
			return x.Severity.Rank() > y.Severity.Rank()
		}
		if sizeOf(x) != sizeOf(y) {
			return sizeOf(x) > sizeOf(y)
		}
		return exAsks[a] < exAsks[b]
	})
	maxChars := 120
	if p, err := core.LoadPromptFS("explain", link.Prompts); err == nil && p.HasMaxChars() {
		maxChars = int(p.MaxChars)
	}
	run("explain", core.ExplainTask, exAsks, func(i int) (core.Value, bool) {
		place := ""
		if findings[i].Path != "" {
			place = s.display(findings[i].Path)
		}
		return core.ExplainInput(findings[i], place), true
	}, func(i int, raw string, input core.Value) {
		if sentence, ok := core.ExplainAnswer(raw, findings[i], input, maxChars); ok {
			findings[i] = core.WithEvidence(findings[i], core.ExplainNoteKey, sentence)
		}
	})

	report.Findings = findings
	return report
}

func sizeOf(f core.Finding) int64 {
	if f.Bytes == nil {
		return 0
	}
	return *f.Bytes
}

// firstIndexOf is the index of the first finding equal to f in all of its fields (the Swift version's
// firstIndex { $0 == f }), or -1.
func firstIndexOf(findings []core.Finding, f core.Finding) int {
	for i, g := range findings {
		if sameFinding(g, f) {
			return i
		}
	}
	return -1
}

func sameFinding(a, b core.Finding) bool {
	if a.Rule != b.Rule || a.Category != b.Category || a.Severity != b.Severity || a.Verdict != b.Verdict || a.Path != b.Path ||
		a.Title != b.Title || a.Key != b.Key || (a.Bytes == nil) != (b.Bytes == nil) || (a.Bytes != nil && *a.Bytes != *b.Bytes) ||
		len(a.Evidence) != len(b.Evidence) {
		return false
	}
	for k, v := range a.Evidence {
		if w, ok := b.Evidence[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// modelLines is what the model said about a finding, as lines to show under it: the name of a folder, the plain
// words, the note on a skill.
func modelLines(f core.Finding) []string {
	var out []string
	for _, k := range []string{core.IdentifyNoteKey, core.ExplainNoteKey, core.SkillNoteKey} {
		if v := f.Evidence[k]; v != "" {
			out = append(out, v)
		}
	}
	return out
}
