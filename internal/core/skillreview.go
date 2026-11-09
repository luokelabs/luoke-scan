package core

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The semantic check of a skill: does what it says it does (its name and description) match what its instructions
// and scripts do? Asked of luoke-core's local model as the generate task luoke-scan.skills (prompts/skills.*), so a
// skill's contents never leave this Mac. Rules decide, the model only explains (decided 11-02): only a skill the
// static checks reported is asked about, and only when the model finds that it does more than it says is a note
// attached to that finding (what it actually does, and what goes beyond its description), without changing its
// severity, verdict, title or key. This file builds what the model is given and checks what it answers; luoke-core is
// asked in the service's withModel (task luoke-scan.skills).

// SkillReviewTask is luoke-core's name for it. The note is evidence SkillNoteKey (reporttext.go; not "model": that
// names an AI model in other rules' findings).
const SkillReviewTask = "luoke-scan.skills"

// SkillReviewAsks says whether a finding's skill is asked about: one the static checks reported, not the note that
// the round stopped early (and not the instruction files, agentfile.*).
func SkillReviewAsks(f Finding) bool {
	return f.Category == CatSkill && strings.HasPrefix(f.Rule, "skill.") && f.Rule != "skill.partial"
}

// SkillReviewLimits bound the input. Total is the whole JSON as sent, in Unicode scalars, escapes and keys included:
// about what luoke-core was asked to plan for. The others bound single parts, in the same unit.
type SkillReviewLimits struct {
	Total, Description, Instructions int
	// File: each other file; Files: how many.
	File, Files, Tools int
	// Listing: the file list, in all.
	Listing, Signals int
}

// DefaultSkillReviewLimits are the limits the scan and the evalset use.
func DefaultSkillReviewLimits() SkillReviewLimits {
	return SkillReviewLimits{Total: 6000, Description: 500, Instructions: 3000, File: 1200, Files: 4, Tools: 10, Listing: 1500, Signals: 12}
}

func reviewKindName(k SkillFileKind) string {
	switch k {
	case FileKindText:
		return "文字"
	case FileKindScript:
		return "脚本"
	case FileKindCompiled:
		return "编译好的程序"
	case FileKindBinary:
		return "看不出是什么的二进制"
	case FileKindArchive:
		return "压缩包或安装包"
	}
	return "图片、字体或文档"
}

func reviewUnreadName(u Unread) string {
	switch u {
	case UnreadTooLarge:
		return "太大，没读"
	case UnreadBudget:
		return "超出读的上限，没读"
	case UnreadLinkOutside:
		return "链接到 skill 外面，没跟进去"
	case UnreadDependencies:
		return "装好的依赖，没看"
	case UnreadTooDeep:
		return "太深，没看"
	case UnreadICloud:
		return "只在 iCloud 里，没下载"
	case UnreadUnreadable:
		return "读不了"
	}
	return ""
}

// reviewSize is bytes the same way on every Mac (the evalset is made on one and checked on another).
func reviewSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
}

var reviewLevel = map[Severity]string{Low: "低", Medium: "中", High: "高"}

func reviewRank(s Severity) int {
	switch s {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	}
	return 3
}

// reviewOrdered is what the rules found, most serious first (as the finding orders them), in the order found within
// a level.
func reviewOrdered(signals []SkillSignal) []SkillSignal {
	out := append([]SkillSignal(nil), signals...)
	sort.SliceStable(out, func(i, j int) bool { return reviewRank(out[i].Severity) < reviewRank(out[j].Severity) })
	return out
}

// ReviewShownPath is a path as the model sees it, and as the note shows it.
func ReviewShownPath(p string) string { return ReviewVisible(p, 120) }

// SkillReviewInput is the input for a skill: its agent, name and description, allowed tools, files, SKILL.md's
// instructions, a few other files (those with the most serious findings first, then scripts), and what the rules
// found, most serious first. A long text gives its start and the lines the rules pointed at (reviewExcerpt). All of it
// within limits.Total. Skill text goes through ReviewVisible. Paths are the skill's own (relative to its folder):
// nothing about where it lives.
func SkillReviewInput(skill Skill, signals []SkillSignal, limits SkillReviewLimits) Value {
	sorted := reviewOrdered(signals)
	description := visibleText(skill.Description)
	head := []Field{
		{"工具", VStr(skill.Agent)},
		{"名字", VStr(ReviewVisible(skill.Name, 60))},
		{"说明", VStr(reviewFit(limits.Description, func(m int) string { return reviewCut(description, m) }))},
	}
	if skill.HasAllowedTools {
		var tools []Value
		for i, t := range skill.AllowedTools {
			if i >= limits.Tools {
				break
			}
			tools = append(tools, VStr(ReviewVisible(t, 60)))
		}
		head = append(head, Field{"允许的工具", VList(tools...)})
	}
	var listed []Value
	used := 0
	for _, f := range skill.Files {
		text := ReviewShownPath(f.Path) + "（" + reviewKindName(f.Kind) + "，" + reviewSize(f.Bytes)
		if f.Unread != "" {
			text += "，" + reviewUnreadName(f.Unread)
		}
		entry := VStr(text + "）")
		if used+entry.Size() > limits.Listing {
			break
		}
		listed = append(listed, entry)
		used += entry.Size() + 2
	}
	if more := len(skill.Files) - len(listed) + skill.Unlisted; more > 0 {
		listed = append(listed, VStr("……还有 "+strconv.Itoa(more)+" 个文件没列出"))
	}
	head = append(head, Field{"文件", VList(listed...)})
	var found []Value
	for i, s := range sorted {
		if i >= limits.Signals {
			break
		}
		level, ok := reviewLevel[s.Severity]
		if !ok {
			level = "参考"
		}
		found = append(found, VStr(aiClean(level+"："+s.Label+signalPlace(s), 200)))
	}
	tail := []Field{{"规则查到的", VList(found...)}}

	// The texts: SKILL.md's instructions, then up to limits.Files others, those with the most serious findings first.
	type part struct {
		path, text      string
		firstLine, cap_ int
		pointed         []int
	}
	pointed := func(path string) []int {
		var out []int
		for _, s := range sorted {
			if s.File == path {
				out = append(out, s.Lines...)
			}
		}
		return out
	}
	worst := func(path string) int {
		for _, s := range sorted {
			if s.File == path {
				return reviewRank(s.Severity)
			}
		}
		return 4
	}
	skillMD := "SKILL.md"
	for _, f := range skill.Files {
		if aiLower(f.Path) == "skill.md" {
			skillMD = f.Path
			break
		}
	}
	parts := []part{{path: skillMD, text: skill.Instructions, firstLine: skill.InstructionsLine, pointed: pointed(skillMD), cap_: limits.Instructions}}
	type indexed struct {
		f SkillFile
		i int
	}
	var candidates []indexed
	for i, f := range skill.Files {
		if f.HasText && (f.Kind == FileKindScript || f.Kind == FileKindText) && f.Path != skillMD {
			candidates = append(candidates, indexed{f, i})
		}
	}
	scriptRank := func(f SkillFile) int {
		if f.Kind == FileKindScript {
			return 0
		}
		return 1
	}
	sort.SliceStable(candidates, func(a, b int) bool {
		x, y := candidates[a], candidates[b]
		if wx, wy := worst(x.f.Path), worst(y.f.Path); wx != wy {
			return wx < wy
		}
		if sx, sy := scriptRank(x.f), scriptRank(y.f); sx != sy {
			return sx < sy
		}
		return x.i < y.i
	})
	var others []SkillFile
	for i, c := range candidates {
		if i >= limits.Files {
			break
		}
		others = append(others, c.f)
	}
	for _, o := range others {
		parts = append(parts, part{path: o.Path, text: o.Text, firstLine: 1, pointed: pointed(o.Path), cap_: limits.File})
	}

	// What is left once the rest and each part's keys are written, shared out so that a short text is given whole and
	// the long ones split the rest evenly.
	bodyKey := Field{"SKILL.md 正文", VStr("")}
	var shells []Value
	for _, o := range others {
		shells = append(shells, VObj(Field{"文件", VStr(ReviewShownPath(o.Path))}, Field{"内容", VStr("")}))
	}
	frame := append(append([]Field{}, head...), bodyKey)
	if len(others) > 0 {
		frame = append(frame, Field{"其他文件", VList(shells...)})
	}
	frame = append(frame, tail...)
	room := limits.Total - VObj(frame...).Size()
	if room < 0 {
		room = 0
	}
	need := make([]int, len(parts))
	for i, p := range parts {
		need[i] = min(p.cap_, escapedLen(visibleText(p.text)))
	}
	order := make([]int, len(parts))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return need[order[a]] < need[order[b]] })
	budget := make([]int, len(parts))
	for k, i := range order {
		budget[i] = min(need[i], room/(len(parts)-k))
		room -= budget[i]
	}
	texts := make([]string, len(parts))
	for i, p := range parts {
		texts[i] = reviewExcerpt(p.text, p.pointed, p.firstLine, budget[i])
	}

	fields := append(append([]Field{}, head...), Field{"SKILL.md 正文", VStr(texts[0])})
	if len(others) > 0 {
		var items []Value
		for k, o := range others {
			items = append(items, VObj(Field{"文件", VStr(ReviewShownPath(o.Path))}, Field{"内容", VStr(texts[k+1])}))
		}
		fields = append(fields, Field{"其他文件", VList(items...)})
	}
	return VObj(append(fields, tail...)...)
}

// reviewFit is the longest text make gives within budget once escaped: make is asked for less until it fits.
func reviewFit(budget int, make func(int) string) string {
	for m := budget; m > 0; {
		s := make(m)
		e := escapedLen(s)
		if e <= budget {
			return s
		}
		m -= max(e-budget, 1)
	}
	return ""
}

// reviewExcerpt is a text within budget (escaped): whole when it fits; otherwise the lines the rules pointed at
// (pointed, numbered from firstLine, most serious first) with two lines around each, then as much of the start as is
// left, each gap marked with where the text goes on. Lines are counted as the rules count them.
func reviewExcerpt(text string, pointed []int, firstLine, budget int) string {
	if budget <= 0 {
		return ""
	}
	whole := visibleText(text)
	if escapedLen(whole) <= budget {
		return whole
	}
	lines := strings.Split(text, "\n")
	join := func(w [2]int) string { return strings.Join(lines[w[0]:w[1]+1], "\n") }
	var windows [][2]int
	used := 0
	for _, p := range pointed {
		i := p - firstLine
		if i < 0 || i >= len(lines) {
			continue
		}
		inside := false
		for _, w := range windows {
			if w[0] <= i && i <= w[1] {
				inside = true
				break
			}
		}
		if inside {
			continue
		}
		w := [2]int{max(0, i-2), min(len(lines)-1, i+2)}
		cost := escapedLen(ReviewVisible(join(w), 400)) + 24
		if used+cost > budget*2/3 {
			break
		}
		windows = append(windows, w)
		used += cost
	}
	if len(windows) == 0 {
		return reviewFit(budget, func(m int) string { return reviewCut(whole, m) })
	}
	sort.SliceStable(windows, func(a, b int) bool { return windows[a][0] < windows[b][0] })
	var merged [][2]int
	for _, w := range windows {
		if n := len(merged); n > 0 && w[0] <= merged[n-1][1]+1 {
			merged[n-1][1] = max(merged[n-1][1], w[1])
		} else {
			merged = append(merged, w)
		}
	}
	tailText := ""
	for _, w := range merged {
		count := w[1] - w[0] + 1
		tailText += "\n⟨……第 " + strconv.Itoa(w[0]+firstLine) + " 行起⟩\n" + ReviewVisible(join(w), 400*((count+4)/5))
	}
	if last := merged[len(merged)-1]; last[1] < len(lines)-1 {
		tailText += "\n⟨……后面还有 " + strconv.Itoa(len(lines)-1-last[1]) + " 行⟩"
	}
	headText := ""
	if merged[0][0] > 0 {
		start := strings.Join(lines[:merged[0][0]], "\n")
		if start != "" {
			shown := visibleText(start)
			headText = reviewFit(budget-escapedLen(tailText), func(m int) string { return reviewCut(shown, m) })
		}
	}
	out := headText + tailText
	if escapedLen(out) <= budget {
		return out
	}
	return reviewFit(budget, func(m int) string { return reviewCut(out, m) })
}

// reviewCut is the first max scalars of a text, and how much was left out.
func reviewCut(t string, max int) string {
	n := utf8.RuneCountInString(t)
	if n <= max {
		return t
	}
	r := []rune(t)
	return string(r[:max]) + "…（后面还有 " + strconv.Itoa(n-max) + " 字没给）"
}

// reviewHidden: characters a person does not see (always), apart from the joiners and tag characters handled in
// visibleText.
func reviewHidden(v rune) bool {
	if v == 0x0A || v == 0x09 {
		return false
	}
	return v < 0x20 || (v >= 0x7F && v <= 0x9F) || v == 0x200B || v == 0x200E || v == 0x200F || (v >= 0x202A && v <= 0x202E) ||
		(v >= 0x2060 && v <= 0x2064) || (v >= 0x2066 && v <= 0x2069) || v == 0xFEFF || v == 0x180E || (v >= 0xFFF9 && v <= 0xFFFB)
}

// reviewAttaches: characters that attach to the one before: combining marks, variation selectors, joiners, skin
// tones. A few in a row are ordinary (accents, emoji); a long run only carries something hidden.
func reviewAttaches(v rune) bool {
	if (v >= 0xFE00 && v <= 0xFE0F) || (v >= 0xE0100 && v <= 0xE01EF) || v == 0x200C || v == 0x200D || (v >= 0x1F3FB && v <= 0x1F3FF) {
		return true
	}
	return unicode.Is(unicode.Mn, v) || unicode.Is(unicode.Me, v)
}

var reviewEncoded = icuCS(`[A-Za-z0-9+/]{200,}={0,2}|(?:[A-Za-z0-9+/]{40,}={0,2}\n){4,}(?:[A-Za-z0-9+/]+={0,2}(?![^\n]))?`)

// ReviewVisible is skill text as the model is given it, at most max scalars (and if cut, how much was left out).
// Invisible characters become a marker saying how many there were: the rules have already reported them, and passed
// on, a model reads what a person cannot. That covers Unicode tag characters (except the few of a real subdivision
// flag, as the rules count them), direction controls, zero-width characters, joiners between two ASCII characters,
// and a run of more than four characters that attach to the one before. A long encoded run (one line of 200 or more,
// or a block of wrapped lines) becomes a marker with its length. CRLF and lone CR become LF.
func ReviewVisible(s string, max int) string { return reviewCut(visibleText(s), max) }

// visibleText is ReviewVisible without the cut.
func visibleText(s string) string {
	u := []rune(s)
	const hide = rune(-1)
	pieces := make([]rune, 0, len(u))
	isTag := func(v rune) bool { return v >= 0xE0000 && v <= 0xE007F }
	for i := 0; i < len(u); {
		v := u[i]
		if isTag(v) {
			j := i
			for j < len(u) && isTag(u[j]) {
				j++
			}
			run := u[i:j]
			letters := true
			for _, c := range run[:len(run)-1] {
				if !((c >= 0xE0030 && c <= 0xE0039) || (c >= 0xE0061 && c <= 0xE007A)) {
					letters = false
					break
				}
			}
			flag := i > 0 && u[i-1] == 0x1F3F4 && len(run) >= 3 && len(run) <= 8 && run[len(run)-1] == 0xE007F && letters
			for _, c := range run {
				if flag {
					pieces = append(pieces, c)
				} else {
					pieces = append(pieces, hide)
				}
			}
			i = j
			continue
		}
		if v == 0x0D {
			pieces = append(pieces, '\n')
			if i+1 < len(u) && u[i+1] == 0x0A {
				i += 2
			} else {
				i++
			}
			continue
		}
		if (v == 0x200C || v == 0x200D) && i > 0 && i+1 < len(u) && u[i-1] < 0x80 && u[i+1] < 0x80 {
			pieces = append(pieces, hide)
		} else if reviewHidden(v) {
			pieces = append(pieces, hide)
		} else {
			pieces = append(pieces, v)
		}
		i++
	}
	// Long runs of attaching characters.
	for k := 0; k < len(pieces); {
		if pieces[k] == hide || !reviewAttaches(pieces[k]) {
			k++
			continue
		}
		e := k
		for e < len(pieces) && pieces[e] != hide && reviewAttaches(pieces[e]) {
			e++
		}
		if e-k > 4 {
			for x := k; x < e; x++ {
				pieces[x] = hide
			}
		}
		k = e
	}
	var out []rune
	run := 0
	for _, p := range pieces {
		if p == hide {
			run++
			continue
		}
		if run > 0 {
			out = append(out, []rune("⟨"+strconv.Itoa(run)+" 个看不见的字符⟩")...)
			run = 0
		}
		out = append(out, p)
	}
	if run > 0 {
		out = append(out, []rune("⟨"+strconv.Itoa(run)+" 个看不见的字符⟩")...)
	}
	matches := reviewEncoded.findAll(out)
	if len(matches) == 0 {
		return string(out)
	}
	var b []rune
	last := 0
	for _, m := range matches {
		b = append(b, out[last:m[0]]...)
		b = append(b, []rune("⟨一段 "+strconv.Itoa(aiUTF16Len(out[m[0]:m[1]]))+" 字的编码⟩")...)
		last = m[1]
	}
	return string(append(b, out[last:]...))
}

// ---------------------------------------------------------------- what the model answers

// ReviewBeyond is something a skill does beyond its description, pinned to one of its files (as the note shows it).
type ReviewBeyond struct{ File, What string }

// ReviewAnswer is the model's answer about a skill.
type ReviewAnswer struct {
	// Fits: whether what the skill does matches what it says it does.
	Fits bool
	// Does: what it actually does, in a sentence; "" (HasDoes false) when the model's sentence may not be shown.
	Does    string
	HasDoes bool
	Beyond  []ReviewBeyond
	// Risk: the model's own sense of the risk: for the eval and a later decision, never shown, never the severity.
	Risk Severity
}

// answerObject is the model's answer as the JSON object a task asks for, its keys exactly these; ok false when it is
// not that (a ```-fenced answer taken out of its fence).
func answerObject(text string, keys ...string) (Value, bool) {
	if strings.HasPrefix(text, "```") {
		var kept []string
		for _, l := range SplitCharacterLF(text) {
			if !strings.HasPrefix(l, "```") {
				kept = append(kept, l)
			}
		}
		text = strings.Join(kept, "\n")
	}
	v, err := ParseFoundation(text)
	if err != nil || v.Kind != VObject || !hasExactKeys(v, keys...) {
		return Value{}, false
	}
	return v, true
}

// SplitCharacterLF is Swift's split(separator: "\n", omittingEmptySubsequences: false) on a String: by Character, so a
// CRLF (one Character) does not split.
func SplitCharacterLF(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func hasExactKeys(v Value, keys ...string) bool {
	if len(v.Obj) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := v.Get(k); !ok {
			return false
		}
	}
	return true
}

func scalars(s string) int { return utf8.RuneCountInString(s) }

// SkillReviewAnswer is the model's answer when it is what the task asks for (prompts/skills.schema.json), with what
// may not be shown taken out: a sentence carrying an address, a host, a command, a key or code is dropped (the rules
// never show what matched, and the model does not either), and so is one that vouches for the skill (a skill can
// address its reviewer); an action pinned to a file the skill does not have is dropped. ok false when the answer is
// not that JSON: not asked again.
func SkillReviewAnswer(raw string, skill Skill) (ReviewAnswer, bool) {
	text := raw
	if r := strings.LastIndex(text, "</think>"); r >= 0 {
		text = text[r+len("</think>"):]
	}
	obj, ok := answerObject(aiTrimWSNL(text), "fits", "does", "beyond", "risk")
	if !ok {
		return ReviewAnswer{}, false
	}
	fits, _ := obj.Get("fits")
	does, _ := obj.Get("does")
	items, _ := obj.Get("beyond")
	risk, _ := obj.Get("risk")
	if fits.Kind != VBool || does.Kind != VString || scalars(does.Str) > 80 || items.Kind != VArray || len(items.Arr) > 3 ||
		risk.Kind != VString || (risk.Str != string(Low) && risk.Str != string(Medium) && risk.Str != string(High)) {
		return ReviewAnswer{}, false
	}
	var beyond []ReviewBeyond
	for _, item := range items.Arr {
		if item.Kind != VObject || !hasExactKeys(item, "file", "what") {
			return ReviewAnswer{}, false
		}
		file, _ := item.Get("file")
		what, _ := item.Get("what")
		if file.Kind != VString || what.Kind != VString || scalars(file.Str) > 120 || scalars(what.Str) > 60 {
			return ReviewAnswer{}, false
		}
		beyond = append(beyond, ReviewBeyond{file.Str, what.Str})
	}
	hosts := ReviewHosts(skill)
	// The model names a file as it was shown; the note shows it cleaned.
	files := map[string]string{}
	for _, f := range skill.Files {
		files[ReviewShownPath(f.Path)] = aiClean(f.Path, 120)
	}
	a := ReviewAnswer{Fits: fits.Bool, Risk: Severity(risk.Str)}
	if said := aiClean(does.Str, 80); said != "" && reviewShareable(said, hosts) {
		a.Does, a.HasDoes = said, true
	}
	for _, b := range beyond {
		what := aiClean(b.What, 60)
		shown, ok := files[b.File]
		if ok && what != "" && reviewShareable(what, hosts) {
			a.Beyond = append(a.Beyond, ReviewBeyond{shown, what})
		}
	}
	return a, true
}

var (
	// reviewURL: an address's host, without the user and password before an @.
	reviewURL   = icuCI(`[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s"'<>@]*@)?([^/\s"'<>)\]:?#@]+)`)
	reviewIPv4  = icuCI(`(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])`)
	reviewIPv6  = icuCI(`(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}(?![0-9a-f:])|::1\b`)
	reviewToken = icuCI(`(?<![A-Za-z0-9+=_-])[A-Za-z0-9+=_-]{20,}(?![A-Za-z0-9+=_-])`)
	reviewEmail = icuCI(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	// reviewDomain: labels ending in a top-level domain that is not also a common file extension (.sh, .py, .md, .pl,
	// .cc, .so, .in, .zip … are names of the skill's own files; .app is an app's name), so a sentence naming one is not
	// shown.
	reviewDomain = icuCI(`(?<![A-Za-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|co|me|xyz|site|online|top|ru|cn|info|biz|tk|ml|ga|cf|gq|link|live|cloud|tech|store|shop|club|pw|su|ws|to|gg|ly|run|lt|st|moe|uk|de|jp|us|fr|nl|eu|ch|se|br|kr|tw|hk|sg|au|ca|ir|ua|it|es|vn|invalid|example|test|onion|click|xin|vip|work|life|world|space|fun|icu|buzz|rest|bond|cyou|sbs|lol|wtf|website|host)(?![A-Za-z0-9_-])`)
	// reviewHostLike: hosts a skill names without an address: the same, and .app and .ai too (collected, never shown
	// back).
	reviewHostLike = icuCI(`(?<![A-Za-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|co|me|xyz|site|online|top|ru|cn|info|biz|tk|ml|ga|cf|gq|link|live|cloud|tech|store|shop|club|pw|su|ws|to|gg|ly|run|lt|st|moe|uk|de|jp|us|fr|nl|eu|ch|se|br|kr|tw|hk|sg|au|ca|ir|ua|it|es|vn|invalid|example|test|onion|click|xin|vip|work|life|world|space|fun|icu|buzz|rest|bond|cyou|sbs|lol|wtf|website|host|app|ai)(?![A-Za-z0-9_-])`)
	// reviewDefanged: addresses written so they do not work ("example[.]com", "hxxp").
	reviewDefanged = icuCI(`\[\.\]|\(\.\)|\[dot\]|\(dot\)|hxxps?`)
	reviewCommand  = icuCI(`(?<![A-Za-z0-9_])(?:curl|wget|bash|sh|zsh|fish|sudo|rm|rmdir|mv|cp|ln|dd|tar|zip|unzip|chmod|chown|chflags|chattr|kill|killall|pkill|launchctl|osascript|crontab|security|sqlite3|diskutil|tmutil|fdesetup|mdutil|sfltool|softwareupdate|python3?|perl|ruby|node|deno|bun|npx|npm|pnpm|yarn|pip3?|pipx|uvx?|gem|cargo|go|brew|git|docker|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|base64|xxd|openssl|gpg|eval|exec|nohup|xattr|spctl|csrutil|tccutil|codesign|defaults|plutil|find|open|cat|echo|printenv|env|powershell|pwsh|mkfs|systemctl)\s+(?:-{1,2}[A-Za-z0-9]|[A-Za-z~/.$"'|<>@])`)
	// reviewVouching: words that vouch for a skill or call the rules wrong: the note only says what it does beyond its
	// description.
	reviewVouching = []string{"放心", "无害", "良性", "没有风险", "没什么风险", "无风险", "低风险", "风险很低", "风险不大", "没问题", "不用担心", "不必担心", "无需担心",
		"可以信任", "值得信任", "可信", "可靠", "正规", "合法", "官方认证", "通过认证", "审核过", "通过审核", "经过审核", "验证过", "核实过",
		"误报", "误判", "是安全的", "很安全", "安全无害", "不会有危险"}
)

// ReviewHosts are the hosts the skill's text names (in addresses, and on their own), each with its last two labels:
// none of them may come back in what the model says.
func ReviewHosts(skill Skill) []string {
	out := map[string]bool{}
	add := func(h string) {
		h = strings.Trim(aiLower(h), ".")
		if graphemeCount(h) < 4 {
			return
		}
		out[h] = true
		var labels []string
		for _, l := range strings.Split(h, ".") {
			if l != "" {
				labels = append(labels, l)
			}
		}
		if len(labels) > 2 && !reviewIPv4.has(h) {
			out[strings.Join(labels[len(labels)-2:], ".")] = true
		}
	}
	texts := []string{skill.Description, skill.Instructions}
	for _, f := range skill.Files {
		if f.HasText {
			texts = append(texts, f.Text)
		}
	}
	for _, t := range texts {
		r := []rune(t)
		for _, m := range reviewURL.findAll(r) {
			if m[2] >= 0 {
				add(string(r[m[2]:m[3]]))
			}
		}
		for _, m := range reviewHostLike.findAll(r) {
			add(string(r[m[0]:m[1]]))
		}
	}
	return sortedKeys(out)
}

// ReviewAddresses are the IPv4 addresses a skill's text has: like its hosts, they may not come back in what the model
// says.
func ReviewAddresses(skill Skill) []string {
	out := map[string]bool{}
	texts := []string{skill.Description, skill.Instructions}
	for _, f := range skill.Files {
		if f.HasText {
			texts = append(texts, f.Text)
		}
	}
	for _, t := range texts {
		r := []rune(t)
		for _, m := range reviewIPv4.findAll(r) {
			out[string(r[m[0]:m[1]])] = true
		}
	}
	return sortedKeys(out)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// reviewShareable says whether a sentence from the model may be shown: no address, domain, IP, e-mail, command, code,
// key-like string (a long run with a digit in it, or a very long one), host from the skill, or vouching.
func reviewShareable(s string, hosts []string) bool {
	lower := aiLower(s)
	if strings.Contains(s, "://") || strings.Contains(lower, "www.") || strings.Contains(s, "`") {
		return false
	}
	for _, re := range []*icuRegexp{reviewIPv4, reviewIPv6, reviewEmail, reviewDomain, reviewDefanged, reviewCommand} {
		if re.has(s) {
			return false
		}
	}
	r := []rune(s)
	for _, m := range reviewToken.findAll(r) {
		t := string(r[m[0]:m[1]])
		if graphemeCount(t) >= 32 || strings.ContainsAny(t, "0123456789") {
			return false
		}
	}
	for _, h := range hosts {
		if strings.Contains(lower, h) {
			return false
		}
	}
	for _, v := range reviewVouching {
		if strings.Contains(s, v) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- the note on the finding

// SkillReviewNote is the note an answer adds to a finding, only when the model says the skill does more than its
// description says: what it actually does, and what goes beyond it. When the model says it matches, nothing: a skill
// can talk to the model that checks it, and a reassuring summary next to what the rules found would vouch for it.
func SkillReviewNote(a ReviewAnswer) (string, bool) {
	if a.Fits {
		return "", false
	}
	var parts []string
	if a.HasDoes {
		parts = append(parts, "它实际在做的："+a.Does)
	}
	if len(a.Beyond) == 0 {
		parts = append(parts, "它做的和说明对不上")
	} else {
		var b []string
		for _, x := range a.Beyond {
			b = append(b, x.File+"："+x.What)
		}
		parts = append(parts, "说明里没说的："+strings.Join(b, "；"))
	}
	return "本机模型看过（只是说明，不改结论）：" + strings.Join(parts, "。"), true
}

// SkillReviewAnnotate is the finding with the model's note as evidence SkillNoteKey; everything the rules set
// stays as it was.
func SkillReviewAnnotate(f Finding, a ReviewAnswer) Finding {
	n, ok := SkillReviewNote(a)
	if !SkillReviewAsks(f) || !ok {
		return f
	}
	return WithEvidence(f, SkillNoteKey, n)
}

// WithEvidence is the finding with one more piece of evidence (a copy: the finding given is not changed).
func WithEvidence(f Finding, key, value string) Finding {
	ev := make(map[string]string, len(f.Evidence)+1)
	for k, v := range f.Evidence {
		ev[k] = v
	}
	ev[key] = value
	f.Evidence = ev
	return f
}
