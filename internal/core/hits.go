package core

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Where a skill's or a chat template's finding was found, as data (docs/data-resources.md 「命中的依据」).
//
// Two parts. What a round keeps with the finding (evidence HitsKey): the kind, the file and the lines — codes, names
// and numbers, never the text that matched. And what is read again when someone asks about one finding
// (SkillEvidence, ChatTemplateEvidence): the same hits, each with the lines themselves, cut short and made safe to
// show (ExcerptLine). The lines are read from the files then and kept nowhere; when the files are no longer what the
// round saw, none are given.
//
// An excerpt is someone else's text, shown to a person as it is written: it may say anything, also words meant for a
// model. It is content, not a statement of this tool, and is given to no model here.

// HitsKey is the evidence a skill's and a chat template's finding carry: a JSON list of Hit.
// HitsMoreKey: how many more there were than the list has.
const (
	HitsKey     = "hits"
	HitsMoreKey = "hits_more"
)

// Bounds of what is kept and shown.
const (
	hitsMost        = 12  // hits of one finding
	hitLinesMost    = 8   // lines of one hit
	hitExcerptsMost = 3   // lines shown of one hit
	excerptMost     = 160 // Characters of one line shown
	excerptsAllMost = 24  // lines shown of one finding
)

// Hit is one place a finding was found. A skill's: one kind (a SignalKind), how serious, the file (relative to the
// skill's folder; several for what could not be read) and the lines (1-based, when it is in one file). A chat
// template's: one file of the model (its name; TEMPLATE, SYSTEM, MESSAGE for Ollama's layers), which part of the model
// it is (template, system, messages) and the kinds found in it.
type Hit struct {
	Kinds    []string `json:"kinds"`
	Severity string   `json:"severity,omitempty"`
	Files    []string `json:"files"`
	Part     string   `json:"part,omitempty"`
	Lines    []int    `json:"lines,omitempty"`
	// LinesMore: lines beyond the ones listed.
	LinesMore int `json:"linesMore,omitempty"`
	// Declared: it is what the skill says it is for.
	Declared bool `json:"declared,omitempty"`
}

// HitsOf are the hits a finding carries; ok false when it carries none (a round from before they were kept).
func HitsOf(f Finding) (hits []Hit, more int, ok bool) {
	raw := f.Evidence[HitsKey]
	if raw == "" || json.Unmarshal([]byte(raw), &hits) != nil {
		return nil, 0, false
	}
	more, _ = strconv.Atoi(f.Evidence[HitsMoreKey])
	return hits, more, true
}

// partCode is where in a model the text is, as a code (part() is the same in words).
func (k templateFileKind) partCode() string {
	switch k {
	case tfOllamaSystem:
		return "system"
	case tfOllamaMessages:
		return "messages"
	}
	return "template"
}

// hit is a template file with something in it, as a hit.
func (f templateFile) hit(row chatTemplateRow) Hit {
	return Hit{Kinds: append([]string{}, row.Kinds...), Files: []string{aiClean(f.shown, 80)}, Part: f.kind.partCode()}
}

// skillHits are the signals that count as hits, the most serious first (as orderedSignals has them), at most
// hitsMost; more: how many were left out.
func skillHits(ordered []SkillSignal) (hits []Hit, more int) {
	for i, s := range ordered {
		if i >= hitsMost {
			more = len(ordered) - hitsMost
			break
		}
		h := Hit{Kinds: []string{string(s.Kind)}, Severity: string(s.Severity), Files: []string{}, Declared: s.Declared}
		switch {
		case len(s.Files) > 0:
			for _, f := range s.Files {
				h.Files = append(h.Files, aiClean(f, 120))
			}
		case s.File != "":
			h.Files = append(h.Files, aiClean(s.File, 120))
		}
		for j, l := range s.Lines {
			if j >= hitLinesMost {
				h.LinesMore = len(s.Lines) - hitLinesMost
				break
			}
			h.Lines = append(h.Lines, l)
		}
		hits = append(hits, h)
	}
	return hits, more
}

// withHits is ev with the hits as evidence; none: left as it is.
func withHits(ev map[string]string, hits []Hit, more int) {
	if len(hits) == 0 {
		return
	}
	data, err := json.Marshal(hits)
	if err != nil {
		return
	}
	ev[HitsKey] = string(data)
	if more > 0 {
		ev[HitsMoreKey] = strconv.Itoa(more)
	}
}

// ---------------------------------------------------------------- a line made safe to show

// Excerpt is one line of a file as it may be shown: Line is 1-based (0: the text has no line of its own in the file, a
// template inside a JSON or GGUF file); Text has no control or invisible characters, is at most excerptMost
// Characters (Cut: it was longer), and has what looks like a credential's value replaced by ExcerptRedacted
// (Redacted).
type Excerpt struct {
	Line     int    `json:"line"`
	Text     string `json:"text"`
	Cut      bool   `json:"cut"`
	Redacted bool   `json:"redacted"`
	// Kinds: what this line has, for a template's (a skill's hit has one kind for all its lines).
	Kinds []string `json:"kinds,omitempty"`
}

// ExcerptRedacted stands where a value was taken out.
const ExcerptRedacted = "⟨redacted⟩"

// excerptName: a name that says a secret follows, up to where its value starts (the group is left open).
const excerptName = `(?i)([A-Za-z0-9_-]*(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|` +
	`auth(?:orization)?|credentials?|cookie|session(?:[_-]?id)?)(?:[_-][A-Za-z0-9]+)*["']?\s*[:=]\s*(?:(?:bearer|basic|token)\s+)?`

var (
	// Values tools give a shape of their own, a private key's block, and the user and password of an address.
	excerptKnown = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*|` +
		`\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bglpat-[A-Za-z0-9_-]{16,}|` +
		`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bxox[abeprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{30,}|\bnpm_[A-Za-z0-9]{30,}|\bhf_[A-Za-z0-9]{30,}|` +
		`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?`)
	excerptUserinfo = regexp.MustCompile(`(://)[^/\s:@]+:[^@\s/]+@`)
	// A webhook's address is the secret itself: what follows the service's fixed path (Slack, Discord, Teams, Feishu
	// and Lark). Its parts are short and split by slashes, so neither excerptLong nor excerptUserinfo sees them.
	excerptWebhook = regexp.MustCompile(`(?i)((?:hooks\.slack\.com/(?:services|workflows|triggers)|discord(?:app)?\.com/api/webhooks|` +
		`[a-z0-9.-]*webhook\.office\.com/webhookb2|open\.(?:feishu\.cn|larksuite\.com)/open-apis/bot/v2/hook)/)[^\s"'<>)]+`)
	// A name that says a secret follows, and its value: password = …, "token": "…", Authorization: Bearer ….
	excerptNamed = regexp.MustCompile(excerptName + `|\bbearer\s+)(["']?)([^\s"',;)]{6,})`)
	// The same with the value in quotes: all of it up to the closing quote, spaces too.
	excerptQuoted = []*regexp.Regexp{regexp.MustCompile(excerptName + `)(")([^"]{6,})`), regexp.MustCompile(excerptName + `)(')([^']{6,})`)}
	// A value given to a command as an argument of its own: --password …, --api-key …; -u user:password.
	excerptFlag = regexp.MustCompile(`(?i)(--[a-z0-9-]*(?:pass(?:word|wd|phrase)?|secret|token|api-?key|access-?key)[a-z0-9-]*\s+)(["']?)([^\s"',;)-][^\s"',;)]{3,})`)
	excerptUser = regexp.MustCompile(`((?:^|\s)(?:-u|--user)[ =]+["']?[^\s:"']+:)()([^\s"']{3,})`)
	// mysql and its kin take the password stuck to -p (-phunter2); -p alone asks for it, -P is the port. Only after one
	// of these programs and within its own command: mkdir -pv, ssh -p 22 are not this.
	excerptStuckName = "((?:^|[\\s/;|&(`])(?:mariadb-dump|mysqldump|mysqladmin|mysql|mariadb)\\s(?:[^|;&]*\\s)?-p)"
	excerptStuck     = regexp.MustCompile(excerptStuckName + "([\"']?)([^\\s\"';|&]+)")
	// The same with the password in quotes: all of it up to the closing quote, spaces too.
	excerptStuckQuoted = []*regexp.Regexp{regexp.MustCompile(excerptStuckName + `(")([^"]+)`), regexp.MustCompile(excerptStuckName + `(')([^']+)`)}
	// A long run of letters and digits with nothing between: a key, a hash, encoded bytes.
	excerptLong = regexp.MustCompile(`[A-Za-z0-9+_=-]{32,}`)
	// A line that is nothing but base64 with slashes in it (a private key's body, an encoded file): the slashes cut it
	// into runs too short for excerptLong. Only a whole line of it, so that a path inside a sentence or a command is
	// left alone; a path alone on its line is told apart in excerptEncoded.
	excerptBase64 = regexp.MustCompile(`^(\s*)([A-Za-z0-9+/]{40,}={0,2})(\s*)$`)
)

// excerptReference: a value that names where the secret is rather than being it ($TOKEN, ${TOKEN}, <token>,
// {{ token }}, %TOKEN%, process.env.TOKEN, os.environ[…]).
func excerptReference(v string) bool {
	if strings.ContainsAny(v[:1], "$<{%") {
		return true
	}
	l := strings.ToLower(v)
	for _, p := range []string{"process.env", "os.environ", "os.getenv", "env.", "env[", "secrets."} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	// Words that say there is none; only as the whole value (a secret may start with one).
	return l == "none" || l == "null" || l == "true" || l == "false"
}

// excerptEncoded says whether a run of base64 letters with slashes is encoded bytes rather than a path: it has capitals,
// small letters and digits, and somewhere between two slashes (or an end) a part that mixes all three or holds a +,
// which the name of a folder seldom does. A path of plain names stays as it is.
func excerptEncoded(run string) bool {
	if !strings.Contains(run, "/") {
		return false // without a slash excerptLong decides
	}
	upper, lower, digit, mixed := false, false, false, false
	for _, part := range strings.Split(strings.TrimRight(run, "="), "/") {
		u, l, d := false, false, false
		for _, c := range part {
			u = u || (c >= 'A' && c <= 'Z')
			l = l || (c >= 'a' && c <= 'z')
			d = d || (c >= '0' && c <= '9')
		}
		upper, lower, digit = upper || u, lower || l, digit || d
		mixed = mixed || (u && l && d) || strings.Contains(part, "+")
	}
	return upper && lower && digit && mixed
}

// excerptSafe is a line of someone else's file without what may not be shown: control and invisible characters (they
// go first, so that none can split a value in two), and what looks like a credential's value.
func excerptSafe(raw string) string {
	s := strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		return r
	}, strings.TrimSuffix(raw, "\r"))
	s = aiClean(s, len(s)+1)
	out := excerptKnown.ReplaceAllString(s, ExcerptRedacted)
	out = excerptUserinfo.ReplaceAllString(out, "${1}"+ExcerptRedacted+"@")
	out = excerptWebhook.ReplaceAllString(out, "${1}"+ExcerptRedacted)
	// Each of these has the name, the quote and the value as its three groups.
	for _, re := range append(append([]*regexp.Regexp{}, excerptQuoted...), excerptNamed, excerptFlag, excerptUser,
		excerptStuckQuoted[0], excerptStuckQuoted[1], excerptStuck) {
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			g := re.FindStringSubmatch(m)
			if g[3] == ExcerptRedacted || excerptReference(g[3]) {
				return m
			}
			return g[1] + g[2] + ExcerptRedacted
		})
	}
	if g := excerptBase64.FindStringSubmatch(out); g != nil && excerptEncoded(g[2]) {
		return g[1] + ExcerptRedacted + g[3]
	}
	return excerptLong.ReplaceAllStringFunc(out, func(m string) string {
		letter, digit := false, false
		for _, c := range m {
			letter = letter || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
			digit = digit || (c >= '0' && c <= '9')
		}
		if letter && digit {
			return ExcerptRedacted
		}
		return m
	})
}

// ExcerptLine is a line of someone else's file as it may be shown (see Excerpt): made safe whole, then cut, so a cut
// never leaves half a value standing.
func ExcerptLine(raw string, line int) Excerpt {
	safe := excerptSafe(raw)
	e := Excerpt{Line: line, Text: aiCut(safe, excerptMost)}
	e.Cut = e.Text != safe
	e.Redacted = strings.Contains(e.Text, ExcerptRedacted)
	return e
}

// ---------------------------------------------------------------- read again for one finding

// Evidence states: the files are as the round saw them and were read (EvidenceRead); they changed or are gone since,
// so nothing is quoted (EvidenceChanged); the finding is not one whose files are read for this (EvidenceNone).
const (
	EvidenceRead    = "read"
	EvidenceChanged = "changed"
	EvidenceNone    = "none"
)

// HitExcerpts is a hit with the lines it points at.
type HitExcerpts struct {
	Hit
	Excerpts []Excerpt
}

// SkillOf reads the skill a finding is about again, within a round's limits; ok false when it is gone, may not be
// looked at, or is not what the finding was made from (its key: the folder and a digest of its files).
func SkillOf(ctx *Context, f Finding) (Skill, bool) {
	i := strings.LastIndex(f.Key, "|")
	if !strings.HasPrefix(f.Rule, "skill.") || i <= 0 {
		return Skill{}, false
	}
	real := f.Key[:i]
	// The key spells the folder as Canonical does (/var for /private/var).
	if at, ok := ResolvedPath(real, ctx); !ok || Canonical(at) != real || !aiIsReg(real+"/SKILL.md") {
		return Skill{}, false
	}
	limits := DefaultSkillLimits()
	budget := limits.MaxRoundBytes
	sk := readSkill(skillSpot{place: SkillPlace{Agent: f.Evidence["agent"], Scope: SkillScope(f.Evidence["scope"])},
		spelled: f.Path, real: real}, limits, &budget, true)
	return sk, sk.RealFolder+"|"+sk.Digest == f.Key
}

// SkillEvidence reads the skill of a finding again and gives its hits with the lines they point at. The skill is
// read within the round's limits; when it is not what the finding was made from (its key: the folder and a digest of
// its files), the state is EvidenceChanged and there are no hits.
func SkillEvidence(ctx *Context, f Finding) (string, []HitExcerpts) {
	if !strings.HasPrefix(f.Rule, "skill.") || strings.LastIndex(f.Key, "|") <= 0 {
		return EvidenceNone, nil
	}
	sk, ok := SkillOf(ctx, f)
	if !ok {
		return EvidenceChanged, nil
	}
	ordered, _ := orderedSignals(SkillSignals(sk))
	hits, _ := skillHits(ordered)
	texts := map[string][]string{}
	out := []HitExcerpts{}
	shown := 0
	for n, h := range hits {
		e := HitExcerpts{Hit: h, Excerpts: []Excerpt{}}
		file := ordered[n].File
		if len(h.Lines) > 0 && len(ordered[n].Files) == 0 {
			lines, have := texts[file]
			if !have {
				for _, sf := range sk.Files {
					if sf.Path == file && sf.HasText {
						lines = strings.Split(sf.Text, "\n")
					}
				}
				texts[file] = lines
			}
			for _, l := range h.Lines {
				if len(e.Excerpts) >= hitExcerptsMost || shown >= excerptsAllMost {
					break
				}
				if l >= 1 && l <= len(lines) {
					e.Excerpts = append(e.Excerpts, ExcerptLine(lines[l-1], l))
					shown++
				}
			}
		}
		out = append(out, e)
	}
	return EvidenceRead, out
}

// templateLineHit is a line of what reaches the model that has words to it, or invisible characters.
type templateLineHit struct {
	kinds []TemplateKind
	text  string
}

// templateLineHits are the lines of text (as the model gets it) the check counts, with the kinds found in each; a
// long line is narrowed to the stretch that has them, when one stretch alone does.
func templateLineHits(text string) []templateLineHit {
	var out []templateLineHit
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		inv := skillInvisible([]rune(line), false)
		found := map[TemplateKind]bool{}
		for _, l := range strings.Split(string(inv.tags), "\n") {
			for _, k := range templateWordsLong(l) {
				found[k] = true
			}
		}
		clean := string(inv.clean)
		for _, k := range templateWordsLong(clean) {
			found[k] = true
		}
		if len(inv.tags) > 0 || inv.bidi > 0 || inv.zeroWidth >= 3 {
			found[TplHidden] = true
		}
		if len(found) == 0 {
			continue
		}
		h := templateLineHit{text: clean}
		for _, k := range templateKindOrder {
			if found[k] {
				h.kinds = append(h.kinds, k)
			}
		}
		// A long line: the stretch that has them. Looked for in the line already made safe, so that no stretch starts
		// or ends inside a value; the first stretch that matches has the words at its end, so it is moved on a third.
		if r := []rune(excerptSafe(clean)); len(r) > excerptMost {
			const width = excerptMost - 10
			for i := 0; i < len(r); i += width / 3 {
				if len(templateWords(string(r[i:min(i+width, len(r))]))) == 0 {
					continue
				}
				if j := i + width/3; j < len(r) && len(templateWords(string(r[j:min(j+width, len(r))]))) > 0 {
					i = j
				}
				h.text = aiTrimWS(string(r[i:min(i+width, len(r))]))
				break
			}
		}
		out = append(out, h)
	}
	return out
}

// modelAt is the model whose folder (an Ollama model's manifest) is dir, found the way a round finds it.
func (r *ChatTemplateRule) modelAt(ctx *Context, tool, dir string, budget *int64) (templateModel, bool) {
	for _, pl := range chatTemplatePlaces {
		if pl.tool != tool {
			continue
		}
		root := ctx.Home + "/" + pl.path
		if _, ok := aiLstat(root); !ok || !ctx.MayFollow(root) || !strings.HasPrefix(dir, root+"/") {
			continue
		}
		realRoot, ok := ResolvedPath(root, ctx)
		if !ok || !aiIsDir(realRoot) {
			continue
		}
		var found []templateModel
		switch pl.tool {
		case "Hugging Face":
			found = r.hfModels(ctx, root, realRoot)
		case "Ollama":
			found = r.ollamaModels(ctx, root, realRoot, budget)
		default:
			found = r.folderModels(ctx, pl.tool, root)
		}
		for _, m := range found {
			if m.dir == dir {
				return m, true
			}
		}
	}
	return templateModel{}, false
}

// ChatTemplateEvidence reads the template files of a finding's model again and gives, file by file, the kinds and the
// lines (of what reaches the model) that have them. When the files are not what the finding was made from (its key:
// a digest of the templates), the state is EvidenceChanged and there are no hits.
func ChatTemplateEvidence(ctx *Context, f Finding) (string, []HitExcerpts) {
	if f.Rule != "model.chat-template" || f.Key == "" {
		return EvidenceNone, nil
	}
	r := &ChatTemplateRule{Limits: DefaultChatTemplateLimits()}
	budget := r.Limits.MaxRoundBytes
	m, ok := r.modelAt(ctx, f.Evidence["tool"], f.Path, &budget)
	if !ok {
		return EvidenceChanged, nil
	}
	seen := map[string]chatTemplateRow{}
	now, _ := r.checkModel(ctx, m, map[string]chatTemplateRow{}, seen, &budget)
	if now == nil || now.Key != f.Key {
		return EvidenceChanged, nil
	}
	out := []HitExcerpts{}
	shown := 0
	for _, tf := range m.files {
		row := seen[tf.real]
		if row.Sev == "" {
			continue
		}
		e := HitExcerpts{Hit: tf.hit(row), Excerpts: []Excerpt{}}
		if st, ok := aiLstat(tf.real); ok && aiStReg(st) {
			texts, syntax, _ := r.templateTexts(tf, st, &budget)
			for _, t := range texts {
				for _, h := range templateLineHits(TemplateOutput(t, syntax)) {
					if len(e.Excerpts) >= hitExcerptsMost || shown >= excerptsAllMost {
						break
					}
					x := ExcerptLine(h.text, 0)
					for _, k := range h.kinds {
						x.Kinds = append(x.Kinds, string(k))
					}
					e.Excerpts = append(e.Excerpts, x)
					shown++
				}
			}
		}
		out = append(out, e)
	}
	return EvidenceRead, out
}
