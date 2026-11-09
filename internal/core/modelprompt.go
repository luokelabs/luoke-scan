package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ModelPrompt is a generate task's prompt (top-level ADR 0019): the files in prompts/ read the way bench/prompts.py
// reads them, and the request luoke-core is sent made the way bench/run_eval.py makes it, byte for byte (a test compares
// the two for every evalset item): what the release eval measured is what the scan asks.
type ModelPrompt struct {
	// Name: explain, identify, skills; the files are prompts/<name>.*.
	Name string
	// Task is luoke-core's name for it: luoke-scan.<name>.
	Task      string
	Version   int64
	MaxTokens int64
	// MaxChars: the longest answer the task asks for, in characters (explain); 0 when it does not say.
	MaxChars     int64
	System       string
	UserTemplate string
	Examples     []PromptExample
	// Schema: what goes to the model (keys starting with x- taken out), for a task whose answer is JSON.
	Schema    *Value
	Params    []Field
	SHA256    string
	hasMaxCha bool
}

// PromptExample is one worked question and answer of a prompt.
type PromptExample struct{ Input, Output Value }

var promptKinds = []string{".task.json", ".system.txt", ".user.txt", ".retry.txt", ".examples.json", ".schema.json"}
var promptPlaceholder = regexp.MustCompile(`\{\{([a-z_]+)\}\}`)

// promptFiles are the task's files, sorted: what its fingerprint covers (exactly these names).
func promptFiles(name string, fsys fs.FS) []string {
	wanted := map[string]bool{"_shared.txt": true}
	for _, k := range promptKinds {
		wanted[name+k] = true
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if wanted[e.Name()] {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// fillPrompt is the template with each {{name}} replaced; every placeholder filled and every value used, or an error.
func fillPrompt(template string, values map[string]string, where string) (string, error) {
	wanted := map[string]bool{}
	for _, m := range promptPlaceholder.FindAllStringSubmatch(template, -1) {
		wanted[m[1]] = true
	}
	var missing, extra []string
	for k := range wanted {
		if _, ok := values[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range values {
		if !wanted[k] {
			extra = append(extra, k)
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		sort.Strings(missing)
		sort.Strings(extra)
		return "", fmt.Errorf("%s：没填 %s，文件里没有 %s", where, swiftList(missing), swiftList(extra))
	}
	return promptPlaceholder.ReplaceAllStringFunc(template, func(m string) string {
		return values[m[2:len(m)-2]]
	}), nil
}

// swiftList is a list of names as Swift prints an array of strings: ["a", "b"].
func swiftList(a []string) string {
	q := make([]string, len(a))
	for i, s := range a {
		q[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// stripX is the schema without this repository's notes (keys starting with x-); the names under "properties" are
// kept whatever they are.
func stripX(v Value, names bool) Value {
	switch v.Kind {
	case VObject:
		var fields []Field
		for _, f := range v.Obj {
			if names || !strings.HasPrefix(f.Key, "x-") {
				fields = append(fields, Field{f.Key, stripX(f.Value, f.Key == "properties" && !names)})
			}
		}
		return VObj(fields...)
	case VArray:
		items := make([]Value, len(v.Arr))
		for i, x := range v.Arr {
			items[i] = stripX(x, false)
		}
		return VList(items...)
	}
	return v
}

// LoadPrompt reads prompts/<name>.* from dir; a placeholder not filled, a value for one the file does not have, an
// enum described differently from the schema's: an error, not a prompt with a hole in it.
func LoadPrompt(name, dir string) (*ModelPrompt, error) { return LoadPromptFS(name, os.DirFS(dir)) }

// LoadPromptFS is LoadPrompt from a file system: a folder (os.DirFS), or the prompts the packed program carries.
func LoadPromptFS(name string, fsys fs.FS) (*ModelPrompt, error) {
	read := func(suffix string) ([]byte, error) {
		b, err := fs.ReadFile(fsys, name+suffix)
		if err != nil {
			return nil, fmt.Errorf("读不到 %s%s", name, suffix)
		}
		return b, nil
	}
	text := func(suffix string) (string, error) {
		b, err := read(suffix)
		if err != nil {
			return "", err
		}
		s, ok := aiDecodeUTF8(b)
		if !ok {
			return "", fmt.Errorf("%s%s 不是 UTF-8", name, suffix)
		}
		return s, nil
	}
	parse := func(suffix string) (Value, error) {
		b, err := read(suffix)
		if err != nil {
			return Value{}, err
		}
		return ParseValue(b)
	}
	task, err := parse(".task.json")
	if err != nil {
		return nil, err
	}
	tv, _ := task.Get("task")
	taskName, ok1 := tv.String()
	vv, _ := task.Get("version")
	version, ok2 := vv.Integer()
	mv, _ := task.Get("max_tokens")
	maxTokens, ok3 := mv.Integer()
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("%s.task.json 缺 task、version 或 max_tokens", name)
	}
	values := map[string]string{}
	p := &ModelPrompt{Name: name, Task: taskName, Version: version, MaxTokens: maxTokens}
	if m, ok := task.Get("max_chars"); ok {
		values["max_chars"] = m.Text()
		if n, ok := m.Integer(); ok {
			p.MaxChars, p.hasMaxCha = n, true
		}
	}
	var full *Value
	if _, err := fs.Stat(fsys, name+".schema.json"); err == nil {
		s, err := parse(".schema.json")
		if err != nil {
			return nil, err
		}
		full = &s
	}
	if full != nil {
		if props, ok := full.Get("properties"); ok && props.Kind == VObject {
			for _, pr := range props.Obj {
				described, ok := pr.Value.Get("x-describe")
				if !ok || described.Kind != VArray {
					continue
				}
				var lines, keys []string
				for _, d := range described.Arr {
					k, ok1 := Value{}, false
					var what Value
					if d.Kind == VArray && len(d.Arr) == 2 {
						k, what = d.Arr[0], d.Arr[1]
						ok1 = k.Kind == VString && what.Kind == VString
					}
					if !ok1 {
						return nil, fmt.Errorf("%s.schema.json：%s 的 x-describe 要是一对对的文字", name, pr.Key)
					}
					keys = append(keys, k.Str)
					lines = append(lines, "- "+k.Str+"："+what.Str)
				}
				var enum []string
				if e, ok := pr.Value.Get("enum"); ok && e.Kind == VArray {
					for _, x := range e.Arr {
						if x.Kind == VString {
							enum = append(enum, x.Str)
						}
					}
				}
				a, b := append([]string{}, keys...), append([]string{}, enum...)
				sort.Strings(a)
				sort.Strings(b)
				if strings.Join(a, "\x00") != strings.Join(b, "\x00") || len(a) != len(b) {
					return nil, fmt.Errorf("%s.schema.json：%s 的 x-describe 和 enum 对不上", name, pr.Key)
				}
				values[pr.Key+"s"] = strings.Join(lines, "\n")
			}
		}
	}
	sysText, err := text(".system.txt")
	if err != nil {
		return nil, err
	}
	if p.System, err = fillPrompt(sysText, values, name+".system.txt"); err != nil {
		return nil, err
	}
	if strings.Contains(p.System, "{{") {
		return nil, fmt.Errorf("%s.system.txt：有认不出的占位符（只能是小写字母和下划线）", name)
	}
	ex, err := parse(".examples.json")
	if err != nil {
		return nil, err
	}
	if ex.Kind != VArray {
		return nil, fmt.Errorf("%s.examples.json 要是一个列表", name)
	}
	for _, e := range ex.Arr {
		in, ok1 := e.Get("input")
		out, ok2 := e.Get("output")
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%s.examples.json：每条要有 input 和 output", name)
		}
		p.Examples = append(p.Examples, PromptExample{in, out})
	}
	if params, ok := task.Get("params"); ok {
		for _, k := range []string{"temperature", "top_p"} {
			if v, ok := params.Get(k); ok {
				p.Params = append(p.Params, Field{k, v})
			}
		}
		if t, ok := params.Get("thinking"); ok {
			p.Params = append(p.Params, Field{"chat_template_kwargs", VObj(Field{"enable_thinking", VBoolean(t.Truthy())})})
		}
	}
	h := sha256.New()
	for _, f := range promptFiles(name, fsys) {
		h.Write([]byte(f))
		h.Write([]byte{0})
		b, _ := fs.ReadFile(fsys, f)
		h.Write(b)
		h.Write([]byte{0})
	}
	p.SHA256 = hex.EncodeToString(h.Sum(nil))
	if p.UserTemplate, err = text(".user.txt"); err != nil {
		return nil, err
	}
	if full != nil {
		s := stripX(*full, false)
		p.Schema = &s
	}
	return p, nil
}

// HasMaxChars says whether the task gives the longest answer it asks for.
func (p *ModelPrompt) HasMaxChars() bool { return p.hasMaxCha }

// User is one user turn: user.txt with the input (a finding, a folder's metadata, a skill) as JSON.
func (p *ModelPrompt) User(input Value) (string, error) {
	return fillPrompt(p.UserTemplate, map[string]string{"input": input.Text()}, p.Task+" 的 user.txt")
}

// Messages are the system prompt, each example as a question and its answer, then this input.
func (p *ModelPrompt) Messages(input Value) (Value, error) {
	turn := func(role, content string) Value {
		return VObj(Field{"role", VStr(role)}, Field{"content", VStr(content)})
	}
	out := []Value{turn("system", p.System)}
	for _, e := range p.Examples {
		answer := e.Output.Text()
		if e.Output.Kind == VString {
			answer = e.Output.Str
		}
		u, err := p.User(e.Input)
		if err != nil {
			return Value{}, err
		}
		out = append(out, turn("user", u), turn("assistant", answer))
	}
	u, err := p.User(input)
	if err != nil {
		return Value{}, err
	}
	return VList(append(out, turn("user", u))...), nil
}

// Body is the body of POST /tasks/<task>/v1/chat/completions for this input, as bench/run_eval.py's request_body
// writes it.
func (p *ModelPrompt) Body(input Value) (string, error) {
	m, err := p.Messages(input)
	if err != nil {
		return "", err
	}
	fields := []Field{{"messages", m}, {"stream", VBoolean(true)}, {"luoke_items", VInteger(1)}, {"max_tokens", VInteger(p.MaxTokens)}}
	fields = append(fields, p.Params...)
	if p.Schema != nil {
		short := p.Task
		if i := strings.LastIndex(short, "."); i >= 0 {
			short = short[i+1:]
		}
		fields = append(fields, Field{"response_format", VObj(Field{"type", VStr("json_schema")},
			Field{"json_schema", VObj(Field{"name", VStr(short)}, Field{"schema", *p.Schema})})})
	}
	return VObj(fields...).Text(), nil
}

// Key is what an answer is kept under: this prompt (all of its files) and this input.
func (p *ModelPrompt) Key(input Value) string {
	h := sha256.Sum256([]byte(p.SHA256 + "\x00" + input.Text()))
	return hex.EncodeToString(h[:16])
}

// WithoutThinking is the model's answer without thinking: paired sections, an unclosed one, one with only a close
// (bench/run_eval.py's strip_think), trimmed.
func WithoutThinking(raw string) string {
	t := raw
	for {
		open := strings.Index(t, "<think>")
		if open < 0 {
			break
		}
		if c := strings.Index(t[open+len("<think>"):], "</think>"); c >= 0 {
			end := open + len("<think>") + c + len("</think>")
			t = t[:open] + t[end:]
		} else {
			t = t[:open]
		}
	}
	if c := strings.LastIndex(t, "</think>"); c >= 0 {
		t = t[c+len("</think>"):]
	}
	return aiTrimWSNL(t)
}

// ---------------------------------------------------------------- answers kept between rounds

// ModelAnswer is a model's answer kept for a task and input, and when it was last used.
type ModelAnswer struct {
	Task   string  `json:"task"`
	Key    string  `json:"key"`
	Answer string  `json:"answer"`
	Used   float64 `json:"used"`
}

func modelAnswersTable(s *Store) Table[ModelAnswer] {
	return NewTable[ModelAnswer](s, "model_answers", 1)
}

// ModelAnswers are the answers kept for a task, by key.
func (s *Store) ModelAnswers(task string) map[string]string {
	out := map[string]string{}
	for _, a := range modelAnswersTable(s).Load() {
		if a.Task == task {
			out[a.Key] = a.Answer
		}
	}
	return out
}

// WriteModelAnswers keeps the new answers, marks the ones used this round as used now, and forgets those not used
// since before.
func (s *Store) WriteModelAnswers(task string, fresh map[string]string, used map[string]bool, now, before time.Time) error {
	t := modelAnswersTable(s)
	rows := t.Load()
	at := float64(now.UnixNano()) / 1e9
	set := map[string]ModelAnswer{}
	for k, a := range fresh {
		set[task+"\x00"+k] = ModelAnswer{Task: task, Key: k, Answer: a, Used: at}
	}
	for k := range used {
		if _, isNew := fresh[k]; isNew {
			continue
		}
		if r, ok := rows[task+"\x00"+k]; ok {
			r.Used = at
			set[task+"\x00"+k] = r
		}
	}
	limit := float64(before.UnixNano()) / 1e9
	var del []string
	for id, r := range rows {
		if _, kept := set[id]; kept || r.Task != task {
			continue
		}
		if r.Used < limit {
			del = append(del, id)
		}
	}
	sort.Strings(del)
	return t.Apply(set, del, false)
}
