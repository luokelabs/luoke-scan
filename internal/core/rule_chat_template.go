package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func init() { Register("model.chat-template", NewChatTemplateRule) }

// ChatTemplateRule: the chat templates of the models AI tools downloaded (chattemplate.go), checked for words to the
// model the families' own templates do not have and for characters nobody sees. One finding per model with something
// to say. The rule itself changes nothing and keeps nothing of the template; a model with a folder of its own can be
// moved to the Trash from its card (service.trashableSkill: preselected when high risk, luoke-scan#152), so the
// finding carries the folder's size. Reads only
// the small files a template is in, within bounds, and of a GGUF file only its header; a file not changed since a
// round read it is not read again.
type ChatTemplateRule struct {
	Limits ChatTemplateLimits
	// Dataless says a file is kept only in iCloud: opening it would download it, so it is not opened (nil: its flags
	// say so; tests stand in for iCloud).
	Dataless func(st syscall.Stat_t) bool
}

func (r *ChatTemplateRule) dataless(st syscall.Stat_t) bool {
	if r.Dataless != nil {
		return r.Dataless(st)
	}
	return aiDataless(st)
}

// ChatTemplateLimits bound what a round looks at.
type ChatTemplateLimits struct {
	MaxModels        int   // model folders and Ollama models
	MaxFilesPerModel int   // template files of one model (several revisions, several GGUF files)
	MaxJSONBytes     int64 // a tokenizer_config.json, chat_template.json or Ollama manifest
	MaxTextBytes     int64 // a .jinja file, an Ollama TEMPLATE, SYSTEM or MESSAGE layer
	MaxRoundBytes    int64 // read in a round (files read before and unchanged cost nothing)
	GGUF             GGUFLimits
}

// DefaultChatTemplateLimits: 500 models, 16 files a model, 4 MiB a JSON file, 1 MiB a template, 512 MiB a round.
func DefaultChatTemplateLimits() ChatTemplateLimits {
	return ChatTemplateLimits{MaxModels: 500, MaxFilesPerModel: 16, MaxJSONBytes: 4 << 20, MaxTextBytes: 1 << 20,
		MaxRoundBytes: 512 << 20, GGUF: DefaultGGUFLimits()}
}

// NewChatTemplateRule is the same for this Mac and a fake home: it only reads files.
func NewChatTemplateRule(l *Layout, f *Fakes) Rule {
	return &ChatTemplateRule{Limits: DefaultChatTemplateLimits()}
}

func (r *ChatTemplateRule) ID() string      { return "model.chat-template" }
func (r *ChatTemplateRule) Emits() []string { return []string{"model.chat-template"} }

// chatTemplatePlaces are the folders of aiTools (rule_space_system.go) whose models carry a chat template (Whisper's
// and PyTorch's do not), kept as their own short list.
var chatTemplatePlaces = []struct{ tool, path string }{
	{"Hugging Face", ".cache/huggingface/hub"},
	{"LM Studio", ".lmstudio/models"},
	{"LM Studio", ".cache/lm-studio/models"},
	{"Ollama", ".ollama/models"},
}

type templateFileKind int

const (
	tfConfig templateFileKind = iota // tokenizer_config.json, chat_template.json: "chat_template", a string or [{name, template}]
	tfJinja                          // chat_template.jinja, additional_chat_templates/*.jinja
	tfGGUF                           // a GGUF file's metadata
	tfOllamaTemplate
	tfOllamaSystem
	tfOllamaMessages
)

// part is where in a model the text is, as the evidence says it.
func (k templateFileKind) part() string {
	switch k {
	case tfOllamaSystem:
		return "默认系统提示"
	case tfOllamaMessages:
		return "预设的对话"
	}
	return "对话模板"
}

type templateFile struct {
	real  string // links resolved: what is read
	at    string // where it is as the user finds it (a Hugging Face snapshot's link, not the blob it points to)
	kind  templateFileKind
	shown string // its name: tokenizer_config.json, a GGUF file's, Ollama's TEMPLATE / SYSTEM / MESSAGE
}

type templateModel struct {
	tool, name string
	dir        string // its folder; an Ollama model's manifest
	files      []templateFile
	more       bool // more files than looked at
}

// chatTemplateRow is what a file said when it was last read: an unchanged file is not read again. Kinds only.
type chatTemplateRow struct {
	Sig    string   `json:"sig"`
	Kinds  []string `json:"kinds,omitempty"`
	Sev    Severity `json:"sev,omitempty"`
	TooBig bool     `json:"tooBig,omitempty"`
	Digest string   `json:"digest,omitempty"`
}

// chatTemplateTable keeps the rows; its version goes up when the checks change, so every file is read again.
func chatTemplateTable(s *Store) Table[chatTemplateRow] {
	return NewTable[chatTemplateRow](s, "chat_templates", 2)
}

// chatTemplateSig is a file as it is now: the rule pack, device, inode, size, and when its contents and its inode
// last changed (the change time cannot be set back by hand).
func chatTemplateSig(st syscall.Stat_t) string {
	return fmt.Sprintf("%s|%d:%d|%d|%d.%d|%d.%d", RulePackVersion, st.Dev, st.Ino, st.Size, st.Mtimespec.Sec,
		st.Mtimespec.Nsec, st.Ctimespec.Sec, st.Ctimespec.Nsec)
}

func (r *ChatTemplateRule) Run(ctx *Context) ([]Finding, error) {
	var table *Table[chatTemplateRow]
	known := map[string]chatTemplateRow{}
	if ctx.Store != nil {
		t := chatTemplateTable(ctx.Store)
		table, known = &t, t.Load()
	}
	seen := map[string]chatTemplateRow{}
	budget := r.Limits.MaxRoundBytes
	out := []Finding{}
	var left []string
	unfinished, models := 0, 0
	save := func(done bool) {
		if table == nil {
			return
		}
		if !done {
			table.Apply(seen, nil, false)
		} else if !reflect.DeepEqual(known, seen) {
			table.Replace(seen)
		}
	}
	for _, pl := range chatTemplatePlaces {
		root := filepath.Join(ctx.Home, pl.path)
		if _, ok := aiLstat(root); !ok {
			continue
		}
		if !ctx.MayFollow(root) {
			left = append(left, pl.tool+" 下载的模型")
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
			found = r.ollamaModels(ctx, root, realRoot, &budget)
		default:
			found = r.folderModels(ctx, pl.tool, root)
		}
		for _, m := range found {
			if ctx.IsCancelled() {
				save(false)
				return nil, Skip(Interrupted, out...)
			}
			if models >= r.Limits.MaxModels {
				unfinished++
				continue
			}
			models++
			if f, whole := r.checkModel(ctx, m, known, seen, &budget); f != nil {
				out = append(out, *f)
				if !whole {
					unfinished++
				}
			} else if !whole {
				unfinished++
			}
		}
	}
	save(true)
	if unfinished > 0 {
		out = append(out, Finding{Rule: "model.chat-template.partial", Category: CatSkill, Severity: Low, Verdict: Info, Path: "",
			Title: fmt.Sprintf("有 %d 个模型的对话模板这一轮没查完", unfinished),
			Evidence: map[string]string{"count": strconv.Itoa(unfinished),
				"why": "模板文件太大（JSON 超过 4 MB、模板超过 1 MB、GGUF 文件头超过 64 MB）、模型超过 500 个，或这一轮读得够多了",
				"how": "太大的不会查；别的下一轮接着查"}})
	}
	if len(left) > 0 {
		return nil, Skip(NotLooked(strings.Join(aiSortedUnique(left), "、")), out...)
	}
	return out, nil
}

// checkModel reads (or takes from the last read) each of a model's template files; the finding when something is in
// them. whole: every file of it was looked at.
func (r *ChatTemplateRule) checkModel(ctx *Context, m templateModel, known, seen map[string]chatTemplateRow, budget *int64) (*Finding, bool) {
	whole := !m.more
	kinds := map[TemplateKind]bool{}
	var sev Severity
	var parts, files, digests []string
	var template string
	for _, f := range m.files {
		st, ok := aiLstat(f.real)
		if !ok || !aiStReg(st) {
			continue
		}
		sig := chatTemplateSig(st)
		row, have := seen[f.real]
		if !have || row.Sig != sig {
			row, have = known[f.real]
		}
		if !have || row.Sig != sig {
			if *budget <= 0 {
				whole = false
				continue
			}
			row = r.readFile(f, st, budget)
			row.Sig = sig
		}
		seen[f.real] = row
		if row.TooBig {
			whole = false
		}
		if row.Sev == "" {
			continue
		}
		for _, k := range row.Kinds {
			kinds[TemplateKind(k)] = true
		}
		if row.Sev.Rank() > sev.Rank() || sev == "" {
			sev = row.Sev
		}
		parts = append(parts, f.kind.part())
		files = append(files, aiClean(f.shown, 80))
		if template == "" && strings.HasPrefix(f.at, m.dir+"/") {
			template = f.at // 「在访达里显示」 selects it, not the whole model folder
		}
		digests = append(digests, row.Digest)
	}
	if sev == "" {
		return nil, whole
	}
	var ordered []TemplateKind
	var ids, labels []string
	for _, k := range templateKindOrder {
		if kinds[k] {
			ordered = append(ordered, k)
			ids = append(ids, string(k))
			labels = append(labels, TemplateKindLabel(k))
		}
	}
	name := aiClean(m.name, 80)
	what := "对话模板里多了给模型的话（" + strings.Join(labels, "、") + "）"
	if len(ordered) == 1 && ordered[0] == TplHidden {
		what = "对话模板里藏着看不见的字符"
	}
	files = aiSortedUnique(files)
	if len(files) > 4 {
		files = append(files[:4], "等 "+strconv.Itoa(len(files))+" 个")
	}
	sort.Strings(digests)
	ev := map[string]string{"tool": m.tool, "model": name, "where": strings.Join(aiSortedUnique(parts), "、"),
		"files": strings.Join(files, "、"), "kinds": strings.Join(ids, ","),
		"why": "用这个模型时，对话模板每次都会套在你的话外面交给模型，模型会照着做；各家正常的模板里只有轮次记号、工具调用的格式和几句固定的默认设定。这一个多了：" +
			strings.Join(labels, "、") + "。原文没有记下",
		"how": chatTemplateHow(m.tool, name)}
	if template != "" {
		ev["template"] = ctx.Shown(template)
	}
	// What moving it to the Trash would free: a model with a folder of its own (not Ollama's, whose path is a manifest
	// and whose files are shared) is offered for the Trash as a whole (service.trashableSkill), so its size is the
	// folder's.
	var bytes *int64
	if m.tool != "Ollama" && aiIsDir(m.dir) {
		bytes = Size(AllocatedSize(m.dir))
	}
	// Keyed on the model and what its templates say: a later change is a new finding, not hidden by a 「以后别提」.
	return &Finding{Rule: "model.chat-template", Category: CatSkill, Severity: sev, Verdict: Info, Path: m.dir, Bytes: bytes,
		Title: m.tool + " 的模型 " + name + "：" + what, Evidence: ev,
		Key: HomeRelative(m.dir, ctx.Home) + "|" + ShortHash(strings.Join(digests, ","))}, whole
}

func chatTemplateHow(tool, name string) string {
	switch tool {
	case "Hugging Face":
		return "多半不是原版：到 Hugging Face 上看清发布者，从原版重新下载（`hf download " + name + "`）；拿不准就先别用这个模型"
	case "Ollama":
		return "是你自己用 Modelfile 建的，看看里面的 SYSTEM、TEMPLATE 是不是你写的；不是的话 `ollama rm " + name + "` 删掉，从 ollama.com 上的原版重新拉"
	}
	return "在 " + tool + " 里删掉这个模型，从可信的发布者重新下载；拿不准就先别用"
}

// readFile reads one template file within the limits and checks it; budget goes down by what was read.
func (r *ChatTemplateRule) readFile(f templateFile, st syscall.Stat_t, budget *int64) chatTemplateRow {
	var row chatTemplateRow
	var texts []string
	var syntax TemplateSyntax
	if f.kind == tfGGUF {
		if r.dataless(st) { // only in iCloud: reading even its header would download all of it
			return row
		}
		fd, err := syscall.Open(f.real, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return row
		}
		file := os.NewFile(uintptr(fd), f.real)
		g := ReadGGUFTemplates(file, r.Limits.GGUF)
		file.Close()
		*budget -= g.Read
		row.TooBig = g.TooBig
		names := make([]string, 0, len(g.Templates))
		for n := range g.Templates {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			texts = append(texts, g.Templates[n])
		}
		syntax = SyntaxJinja
	} else {
		max := r.Limits.MaxTextBytes
		if f.kind == tfConfig {
			max = r.Limits.MaxJSONBytes
		}
		if st.Size > max {
			row.TooBig = true
			return row
		}
		if r.dataless(st) { // only in iCloud: reading it would download it
			return row
		}
		data, ok := aiReadHead(f.real, int(st.Size))
		if !ok {
			return row
		}
		*budget -= int64(len(data))
		text, ok := aiDecodeUTF8(data)
		if !ok {
			return row
		}
		switch f.kind {
		case tfConfig:
			texts, syntax = configTemplates(data), SyntaxJinja
		case tfJinja:
			texts, syntax = []string{text}, SyntaxJinja
		case tfOllamaTemplate:
			texts, syntax = []string{text}, SyntaxGo
		case tfOllamaSystem:
			texts, syntax = []string{text}, SyntaxPlain
		case tfOllamaMessages:
			var msgs []struct {
				Content string `json:"content"`
			}
			if json.Unmarshal(data, &msgs) == nil {
				for _, m := range msgs {
					texts = append(texts, m.Content)
				}
			}
			syntax = SyntaxPlain
		}
	}
	found := map[TemplateKind]bool{}
	h := sha256.New()
	for _, t := range texts {
		h.Write([]byte(t))
		h.Write([]byte{0})
		c := CheckChatTemplate(t, syntax)
		for _, k := range c.Kinds {
			found[k] = true
		}
		if c.Severity.Rank() > row.Sev.Rank() || row.Sev == "" {
			row.Sev = c.Severity
		}
	}
	for _, k := range templateKindOrder {
		if found[k] {
			row.Kinds = append(row.Kinds, string(k))
		}
	}
	sum := h.Sum(nil)
	row.Digest = hex.EncodeToString(sum[:8])
	return row
}

// configTemplates are the templates in a tokenizer_config.json or chat_template.json: "chat_template" as one string,
// or as a list of {"name", "template"} (a default one and others, like tool_use).
func configTemplates(data []byte) []string {
	var cfg struct {
		ChatTemplate json.RawMessage `json:"chat_template"`
	}
	if json.Unmarshal(data, &cfg) != nil || len(cfg.ChatTemplate) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(cfg.ChatTemplate, &one) == nil {
		return []string{one}
	}
	var named []struct {
		Template string `json:"template"`
	}
	var out []string
	if json.Unmarshal(cfg.ChatTemplate, &named) == nil {
		for _, n := range named {
			out = append(out, n.Template)
		}
	}
	return out
}

// sortedChildren are a folder's children by name.
func sortedChildren(dir string) []string {
	c := Children(dir)
	sort.Strings(c)
	return c
}

var ggufShard = regexp.MustCompile(`-(\d{5})-of-\d{5}\.gguf$`)

// templateFileIn is a template file at path, links followed while this round may look (inside within, when given).
func templateFileIn(ctx *Context, path, within string, kind templateFileKind, shown string) (templateFile, bool) {
	if _, ok := aiLstat(path); !ok {
		return templateFile{}, false
	}
	real, ok := ResolvedPath(path, ctx)
	if !ok || !aiIsReg(real) || (within != "" && !strings.HasPrefix(real, within+"/")) {
		return templateFile{}, false
	}
	return templateFile{real: real, at: path, kind: kind, shown: shown}, true
}

// templateFilesIn are the template files in a model's folder (a Hugging Face snapshot, an LM Studio model): the
// tokenizer's config, the template files, and GGUF files (not a vision projector's, of a split model only the first
// part), one folder down too when deep.
func templateFilesIn(ctx *Context, dir, within string, deep bool) []templateFile {
	var out []templateFile
	add := func(path string, kind templateFileKind) {
		if f, ok := templateFileIn(ctx, path, within, kind, filepath.Base(path)); ok {
			out = append(out, f)
		}
	}
	add(filepath.Join(dir, "tokenizer_config.json"), tfConfig)
	add(filepath.Join(dir, "chat_template.json"), tfConfig)
	add(filepath.Join(dir, "chat_template.jinja"), tfJinja)
	extra := 0
	for _, p := range sortedChildren(filepath.Join(dir, "additional_chat_templates")) {
		if strings.HasSuffix(p, ".jinja") && extra < 8 {
			add(p, tfJinja)
			extra++
		}
	}
	ggufs := func(d string) {
		for _, p := range sortedChildren(d) {
			n := strings.ToLower(filepath.Base(p))
			if !strings.HasSuffix(n, ".gguf") || strings.Contains(n, "mmproj") {
				continue
			}
			if m := ggufShard.FindStringSubmatch(n); m != nil && m[1] != "00001" {
				continue
			}
			add(p, tfGGUF)
		}
	}
	ggufs(dir)
	if deep {
		sub := 0
		for _, d := range sortedChildren(dir) {
			if sub >= 64 {
				break
			}
			if aiIsDir(d) && filepath.Base(d) != "additional_chat_templates" {
				sub++
				ggufs(d)
			}
		}
	}
	return out
}

// capFiles keeps a model's first files.
func (r *ChatTemplateRule) capFiles(m *templateModel) {
	if len(m.files) > r.Limits.MaxFilesPerModel {
		m.files, m.more = m.files[:r.Limits.MaxFilesPerModel], true
	}
}

// hfModels: each models--org--name in the hub, the files of its snapshots (links into the hub's blobs; none followed
// out of the hub).
func (r *ChatTemplateRule) hfModels(ctx *Context, root, realRoot string) []templateModel {
	var out []templateModel
	for _, d := range sortedChildren(root) {
		n := filepath.Base(d)
		if !strings.HasPrefix(n, "models--") || !aiIsDir(d) {
			continue
		}
		m := templateModel{tool: "Hugging Face", name: strings.ReplaceAll(n[len("models--"):], "--", "/"), dir: d}
		snaps, more := hfSnapshots(d, hfMaxSnapshots)
		m.more = more
		for _, s := range snaps {
			m.files = append(m.files, templateFilesIn(ctx, s, realRoot, true)...)
		}
		r.capFiles(&m)
		if len(m.files) > 0 || m.more {
			out = append(out, m)
		}
	}
	return out
}

// hfMaxSnapshots: the revisions of one hub model looked at.
const hfMaxSnapshots = 4

var hfRevision = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// hfSnapshots: the snapshot folders of a hub model to look at, at most max. First the ones its refs name (refs/main
// and the like: what the tools load when asked for a model by name), then the others newest first. The hub keeps every
// revision ever downloaded; the old ones past max are left without counting as not looked at, else a model updated a
// few times would say so every round. more: refs name more than max.
func hfSnapshots(dir string, max int) (out []string, more bool) {
	snaps := filepath.Join(dir, "snapshots")
	taken := map[string]bool{}
	take := func(s string) bool {
		if taken[s] || !aiIsDir(s) {
			return false
		}
		if len(out) >= max {
			return true
		}
		taken[s] = true
		out = append(out, s)
		return false
	}
	for _, rev := range hfRefs(filepath.Join(dir, "refs")) {
		if take(filepath.Join(snaps, rev)) {
			more = true
		}
	}
	type snap struct {
		path string
		at   int64
	}
	var rest []snap
	for _, s := range sortedChildren(snaps) {
		if st, ok := aiLstat(s); ok && aiStDir(st) && !taken[s] {
			rest = append(rest, snap{s, st.Mtimespec.Nano()})
		}
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].at > rest[j].at })
	for _, s := range rest {
		take(s.path)
	}
	return out, more
}

// hfRefs: the revisions a hub model's refs name (refs/main first, then the others, refs/pr/* too), each a commit
// hash: anything else in a ref is not a folder name to look up.
func hfRefs(refs string) []string {
	var names []string
	for _, p := range sortedChildren(refs) {
		if aiIsDir(p) {
			names = append(names, sortedChildren(p)...)
		} else {
			names = append(names, p)
		}
	}
	sort.SliceStable(names, func(i, j int) bool { return filepath.Base(names[i]) == "main" && filepath.Base(names[j]) != "main" })
	var out []string
	for _, p := range names {
		st, ok := aiLstat(p)
		if !ok || !aiStReg(st) || st.Size > 128 || aiDataless(st) {
			continue
		}
		data, ok := aiReadHead(p, int(st.Size))
		if rev := strings.TrimSpace(string(data)); ok && hfRevision.MatchString(rev) {
			out = append(out, rev)
		}
	}
	return out
}

// folderModels: LM Studio's <publisher>/<model> folders.
func (r *ChatTemplateRule) folderModels(ctx *Context, tool, root string) []templateModel {
	var out []templateModel
	folders := modelFolders(root, tool)
	sort.SliceStable(folders, func(i, j int) bool { return folders[i].dir < folders[j].dir })
	for _, mf := range folders {
		m := templateModel{tool: tool, name: mf.name, dir: mf.dir, files: templateFilesIn(ctx, mf.dir, "", false)}
		r.capFiles(&m)
		if len(m.files) > 0 {
			out = append(out, m)
		}
	}
	return out
}

var ollamaDigest = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// ollamaModels: each manifest (manifests/<registry>/<namespace>/<model>/<tag>), its TEMPLATE, SYSTEM and MESSAGE
// layers in blobs/. The manifest says which blob: only a well-formed digest is taken, and only a file in the blobs.
func (r *ChatTemplateRule) ollamaModels(ctx *Context, root, realRoot string, budget *int64) []templateModel {
	var out []templateModel
	manifests := filepath.Join(root, "manifests")
	listed := 0
	for _, host := range sortedChildren(manifests) {
		for _, ns := range sortedChildren(host) {
			for _, model := range sortedChildren(ns) {
				for _, tag := range sortedChildren(model) {
					if listed >= 4*r.Limits.MaxModels {
						return out
					}
					listed++
					st, ok := aiLstat(tag)
					if !ok || !aiStReg(st) || st.Size > r.Limits.MaxJSONBytes {
						continue
					}
					data, ok := aiReadHead(tag, int(st.Size))
					if !ok {
						continue
					}
					*budget -= int64(len(data))
					var man struct {
						Layers []struct {
							MediaType string `json:"mediaType"`
							Digest    string `json:"digest"`
						} `json:"layers"`
					}
					if json.Unmarshal(data, &man) != nil {
						continue
					}
					m := templateModel{tool: "Ollama", name: ollamaName(filepath.Base(host), filepath.Base(ns), filepath.Base(model),
						filepath.Base(tag)), dir: tag}
					for _, l := range man.Layers {
						var kind templateFileKind
						var shown string
						switch l.MediaType {
						case "application/vnd.ollama.image.template":
							kind, shown = tfOllamaTemplate, "TEMPLATE"
						case "application/vnd.ollama.image.system":
							kind, shown = tfOllamaSystem, "SYSTEM"
						case "application/vnd.ollama.image.messages":
							kind, shown = tfOllamaMessages, "MESSAGE"
						default:
							continue
						}
						d := ollamaDigest.FindStringSubmatch(l.Digest)
						if d == nil {
							continue
						}
						if f, ok := templateFileIn(ctx, filepath.Join(root, "blobs", "sha256-"+d[1]), realRoot, kind, shown); ok {
							m.files = append(m.files, f)
						}
					}
					r.capFiles(&m)
					if len(m.files) > 0 {
						out = append(out, m)
					}
				}
			}
		}
	}
	return out
}

// ollamaName is a model as `ollama list` names it: qwen2.5:7b for the library's, namespace/model:tag on the registry,
// host/namespace/model:tag elsewhere (hf.co/…).
func ollamaName(host, ns, model, tag string) string {
	switch {
	case host == "registry.ollama.ai" && ns == "library":
		return model + ":" + tag
	case host == "registry.ollama.ai":
		return ns + "/" + model + ":" + tag
	}
	return host + "/" + ns + "/" + model + ":" + tag
}
