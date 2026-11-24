package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	assets "github.com/luokelabs/luoke-scan"
)

// The curated lists are data files, rules/*.json at the repository's root, carried inside the program (assets.FS) and
// read once at start: the rebuildable caches, the temp folder prefixes of test tools, where VM and AI tools keep their
// space, the folders a project's tools make again, the settings files that say what browsers and AI tools run, and what the
// folders of a home are (whose, the user's own or not, what deleting one loses).
// Lists only: how serious a finding is, what is urgent, what may go without a click (autoCaches, autoTemp) and the
// checks made before anything is removed stay in code.
//
// A file that cannot be read (bad JSON, a field this program does not know, another version, an entry that fails its
// checks) leaves its lists empty: the rules using it skip with a reason (rulesMissing), and automatic cleaning finds
// nothing it knows. The tests read every file the same way, so a broken one does not get past them.

// rulesVersion is the version of the files' shape this program reads.
const rulesVersion = 1

// rulesFiles are the files read, in the order the tests check them.
var rulesFiles = []string{"rules/caches.json", "rules/temp-folders.json", "rules/space-tools.json", "rules/build-artifacts.json",
	"rules/settings-files.json", "rules/folders.json"}

// The files as read (with why and samples, for the tests), and what came of reading each.
var (
	cachesRules   cachesList
	tempRules     tempList
	spaceRules    spaceList
	artifactRules artifactsList
	settingsRules settingsList
	foldersRules  foldersList

	cachesErr, tempErr, spaceErr, artifactsErr, settingsErr, foldersErr error
)

// The files are read here rather than in the variables' initializers: the checks use package-level values (regular
// expressions) that Go would not set up first, as it does not follow a call through a type parameter's method.
func init() {
	cachesRules, cachesErr = readRules[cachesList]("rules/caches.json")
	tempRules, tempErr = readRules[tempList]("rules/temp-folders.json")
	spaceRules, spaceErr = readRules[spaceList]("rules/space-tools.json")
	artifactRules, artifactsErr = readRules[artifactsList]("rules/build-artifacts.json")
	settingsRules, settingsErr = readRules[settingsList]("rules/settings-files.json")
	foldersRules, foldersErr = readRules[foldersList]("rules/folders.json")

	KnownCaches, CacheUsers = cachesRules.known(), cachesRules.users()
	AutoKnownTemp = tempRules.tools()
	vmTools, vmMarkers, aiTools = spaceRules.vmTools(), spaceRules.vmMarkers(), spaceRules.aiTools()
	staleArtifactKinds = artifactRules.kinds()
	chromiumBrowsers, mcpConfigs = settingsRules.browsers(), settingsRules.mcpConfigs()
	fileKinds = foldersRules.kinds()
}

// fileKinds: a file's extension (lowercase) → its kind.
var fileKinds map[string]string

// rulesMissing is why a check did not run: a list it needs could not be read.
func rulesMissing(file string) error {
	return Skip("这一版带的清单 " + file + " 读不出来，这一项没查")
}

type rulesChecker interface{ check() error }

// readRules reads one file of assets.FS (decodeRules); on any error the lists are empty.
func readRules[T any, P interface {
	*T
	rulesChecker
}](name string) (T, error) {
	var zero T
	b, err := assets.FS.ReadFile(name)
	if err != nil {
		return zero, err
	}
	v, err := decodeRules[T, P](b)
	if err != nil {
		return zero, fmt.Errorf("%s：%w", name, err)
	}
	return v, nil
}

// decodeRules reads a rules file strictly: one JSON object, no field the program does not know, nothing after it; then
// its own checks.
func decodeRules[T any, P interface {
	*T
	rulesChecker
}](b []byte) (T, error) {
	var v T
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(P(&v)); err != nil {
		return v, err
	}
	if _, err := d.Token(); err != io.EOF {
		return v, errors.New("JSON 后面还有别的内容")
	}
	return v, P(&v).check()
}

// rulesHead is what every file starts with: the version of its shape, and what it is about (how an entry is read,
// how a new one is treated), for whoever adds to it.
type rulesHead struct {
	Version int      `json:"version"`
	About   []string `json:"about"`
}

func (h rulesHead) check() error {
	if h.Version != rulesVersion {
		return fmt.Errorf("version 是 %d，这一版只认 %d", h.Version, rulesVersion)
	}
	if len(h.About) == 0 {
		return errors.New("缺 about：说明这个文件是什么、新加的条目怎么算")
	}
	return nil
}

// rulesError names the entry a problem is in.
func rulesError(list string, i int, name, format string, args ...any) error {
	return fmt.Errorf("%s 第 %d 条（%s）：%s", list, i+1, name, fmt.Sprintf(format, args...))
}

// checkRelative: a path under the home (or the folder the list is about), spelled plainly: not empty, not absolute,
// not from ~, no empty, . or .. part.
func checkRelative(p string) error {
	if p == "" {
		return errors.New("路径是空的")
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") {
		return fmt.Errorf("%q 要写成相对路径（不以 / 或 ~ 开头）", p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsRune(part, 0) {
			return fmt.Errorf("%q 里有空的、. 或 .. 的一段", p)
		}
	}
	return nil
}

// within: p is dir or inside it (both relative, slash-separated).
func within(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// checkFiles: a sample's files, at least one, each a relative path.
func checkFiles(files []string) error {
	if len(files) == 0 {
		return errors.New("样例没有 files")
	}
	for _, f := range files {
		if err := checkRelative(f); err != nil {
			return err
		}
	}
	return nil
}

func oneOf(s string, allowed ...string) bool {
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- rules/caches.json

type cachesList struct {
	rulesHead
	Caches    []cacheEntry `json:"caches"`
	NotCaches []notCache   `json:"notCaches"`
}

type cacheEntry struct {
	ID      string            `json:"id"`
	Path    string            `json:"path"`
	Tool    string            `json:"tool"`
	Clean   string            `json:"clean"`
	Command string            `json:"command,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Users   []string          `json:"users"`
	Why     string            `json:"why"`
	Samples []cacheSample     `json:"samples"`
}

// cacheSample: files made in a fake home, the programs running, and what comes of it: auto (reported, cleaned without a
// click), ask (reported, cleaned once the user clicks), none (not reported).
type cacheSample struct {
	Files   []string `json:"files"`
	Running []string `json:"running,omitempty"`
	Expect  string   `json:"expect"`
}

// notCache is a place that looks like a cache but holds what deleting it would lose.
type notCache struct {
	Path string `json:"path"`
	Why  string `json:"why"`
}

var (
	cacheIDShape   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	commandShape   = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	envNameShape   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	programNameBad = regexp.MustCompile(`[/\x00]`)
)

func (f *cachesList) check() error {
	if err := f.rulesHead.check(); err != nil {
		return err
	}
	if len(f.Caches) == 0 {
		return errors.New("caches 是空的")
	}
	ids, paths := map[string]bool{}, map[string]bool{}
	for i, c := range f.Caches {
		fail := func(format string, args ...any) error { return rulesError("caches", i, c.ID, format, args...) }
		if !cacheIDShape.MatchString(c.ID) {
			return fail("id 只用小写字母、数字和 -")
		}
		if ids[c.ID] {
			return fail("id 重了")
		}
		ids[c.ID] = true
		if err := checkRelative(c.Path); err != nil {
			return fail("path：%v", err)
		}
		if paths[c.Path] {
			return fail("path 重了")
		}
		paths[c.Path] = true
		if c.Tool == "" || c.Clean == "" || c.Why == "" {
			return fail("tool、clean、why 都要写")
		}
		if c.Command != "" && !commandShape.MatchString(c.Command) {
			return fail("command 只写命令名")
		}
		if len(c.Env) > 0 && c.Command == "" {
			return fail("env 是给 command 用的，没有 command 就不写")
		}
		for k, v := range c.Env {
			if !envNameShape.MatchString(k) {
				return fail("env 的名字 %q 不对", k)
			}
			if err := checkRelative(v); err != nil {
				return fail("env %s：%v", k, err)
			}
		}
		if len(c.Users) == 0 {
			return fail("要写 users：哪些程序在用它（不知道谁在用，就没法知道它没在用）")
		}
		for _, u := range c.Users {
			if u == "" || programNameBad.MatchString(u) {
				return fail("users 里的 %q 要是程序名", u)
			}
		}
		if len(c.Samples) == 0 {
			return fail("要有 samples")
		}
		for _, s := range c.Samples {
			if err := checkFiles(s.Files); err != nil {
				return fail("samples：%v", err)
			}
			if !oneOf(s.Expect, "auto", "ask", "none") {
				return fail("samples 的 expect 只能是 auto、ask、none")
			}
			for _, u := range s.Running {
				if u == "" {
					return fail("samples 的 running 里有空的")
				}
			}
		}
	}
	for i, c := range f.Caches {
		for _, o := range f.Caches[i+1:] {
			if within(c.Path, o.Path) || within(o.Path, c.Path) {
				return rulesError("caches", i, c.ID, "path 和 %s 的套在一起，同一个文件夹会算两遍", o.ID)
			}
		}
	}
	for i, n := range f.NotCaches {
		if err := checkRelative(n.Path); err != nil {
			return rulesError("notCaches", i, n.Path, "%v", err)
		}
		if n.Why == "" {
			return rulesError("notCaches", i, n.Path, "要写 why")
		}
		for _, c := range f.Caches {
			if within(n.Path, c.Path) {
				return rulesError("notCaches", i, n.Path, "在缓存 %s 里：删那个缓存会把它一起删掉", c.ID)
			}
		}
	}
	return nil
}

func (f cachesList) known() []RebuildableCache {
	var out []RebuildableCache
	for _, c := range f.Caches {
		out = append(out, RebuildableCache{ID: c.ID, Path: c.Path, Tool: c.Tool, Clean: c.Clean, Command: c.Command, Env: c.Env})
	}
	return out
}

func (f cachesList) users() map[string][]string {
	out := map[string][]string{}
	for _, c := range f.Caches {
		out[c.ID] = c.Users
	}
	return out
}

// ---------------------------------------------------------------- rules/temp-folders.json

type tempList struct {
	rulesHead
	Folders []tempEntry `json:"folders"`
}

type tempEntry struct {
	Prefix  string       `json:"prefix"`
	Tool    string       `json:"tool"`
	Why     string       `json:"why"`
	Samples []tempSample `json:"samples"`
}

// tempSample: files made in a fake temp folder, the command lines of the programs running (lowercased), and what comes
// of it (as cacheSample).
type tempSample struct {
	Files        []string `json:"files"`
	CommandLines []string `json:"commandLines,omitempty"`
	Expect       string   `json:"expect"`
}

func (f *tempList) check() error {
	if err := f.rulesHead.check(); err != nil {
		return err
	}
	if len(f.Folders) == 0 {
		return errors.New("folders 是空的")
	}
	seen := map[string]bool{}
	for i, e := range f.Folders {
		fail := func(format string, args ...any) error { return rulesError("folders", i, e.Prefix, format, args...) }
		if p, ok := TempLeakPrefix(e.Prefix + "-AbC123"); !ok || p != e.Prefix || strings.Contains(e.Prefix, "/") {
			return fail("prefix 要是临时文件夹名去掉随机后缀的部分")
		}
		if seen[e.Prefix] {
			return fail("prefix 重了")
		}
		seen[e.Prefix] = true
		if e.Tool == "" || e.Why == "" {
			return fail("tool、why 都要写")
		}
		if len(e.Samples) == 0 {
			return fail("要有 samples")
		}
		for _, s := range e.Samples {
			if err := checkFiles(s.Files); err != nil {
				return fail("samples：%v", err)
			}
			for _, file := range s.Files {
				if p, ok := TempLeakPrefix(strings.SplitN(file, "/", 2)[0]); !ok || p != e.Prefix {
					return fail("samples 的 %q 不在这个前缀的文件夹里", file)
				}
			}
			if !oneOf(s.Expect, "auto", "ask", "none") {
				return fail("samples 的 expect 只能是 auto、ask、none")
			}
		}
	}
	return nil
}

func (f tempList) tools() map[string]string {
	out := map[string]string{}
	for _, e := range f.Folders {
		out[e.Prefix] = e.Tool
	}
	return out
}

// ---------------------------------------------------------------- rules/space-tools.json

type spaceList struct {
	rulesHead
	VMDisks  []vmEntry `json:"vmDisks"`
	AIModels []aiEntry `json:"aiModels"`
}

type vmEntry struct {
	Tool    string       `json:"tool"`
	Paths   []string     `json:"paths"`
	Explain string       `json:"explain"`
	How     string       `json:"how"`
	Signs   *vmSigns     `json:"signs,omitempty"`
	Why     string       `json:"why"`
	Samples []pathSample `json:"samples"`
}

// vmSigns are signs the tool is installed: its folder in the home, its app in an app folder.
type vmSigns struct {
	Folder string `json:"folder"`
	App    string `json:"app"`
}

type aiEntry struct {
	Tool    string       `json:"tool"`
	Path    string       `json:"path"`
	Models  string       `json:"models,omitempty"`
	How     string       `json:"how"`
	Why     string       `json:"why"`
	Samples []pathSample `json:"samples"`
}

// pathSample: files made (in a fake home, or a fake project) and what comes of it: found (reported) or none; models
// are the models listed one by one.
type pathSample struct {
	Files  []string `json:"files"`
	Models []string `json:"models,omitempty"`
	Expect string   `json:"expect"`
}

// How each model has a folder of its own under an AI tool's folder (aiTool.models): Hugging Face's models--org--name and
// datasets--org--name, or <publisher>/<model>.
const (
	modelsHuggingFace = "huggingface"
	modelsPublisher   = "publisher/model"
)

func checkPathSamples(samples []pathSample, models bool) error {
	if len(samples) == 0 {
		return errors.New("要有 samples")
	}
	for _, s := range samples {
		if err := checkFiles(s.Files); err != nil {
			return err
		}
		if !oneOf(s.Expect, "found", "none") {
			return errors.New("samples 的 expect 只能是 found、none")
		}
		if len(s.Models) > 0 && (!models || s.Expect != "found") {
			return errors.New("samples 的 models 只给一个模型一个文件夹的、报出来的写")
		}
	}
	return nil
}

func (f *spaceList) check() error {
	if err := f.rulesHead.check(); err != nil {
		return err
	}
	if len(f.VMDisks) == 0 || len(f.AIModels) == 0 {
		return errors.New("vmDisks、aiModels 不能是空的")
	}
	tools := map[string]bool{}
	for i, v := range f.VMDisks {
		fail := func(format string, args ...any) error { return rulesError("vmDisks", i, v.Tool, format, args...) }
		if v.Tool == "" || v.Explain == "" || v.How == "" || v.Why == "" {
			return fail("tool、explain、how、why 都要写")
		}
		if tools[v.Tool] {
			return fail("tool 重了")
		}
		tools[v.Tool] = true
		if len(v.Paths) == 0 {
			return fail("要写 paths")
		}
		for _, p := range v.Paths {
			if err := checkRelative(p); err != nil {
				return fail("paths：%v", err)
			}
		}
		if s := v.Signs; s != nil {
			if err := checkRelative(s.Folder); err != nil {
				return fail("signs 的 folder：%v", err)
			}
			if !strings.HasSuffix(s.App, ".app") || strings.Contains(s.App, "/") {
				return fail("signs 的 app 写应用的文件名（某某.app）")
			}
		}
		if err := checkPathSamples(v.Samples, false); err != nil {
			return fail("%v", err)
		}
	}
	paths := map[string]bool{}
	for i, a := range f.AIModels {
		fail := func(format string, args ...any) error { return rulesError("aiModels", i, a.Tool, format, args...) }
		if a.Tool == "" || a.How == "" || a.Why == "" {
			return fail("tool、how、why 都要写")
		}
		if err := checkRelative(a.Path); err != nil {
			return fail("path：%v", err)
		}
		if paths[a.Path] {
			return fail("path 重了")
		}
		paths[a.Path] = true
		if !oneOf(a.Models, "", modelsHuggingFace, modelsPublisher) {
			return fail("models 只能是 %s、%s 或不写", modelsHuggingFace, modelsPublisher)
		}
		if err := checkPathSamples(a.Samples, a.Models != ""); err != nil {
			return fail("%v", err)
		}
	}
	return nil
}

// vmTool: a container or VM tool that keeps everything inside one large disk image (sparse: what counts is what it
// holds). explain is what the user is told of it, how what to do.
type vmTool struct {
	tool    string
	paths   []string
	explain string
	how     string
}

type vmSign struct{ folder, app string }

// aiTool: the folder of an AI tool's downloaded models. models: how each model is a folder of its own (offered one by
// one); "" none, only the total counts.
type aiTool struct {
	tool, path string
	models     string
	how        string
}

func (f spaceList) vmTools() []vmTool {
	var out []vmTool
	for _, v := range f.VMDisks {
		out = append(out, vmTool{tool: v.Tool, paths: v.Paths, explain: v.Explain, how: v.How})
	}
	return out
}

func (f spaceList) vmMarkers() map[string]vmSign {
	out := map[string]vmSign{}
	for _, v := range f.VMDisks {
		if v.Signs != nil {
			out[v.Tool] = vmSign{folder: v.Signs.Folder, app: v.Signs.App}
		}
	}
	return out
}

func (f spaceList) aiTools() []aiTool {
	var out []aiTool
	for _, a := range f.AIModels {
		out = append(out, aiTool{tool: a.Tool, path: a.Path, models: a.Models, how: a.How})
	}
	return out
}

// ---------------------------------------------------------------- rules/build-artifacts.json

type artifactsList struct {
	rulesHead
	Artifacts []artifactEntry `json:"artifacts"`
}

type artifactEntry struct {
	Name    string       `json:"name"`
	Markers []string     `json:"markers"`
	Inside  string       `json:"inside,omitempty"`
	Again   string       `json:"again"`
	Why     string       `json:"why"`
	Samples []pathSample `json:"samples"`
}

func (f *artifactsList) check() error {
	if err := f.rulesHead.check(); err != nil {
		return err
	}
	if len(f.Artifacts) == 0 {
		return errors.New("artifacts 是空的")
	}
	seen := map[string]bool{}
	for i, a := range f.Artifacts {
		fail := func(format string, args ...any) error { return rulesError("artifacts", i, a.Name, format, args...) }
		if err := checkRelative(a.Name); err != nil || strings.Contains(a.Name, "/") {
			return fail("name 是一个文件夹名")
		}
		if a.Again == "" || a.Why == "" {
			return fail("again、why 都要写")
		}
		if len(a.Markers) == 0 {
			return fail("要写 markers")
		}
		for _, m := range a.Markers {
			if ext, ok := strings.CutPrefix(m, "*."); ok {
				if ext == "" || strings.ContainsAny(ext, "/*") {
					return fail("markers 的 %q：*. 后面写扩展名", m)
				}
			} else if err := checkRelative(m); err != nil {
				return fail("markers：%v", err)
			}
			if seen[a.Name+"\x00"+m] {
				return fail("和前面一条一样（同名、同一个 marker），后面这条永远用不上")
			}
			seen[a.Name+"\x00"+m] = true
		}
		if a.Inside != "" {
			if err := checkRelative(a.Inside); err != nil {
				return fail("inside：%v", err)
			}
		}
		if err := checkPathSamples(a.Samples, false); err != nil {
			return fail("%v", err)
		}
	}
	return nil
}

func (f artifactsList) kinds() []staleArtifactKind {
	var out []staleArtifactKind
	for _, a := range f.Artifacts {
		out = append(out, staleArtifactKind{name: a.Name, markers: a.Markers, inside: a.Inside, again: a.Again})
	}
	return out
}

// ---------------------------------------------------------------- rules/settings-files.json

type settingsList struct {
	rulesHead
	Browsers []browserEntry `json:"browsers"`
	MCP      []mcpEntry     `json:"mcp"`
}

type browserEntry struct {
	Name     string        `json:"name"`
	Path     string        `json:"path"`
	BundleID string        `json:"bundleID"`
	Why      string        `json:"why"`
	Samples  []writeSample `json:"samples"`
}

type mcpEntry struct {
	Tool    string        `json:"tool"`
	Path    string        `json:"path"`
	Key     string        `json:"key"`
	Why     string        `json:"why"`
	Samples []writeSample `json:"samples"`
}

// writeSample: files written in a fake home (a string as it is, anything else as JSON), and the finding that comes of
// it (a rule name), or none.
type writeSample struct {
	Write  map[string]json.RawMessage `json:"write"`
	Expect string                     `json:"expect"`
}

func checkWriteSamples(samples []writeSample, expect ...string) error {
	if len(samples) == 0 {
		return errors.New("要有 samples")
	}
	for _, s := range samples {
		if len(s.Write) == 0 {
			return errors.New("样例没有 write")
		}
		for p := range s.Write {
			if err := checkRelative(p); err != nil {
				return err
			}
		}
		if !oneOf(s.Expect, append(expect, "none")...) {
			return fmt.Errorf("samples 的 expect 只能是 %s 或 none", strings.Join(expect, "、"))
		}
	}
	return nil
}

func (f *settingsList) check() error {
	if err := f.rulesHead.check(); err != nil {
		return err
	}
	if len(f.Browsers) == 0 || len(f.MCP) == 0 {
		return errors.New("browsers、mcp 不能是空的")
	}
	names, paths := map[string]bool{}, map[string]bool{}
	for i, b := range f.Browsers {
		fail := func(format string, args ...any) error { return rulesError("browsers", i, b.Name, format, args...) }
		if b.Name == "" || b.Why == "" {
			return fail("name、why 都要写")
		}
		if names[b.Name] {
			return fail("name 重了")
		}
		names[b.Name] = true
		if err := checkRelative(b.Path); err != nil {
			return fail("path：%v", err)
		}
		if paths[b.Path] {
			return fail("path 重了")
		}
		paths[b.Path] = true
		if !bundleIDShape.MatchString(b.BundleID) {
			return fail("bundleID 不对")
		}
		if err := checkWriteSamples(b.Samples, "browser.extensions", "browser.forced-extensions", "browser.sideloaded-extensions"); err != nil {
			return fail("%v", err)
		}
	}
	names, paths = map[string]bool{}, map[string]bool{}
	for i, m := range f.MCP {
		fail := func(format string, args ...any) error { return rulesError("mcp", i, m.Tool, format, args...) }
		if m.Tool == "" || m.Key == "" || m.Why == "" {
			return fail("tool、key、why 都要写")
		}
		if names[m.Tool] {
			return fail("tool 重了")
		}
		names[m.Tool] = true
		if err := checkRelative(m.Path); err != nil {
			return fail("path：%v", err)
		}
		if paths[m.Path] {
			return fail("path 重了")
		}
		paths[m.Path] = true
		if err := checkWriteSamples(m.Samples, "mcp.servers", "mcp.secrets"); err != nil {
			return fail("%v", err)
		}
	}
	return nil
}

// chromiumBrowser: a Chromium browser's user data folder under the home, and its bundle id (managed preferences).
type chromiumBrowser struct{ name, path, bundleID string }

// mcpConfig: where a tool keeps its MCP servers, relative to the home, and under which key.
type mcpConfig struct{ tool, path, key string }

func (f settingsList) browsers() []chromiumBrowser {
	var out []chromiumBrowser
	for _, b := range f.Browsers {
		out = append(out, chromiumBrowser{name: b.Name, path: b.Path, bundleID: b.BundleID})
	}
	return out
}

func (f settingsList) mcpConfigs() []mcpConfig {
	var out []mcpConfig
	for _, m := range f.MCP {
		out = append(out, mcpConfig{tool: m.Tool, path: m.Path, key: m.Key})
	}
	return out
}

// ---------------------------------------------------------------- rules/folders.json

type foldersList struct {
	rulesHead
	Kinds   []kindEntry   `json:"kinds"`
	Actions []actionEntry `json:"actions"`
	Folders []folderEntry `json:"folders"`
}

// actionEntry: a way to make room in a folder that is not the scan's own cleaning: where it is done, and what with.
type actionEntry struct {
	ID       string `json:"id"`
	By       string `json:"by"`
	Pane     string `json:"pane,omitempty"`
	App      string `json:"app,omitempty"`
	BundleID string `json:"bundleId,omitempty"`
	Command  string `json:"command,omitempty"`
	Why      string `json:"why"`
}

// Where an action is done (FolderAction.By). ActionByScan is not in the list: the scan's own cleaning, which
// data/usage gives from the plans.
const (
	ActionByFinder   = "finder"
	ActionBySettings = "system-settings"
	ActionByApp      = "app"
	ActionByCommand  = "command"
	ActionByScan     = "scan"
)

// ActionClean is the id of the scan's own cleaning; no entry of the list may take it.
const ActionClean = "clean"

// ActionEmptyTrash empties the whole Trash: an action for the Trash itself, not for one thing in it.
const ActionEmptyTrash = "empty-trash"

// kindEntry: a kind of file, told by its extension (lowercase, without the dot).
type kindEntry struct {
	ID         string   `json:"id"`
	Extensions []string `json:"extensions"`
	Why        string   `json:"why"`
}

// KindOther is the kind of a file whose extension is in no entry.
const KindOther = "other"

var extensionShape = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

type folderEntry struct {
	Path      string   `json:"path"`
	Owner     string   `json:"owner,omitempty"`
	Content   string   `json:"content"`
	IfDeleted string   `json:"ifDeleted"`
	Actions   []string `json:"actions,omitempty"`
	Why       string   `json:"why"`
	Samples   []string `json:"samples"`
}

// What a folder holds (FolderWhat.Content) and what deleting it loses (FolderWhat.IfDeleted): the codes data/usage
// gives, described in rules/folders.json and docs/data-resources.md.
const (
	ContentUser     = "user"
	ContentAppData  = "app-data"
	ContentCache    = "cache"
	ContentDownload = "download"
	ContentSystem   = "system"
	ContentTemp     = "temp" // not in the list: the temporary folder is not under the home

	DeletedLost       = "lost"
	DeletedSynced     = "synced"
	DeletedRedownload = "redownload"
	DeletedRebuilds   = "rebuilds"
	DeletedResets     = "resets"
)

func (f *foldersList) check() error {
	if err := f.rulesHead.check(); err != nil {
		return err
	}
	if len(f.Folders) == 0 {
		return errors.New("folders 不能是空的")
	}
	if len(f.Kinds) == 0 {
		return errors.New("kinds 不能是空的")
	}
	ids, exts := map[string]bool{}, map[string]bool{}
	for i, k := range f.Kinds {
		fail := func(format string, args ...any) error { return rulesError("kinds", i, k.ID, format, args...) }
		if !cacheIDShape.MatchString(k.ID) || k.ID == KindOther {
			return fail("id 是小写字母、数字和连字符的代号，不能是 other")
		}
		if ids[k.ID] {
			return fail("id 重了")
		}
		ids[k.ID] = true
		if k.Why == "" || len(k.Extensions) == 0 {
			return fail("extensions、why 都要写")
		}
		for _, x := range k.Extensions {
			if !extensionShape.MatchString(x) {
				return fail("扩展名 %q 要小写、不带点", x)
			}
			if exts[x] {
				return fail("扩展名 %s 已经归了别的种类", x)
			}
			exts[x] = true
		}
	}
	if len(f.Actions) == 0 {
		return errors.New("actions 不能是空的")
	}
	acts := map[string]bool{}
	for i, a := range f.Actions {
		fail := func(format string, args ...any) error { return rulesError("actions", i, a.ID, format, args...) }
		if !cacheIDShape.MatchString(a.ID) || a.ID == ActionClean {
			return fail("id 是小写字母、数字和连字符的代号，不能是 clean")
		}
		if acts[a.ID] {
			return fail("id 重了")
		}
		acts[a.ID] = true
		if a.Why == "" {
			return fail("要写 why")
		}
		// each place has its own fields, and only those
		var ok bool
		switch a.By {
		case ActionByFinder:
			ok = a.Pane == "" && a.App == "" && a.BundleID == "" && a.Command == ""
		case ActionBySettings:
			ok = oneOf(a.Pane, "storage", "icloud") && a.App == "" && a.BundleID == "" && a.Command == ""
		case ActionByApp:
			ok = a.App != "" && a.Pane == "" && a.Command == "" && (a.BundleID == "" || LooksLikeBundleID(a.BundleID))
		case ActionByCommand:
			ok = a.Command != "" && strings.TrimSpace(a.Command) == a.Command && a.Pane == "" && a.App == "" && a.BundleID == ""
		default:
			return fail("by 只能是 finder、system-settings、app、command")
		}
		if !ok {
			return fail("by 是 %s 时该写的字段不对（system-settings 写 pane，app 写 app、可以带 bundleId，command 写 command，别的不写）", a.By)
		}
	}
	paths := map[string]bool{}
	for i, e := range f.Folders {
		fail := func(format string, args ...any) error { return rulesError("folders", i, e.Path, format, args...) }
		used := map[string]bool{}
		for _, id := range e.Actions {
			if !acts[id] || used[id] {
				return fail("actions 里的 %s 不在 actions 清单里，或者写了两遍", id)
			}
			used[id] = true
		}
		if err := checkRelative(e.Path); err != nil {
			return fail("path：%v", err)
		}
		if paths[e.Path] {
			return fail("path 重了")
		}
		paths[e.Path] = true
		if e.Owner != "" && !cacheIDShape.MatchString(e.Owner) {
			return fail("owner 是小写字母、数字和连字符的代号")
		}
		if !oneOf(e.Content, ContentUser, ContentAppData, ContentCache, ContentDownload, ContentSystem) {
			return fail("content 不认得")
		}
		if !oneOf(e.IfDeleted, DeletedLost, DeletedSynced, DeletedRedownload, DeletedRebuilds, DeletedResets) {
			return fail("ifDeleted 不认得")
		}
		if e.Why == "" {
			return fail("要写 why")
		}
		if len(e.Samples) == 0 {
			return fail("要有 samples")
		}
		for _, s := range e.Samples {
			if err := checkRelative(s); err != nil {
				return fail("samples：%v", err)
			}
		}
	}
	// a sample falls on its own entry: not outside it, not on a deeper one
	for i, e := range f.Folders {
		for _, s := range e.Samples {
			if got, ok := f.what(s); !ok || got.Path != e.Path {
				return rulesError("folders", i, e.Path, "样例 %s 没落在这一条上", s)
			}
		}
	}
	return nil
}

// FolderWhat: what a folder of the home is: whose (a code; "" for a place many apps share), what it holds, what
// deleting it loses. Path: the entry of rules/folders.json it comes from, relative to the home.
type FolderWhat struct{ Path, Owner, Content, IfDeleted string }

// what: the deepest entry rel (relative to the home) is, or is inside.
func (f foldersList) what(rel string) (FolderWhat, bool) {
	best := -1
	for i, e := range f.Folders {
		if within(rel, e.Path) && (best < 0 || len(e.Path) > len(f.Folders[best].Path)) {
			best = i
		}
	}
	if best < 0 {
		return FolderWhat{}, false
	}
	e := f.Folders[best]
	return FolderWhat{Path: e.Path, Owner: e.Owner, Content: e.Content, IfDeleted: e.IfDeleted}, true
}

// WhatFolder: what the folder (or file) at rel, relative to the home and slash-separated, is, by the deepest entry of
// rules/folders.json it is or is inside; ok false when no entry covers it (or the list could not be read).
func WhatFolder(rel string) (FolderWhat, bool) { return foldersRules.what(rel) }

func (f foldersList) kinds() map[string]string {
	out := map[string]string{}
	for _, k := range f.Kinds {
		for _, x := range k.Extensions {
			out[x] = k.ID
		}
	}
	return out
}

// FileKind: the kind of the file called name, by its extension alone (rules/folders.json's kinds); KindOther for an
// extension in no entry, and for a name without one.
func FileKind(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return KindOther
	}
	ext := name[i+1:]
	if k, ok := fileKinds[ext]; ok {
		return k
	}
	if k, ok := fileKinds[strings.ToLower(ext)]; ok {
		return k
	}
	return KindOther
}

// FolderAction is a way to make room in a folder, done outside the scan: its id, where it is done (By), and by that
// the settings pane (a code), the app (its name, its bundle id when known) or the command.
type FolderAction struct{ ID, By, Pane, App, BundleID, Command string }

// FolderActions: what can be done about the folder (or file) at rel, relative to the home: the actions of the deepest
// entry of rules/folders.json it is or is inside, in the entry's order; none without an entry.
func FolderActions(rel string) []FolderAction {
	w, ok := foldersRules.what(rel)
	if !ok {
		return nil
	}
	var out []FolderAction
	for _, e := range foldersRules.Folders {
		if e.Path == w.Path {
			out = foldersRules.actionsOf(e, out)
		}
	}
	return out
}

// FolderActionsBelow: the actions of the entries strictly inside rel, each once, in the list's order. For a folder that
// is measured a level above where the list's entries are (~/.ollama holds models/, which is the entry): what can be
// done about what is in it.
func FolderActionsBelow(rel string) []FolderAction {
	var out []FolderAction
	for _, e := range foldersRules.Folders {
		if e.Path != rel && within(e.Path, rel) {
			out = foldersRules.actionsOf(e, out)
		}
	}
	return out
}

// actionsOf adds an entry's actions to out, leaving out the ones already there.
func (f foldersList) actionsOf(e folderEntry, out []FolderAction) []FolderAction {
	for _, id := range e.Actions {
		seen := false
		for _, o := range out {
			seen = seen || o.ID == id
		}
		if seen {
			continue
		}
		for _, a := range f.Actions {
			if a.ID == id {
				out = append(out, FolderAction{a.ID, a.By, a.Pane, a.App, a.BundleID, a.Command})
			}
		}
	}
	return out
}
