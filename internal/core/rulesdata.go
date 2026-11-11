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
// space, the folders a project's tools make again, and the settings files that say what browsers and AI tools run.
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
	"rules/settings-files.json"}

// The files as read (with why and samples, for the tests), and what came of reading each.
var (
	cachesRules   cachesList
	tempRules     tempList
	spaceRules    spaceList
	artifactRules artifactsList
	settingsRules settingsList

	cachesErr, tempErr, spaceErr, artifactsErr, settingsErr error
)

// The files are read here rather than in the variables' initializers: the checks use package-level values (regular
// expressions) that Go would not set up first, as it does not follow a call through a type parameter's method.
func init() {
	cachesRules, cachesErr = readRules[cachesList]("rules/caches.json")
	tempRules, tempErr = readRules[tempList]("rules/temp-folders.json")
	spaceRules, spaceErr = readRules[spaceList]("rules/space-tools.json")
	artifactRules, artifactsErr = readRules[artifactsList]("rules/build-artifacts.json")
	settingsRules, settingsErr = readRules[settingsList]("rules/settings-files.json")

	KnownCaches, CacheUsers = cachesRules.known(), cachesRules.users()
	AutoKnownTemp = tempRules.tools()
	vmTools, vmMarkers, aiTools = spaceRules.vmTools(), spaceRules.vmMarkers(), spaceRules.aiTools()
	staleArtifactKinds = artifactRules.kinds()
	chromiumBrowsers, mcpConfigs = settingsRules.browsers(), settingsRules.mcpConfigs()
}

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
