package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	assets "github.com/luokelabs/luoke-scan"
)

// Every file in rules/ is one the program reads, and each was read without a problem (decodeRules: the shape, no
// unknown field, the version, every entry's own checks).
func TestRulesFilesAreRead(t *testing.T) {
	names, err := fs.Glob(assets.FS, "rules/*.json")
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(rulesFiles)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("rules/ 里的文件 %v，程序读的是 %v：多出来的没人读", names, want)
	}
	for name, err := range map[string]error{"caches": cachesErr, "temp-folders": tempErr, "space-tools": spaceErr,
		"build-artifacts": artifactsErr, "settings-files": settingsErr} {
		if err != nil {
			t.Errorf("%s 读不出来：%v", name, err)
		}
	}
	if len(KnownCaches) == 0 || len(AutoKnownTemp) == 0 || len(vmTools) == 0 || len(aiTools) == 0 || len(staleArtifactKinds) == 0 ||
		len(chromiumBrowsers) == 0 || len(mcpConfigs) == 0 {
		t.Fatal("有清单是空的")
	}
	// What automatic cleaning may take is in the lists: an id or prefix it names that is not there is a mistake.
	ids := map[string]bool{}
	for _, c := range KnownCaches {
		ids[c.ID] = true
	}
	for id := range autoCaches {
		if !ids[id] {
			t.Errorf("autoCaches 里的 %s 不在 rules/caches.json 里", id)
		}
	}
	for p := range autoTemp {
		if _, ok := AutoKnownTemp[p]; !ok {
			t.Errorf("autoTemp 里的 %s 不在 rules/temp-folders.json 里", p)
		}
	}
	for p := range AutoWaitForTool {
		if !autoTemp[p] {
			t.Errorf("AutoWaitForTool 里的 %s 不是自动清的前缀", p)
		}
	}
}

// decodeRulesFile reads b as the file name is read.
func decodeRulesFile(name string, b []byte) error {
	var err error
	switch name {
	case "rules/caches.json":
		_, err = decodeRules[cachesList](b)
	case "rules/temp-folders.json":
		_, err = decodeRules[tempList](b)
	case "rules/space-tools.json":
		_, err = decodeRules[spaceList](b)
	case "rules/build-artifacts.json":
		_, err = decodeRules[artifactsList](b)
	case "rules/settings-files.json":
		_, err = decodeRules[settingsList](b)
	default:
		err = errors.New("没有这个文件")
	}
	return err
}

// What a file must not have is caught: each case changes one thing in the real file.
func TestRulesFilesRejectWhatIsWrong(t *testing.T) {
	entry := func(m map[string]any, list string, i int) map[string]any { return m[list].([]any)[i].(map[string]any) }
	sample := func(m map[string]any, list string, i int) map[string]any {
		return entry(m, list, i)["samples"].([]any)[0].(map[string]any)
	}
	cases := []struct {
		file, what string
		change     func(m map[string]any)
	}{
		{"rules/caches.json", "不认得的字段", func(m map[string]any) { m["extra"] = 1 }},
		{"rules/caches.json", "条目里不认得的字段", func(m map[string]any) { entry(m, "caches", 0)["auto"] = true }},
		{"rules/caches.json", "不认得的 version", func(m map[string]any) { m["version"] = 2 }},
		{"rules/caches.json", "没有 version", func(m map[string]any) { delete(m, "version") }},
		{"rules/caches.json", "没有 about", func(m map[string]any) { delete(m, "about") }},
		{"rules/caches.json", "path 里有 ..", func(m map[string]any) { entry(m, "caches", 0)["path"] = "Library/../Caches/pip" }},
		{"rules/caches.json", "path 以 / 开头", func(m map[string]any) { entry(m, "caches", 0)["path"] = "/opt/demo/Library/Caches/pip" }},
		{"rules/caches.json", "path 以 ~ 开头", func(m map[string]any) { entry(m, "caches", 0)["path"] = "~/Library/Caches/pip" }},
		{"rules/caches.json", "path 有空的一段", func(m map[string]any) { entry(m, "caches", 0)["path"] = "Library//Caches/pip" }},
		{"rules/caches.json", "path 套着别的缓存", func(m map[string]any) { entry(m, "caches", 0)["path"] = "Library/Caches" }},
		{"rules/caches.json", "id 重了", func(m map[string]any) { entry(m, "caches", 1)["id"] = entry(m, "caches", 0)["id"] }},
		{"rules/caches.json", "id 有大写", func(m map[string]any) { entry(m, "caches", 0)["id"] = "Pip" }},
		{"rules/caches.json", "why 是空的", func(m map[string]any) { entry(m, "caches", 0)["why"] = "" }},
		{"rules/caches.json", "没有 why", func(m map[string]any) { delete(entry(m, "caches", 0), "why") }},
		{"rules/caches.json", "没有 users", func(m map[string]any) { delete(entry(m, "caches", 0), "users") }},
		{"rules/caches.json", "env 的值是绝对路径", func(m map[string]any) {
			entry(m, "caches", 2)["env"] = map[string]any{"GOCACHE": "/tmp/go-build"}
		}},
		{"rules/caches.json", "有 env 没有 command", func(m map[string]any) { entry(m, "caches", 0)["env"] = map[string]any{"X": "a"} }},
		{"rules/caches.json", "没有 samples", func(m map[string]any) { entry(m, "caches", 0)["samples"] = []any{} }},
		{"rules/caches.json", "样例的 expect 不认得", func(m map[string]any) { sample(m, "caches", 0)["expect"] = "maybe" }},
		{"rules/caches.json", "样例的文件是绝对路径", func(m map[string]any) { sample(m, "caches", 0)["files"] = []any{"/etc/hosts"} }},
		{"rules/caches.json", "notCaches 在缓存里", func(m map[string]any) {
			m["notCaches"] = append(m["notCaches"].([]any), map[string]any{"path": "Library/Caches/pip/selfcheck", "why": "x"})
		}},
		{"rules/temp-folders.json", "前缀是系统服务的", func(m map[string]any) { entry(m, "folders", 0)["prefix"] = "com.apple.akd" }},
		{"rules/temp-folders.json", "前缀带 /", func(m map[string]any) { entry(m, "folders", 0)["prefix"] = "a/b" }},
		{"rules/temp-folders.json", "前缀重了", func(m map[string]any) { entry(m, "folders", 1)["prefix"] = entry(m, "folders", 0)["prefix"] }},
		{"rules/temp-folders.json", "样例不在这个前缀的文件夹里", func(m map[string]any) {
			sample(m, "folders", 0)["files"] = []any{"other-AbC123/x"}
		}},
		{"rules/space-tools.json", "models 不认得", func(m map[string]any) { entry(m, "aiModels", 0)["models"] = "flat" }},
		{"rules/space-tools.json", "signs 的 app 不是 .app", func(m map[string]any) {
			entry(m, "vmDisks", 0)["signs"].(map[string]any)["app"] = "Docker"
		}},
		{"rules/space-tools.json", "虚拟磁盘的样例 expect 不认得", func(m map[string]any) { sample(m, "vmDisks", 0)["expect"] = "auto" }},
		{"rules/space-tools.json", "只算总的却写了 models", func(m map[string]any) { sample(m, "aiModels", 3)["models"] = []any{"x"} }},
		{"rules/space-tools.json", "没有 explain", func(m map[string]any) { delete(entry(m, "vmDisks", 0), "explain") }},
		{"rules/build-artifacts.json", "name 不是一个文件夹名", func(m map[string]any) { entry(m, "artifacts", 0)["name"] = "a/b" }},
		{"rules/build-artifacts.json", "marker 只有 *.", func(m map[string]any) { entry(m, "artifacts", 0)["markers"] = []any{"*."} }},
		{"rules/build-artifacts.json", "marker 带 ..", func(m map[string]any) { entry(m, "artifacts", 0)["markers"] = []any{"../package.json"} }},
		{"rules/build-artifacts.json", "同名同 marker 的两条", func(m map[string]any) { entry(m, "artifacts", 1)["name"] = "node_modules" }},
		{"rules/settings-files.json", "bundleID 不对", func(m map[string]any) { entry(m, "browsers", 0)["bundleID"] = "chrome" }},
		{"rules/settings-files.json", "tool 重了", func(m map[string]any) { entry(m, "mcp", 1)["tool"] = entry(m, "mcp", 0)["tool"] }},
		{"rules/settings-files.json", "浏览器的样例 expect 是 MCP 的", func(m map[string]any) { sample(m, "browsers", 0)["expect"] = "mcp.servers" }},
		{"rules/settings-files.json", "样例写到家目录外面", func(m map[string]any) {
			sample(m, "mcp", 0)["write"] = map[string]any{"../outside.json": "{}"}
		}},
	}
	read := func(file string) map[string]any {
		b, err := assets.FS.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, file := range rulesFiles { // as written out again, unchanged, each file still reads: the failures are the changes'
		b, _ := json.Marshal(read(file))
		if err := decodeRulesFile(file, b); err != nil {
			t.Fatalf("%s：%v", file, err)
		}
	}
	for _, c := range cases {
		m := read(c.file)
		c.change(m)
		b, _ := json.Marshal(m)
		if err := decodeRulesFile(c.file, b); err == nil {
			t.Errorf("%s：%s，没挑出来", c.file, c.what)
		}
	}
	b, _ := assets.FS.ReadFile("rules/caches.json")
	if err := decodeRulesFile("rules/caches.json", append(b, "{}"...)); err == nil {
		t.Error("JSON 后面还有东西，没挑出来")
	}
}

// keptInOrder: every entry there before the move is there now, the same, in the same order among them (entries may be
// added anywhere).
func keptInOrder[T any](t *testing.T, list string, before, now []T, key func(T) string) {
	t.Helper()
	at := 0
	for _, b := range before {
		found := false
		for at < len(now) {
			n := now[at]
			at++
			if key(n) == key(b) {
				if !reflect.DeepEqual(n, b) {
					t.Errorf("%s 的 %s 变了：%+v，原来是 %+v", list, key(b), n, b)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s 少了 %s，或者顺序变了", list, key(b))
			return
		}
	}
}

// The lists read from rules/ are what the code said before they moved (rulesdata_premove_test.go), and what was
// cleaned without a click still is.
func TestRulesDataAsBeforeTheMove(t *testing.T) {
	keptInOrder(t, "caches", preMoveCaches, KnownCaches, func(c RebuildableCache) string { return c.ID })
	for id, users := range preMoveCacheUsers {
		if !reflect.DeepEqual(CacheUsers[id], users) {
			t.Errorf("%s 的 users 变了：%v，原来是 %v", id, CacheUsers[id], users)
		}
	}
	for _, id := range preMoveAutoCaches {
		if !autoCaches[id] {
			t.Errorf("%s 原来不用点就清，现在不了", id)
		}
	}
	for p, tool := range preMoveTemp {
		if AutoKnownTemp[p] != tool {
			t.Errorf("临时文件夹 %s 的工具变了：%q，原来是 %q", p, AutoKnownTemp[p], tool)
		}
	}
	for _, p := range preMoveAutoTemp {
		if !autoTemp[p] {
			t.Errorf("临时文件夹 %s 原来不用点就清，现在不了", p)
		}
	}
	if !reflect.DeepEqual(AutoWaitForTool, preMoveWaitForTool) {
		t.Errorf("AutoWaitForTool 变了：%v", AutoWaitForTool)
	}
	keptInOrder(t, "vmDisks", preMoveVMTools, vmTools, func(v vmTool) string { return v.tool })
	for tool, m := range preMoveVMMarkers {
		if vmMarkers[tool] != m {
			t.Errorf("%s 的 signs 变了：%+v，原来是 %+v", tool, vmMarkers[tool], m)
		}
	}
	keptInOrder(t, "aiModels", preMoveAITools, aiTools, func(a aiTool) string { return a.path })
	keptInOrder(t, "artifacts", preMoveArtifactKinds, staleArtifactKinds, func(k staleArtifactKind) string {
		return k.name + " " + strings.Join(k.markers, ",")
	})
	keptInOrder(t, "browsers", preMoveBrowsers, chromiumBrowsers, func(b chromiumBrowser) string { return b.name })
	keptInOrder(t, "mcp", preMoveMCPConfigs, mcpConfigs, func(m mcpConfig) string { return m.tool })
}

// A list that could not be read: the rules using it say so and look at nothing.
func TestRulesMissingSkips(t *testing.T) {
	for _, c := range []struct {
		err  *error
		file string
		rule Rule
	}{
		{&cachesErr, "caches.json", &CacheRule{}},
		{&spaceErr, "space-tools.json", &SystemSpaceRule{Snapshots: func() ([]time.Time, bool) { return nil, false }}},
		{&artifactsErr, "build-artifacts.json", &StaleProjectRule{}},
		{&settingsErr, "settings-files.json", &BrowserRule{}},
		{&settingsErr, "settings-files.json", &McpRule{}},
	} {
		was := *c.err
		*c.err = errors.New("坏了")
		found, err := c.rule.Run(&Context{Home: t.TempDir(), Now: testNow})
		*c.err = was
		var se *SkippedError
		if !errors.As(err, &se) || !strings.Contains(se.Reason, c.file) || len(found) > 0 || len(se.Partial) > 0 {
			t.Errorf("%s：%v %v", c.rule.ID(), found, err)
		}
	}
}

// plant makes files (relative to root) with a little in each, everything in it dated ten days ago.
func plant(t *testing.T, root string, files []string) {
	t.Helper()
	at := testNow.Add(-10 * testDay)
	for _, f := range files {
		writeBlob(t, filepath.Join(root, f), 64, at)
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && p != root {
			os.Chtimes(p, at, at)
		}
		return nil
	})
}

// covered: some finding's path is one of files (under root) or a folder they are in.
func covered(found []Finding, root string, files []string) bool {
	for _, f := range found {
		for _, file := range files {
			if f.Path != "" && within(filepath.Join(root, file), f.Path) {
				return true
			}
		}
	}
	return false
}

// cacheOutcome: what a home gets for the cache rule: auto (reported and taken without a click), ask (reported, left for
// a click) or none. found are all the findings.
func cacheOutcome(t *testing.T, home, rule string, running map[string]bool) (string, []Finding) {
	t.Helper()
	r := &CacheRule{Caches: KnownCaches, MinBytes: 1, Installed: func(string, string) bool { return false }}
	found, err := r.Run(&Context{Home: home, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	p := NewAutoPick(home, "", testNow, running)
	p.Installed = func(string, string) bool { return false }
	taken := map[string]bool{}
	for _, it := range p.Pick(found) {
		taken[it.Rule] = true
	}
	for _, f := range found {
		if f.Rule == rule {
			if taken[rule] {
				return "auto", found
			}
			return "ask", found
		}
	}
	return "none", found
}

// Each cache's samples come out as they say; one that goes without a click waits while any of its users runs; nothing
// is reported in the places that are not caches.
func TestRulesSamplesCaches(t *testing.T) {
	for _, c := range cachesRules.Caches {
		rule := "cache.rebuildable." + c.ID
		for i, s := range c.Samples {
			t.Run(fmt.Sprintf("%s/%d", c.ID, i+1), func(t *testing.T) {
				home := t.TempDir()
				plant(t, home, s.Files)
				got, found := cacheOutcome(t, home, rule, spaceSet(s.Running...))
				if got != s.Expect {
					t.Fatalf("结论是 %s，样例写的是 %s", got, s.Expect)
				}
				if s.Expect == "none" && covered(found, home, s.Files) {
					t.Fatalf("别的缓存把它报了：%v", found)
				}
				if s.Expect != "auto" {
					return
				}
				for _, u := range c.Users {
					if got, _ := cacheOutcome(t, home, rule, map[string]bool{u: true}); got != "ask" {
						t.Errorf("%s 在跑时：%s", u, got)
					}
				}
			})
		}
	}
	for _, n := range cachesRules.NotCaches {
		home := t.TempDir()
		files := []string{n.Path + "/sample"}
		plant(t, home, files)
		if _, found := cacheOutcome(t, home, "", map[string]bool{}); covered(found, home, files) {
			t.Errorf("%s 不是缓存，却报了：%v", n.Path, found)
		}
	}
}

// noJournal: the journal is not known, so everything is looked at.
func noJournal() JournalSource {
	return JournalSource{Replay: func([]string, uint64, func() bool) Changes { return Everything() },
		CurrentEventID: func() uint64 { return 1 }, JournalID: func(string) string { return "" }}
}

// Each temp folder prefix's samples come out as they say.
func TestRulesSamplesTempFolders(t *testing.T) {
	for _, e := range tempRules.Folders {
		for i, s := range e.Samples {
			t.Run(fmt.Sprintf("%s/%d", e.Prefix, i+1), func(t *testing.T) {
				root := t.TempDir()
				tmp := filepath.Join(root, "tmp")
				plant(t, tmp, s.Files)
				r := &TempLeakRule{MinCount: 1, MinBytes: 1, Quiet: TempLeakQuiet, Journal: noJournal()}
				found, err := r.Run(&Context{Home: root, Tmp: tmp, Now: testNow})
				if err != nil {
					t.Fatal(err)
				}
				lines := slices.Clone(s.CommandLines)
				p := NewAutoPick(root, tmp, testNow, map[string]bool{})
				p.CommandLines = &lines
				taken := map[string]bool{}
				for _, it := range p.Pick(found) {
					taken[it.FindingID] = true
				}
				got := "none"
				for _, f := range found {
					if f.Evidence["prefix"] == e.Prefix {
						got = "ask"
						if taken[f.ID()] {
							got = "auto"
						}
					}
				}
				if got != s.Expect {
					t.Fatalf("结论是 %s，样例写的是 %s（%v）", got, s.Expect, found)
				}
			})
		}
	}
}

// spaceFindings: what the system space rule finds in a home, counting from any size (Time Machine, restore images and
// Xcode's folders left out).
func spaceFindings(t *testing.T, home string) []Finding {
	t.Helper()
	r := &SystemSpaceRule{SnapshotAge: 2 * testDay, MinVMBytes: 1, MinModelBytes: 1, MinModelsTotal: 1, MaxModels: 100,
		MinDeviceSupportBytes: 1 << 50, MinArchivesBytes: 1 << 50, MinSimulatorBytes: 1 << 50, MinIpswBytes: 1 << 50, IpswQuiet: testDay,
		DeviceSupportQuiet: 30 * testDay, Snapshots: func() ([]time.Time, bool) { return nil, false }}
	found, err := r.Run(&Context{Home: home, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// Each VM tool's and AI tool's samples come out as they say.
func TestRulesSamplesSpaceTools(t *testing.T) {
	for _, v := range spaceRules.VMDisks {
		for i, s := range v.Samples {
			t.Run(fmt.Sprintf("%s/%d", v.Tool, i+1), func(t *testing.T) {
				home := t.TempDir()
				plant(t, home, s.Files)
				got := "none"
				for _, f := range spaceFindings(t, home) {
					if f.Rule == "space.vm-disk" && f.Evidence["tool"] == v.Tool {
						got = "found"
						if f.Evidence["why"] != v.Explain || f.Evidence["how"] != v.How {
							t.Errorf("说的不是这一条写的：%v", f.Evidence)
						}
					}
				}
				if got != s.Expect {
					t.Fatalf("结论是 %s，样例写的是 %s", got, s.Expect)
				}
			})
		}
	}
	for _, a := range spaceRules.AIModels {
		for i, s := range a.Samples {
			t.Run(fmt.Sprintf("%s/%s/%d", a.Tool, a.Path, i+1), func(t *testing.T) {
				home := t.TempDir()
				plant(t, home, s.Files)
				found := spaceFindings(t, home)
				got := "none"
				var models []string
				for _, f := range found {
					if f.Rule == "space.ai-models" && strings.Contains(f.Evidence["tools"], a.Tool+" ") {
						got = "found"
					}
					if f.Rule == "space.ai-model" && f.Evidence["tool"] == a.Tool {
						models = append(models, f.Evidence["model"])
					}
				}
				slices.Sort(models)
				want := slices.Clone(s.Models)
				slices.Sort(want)
				if got != s.Expect || !slices.Equal(models, want) {
					t.Fatalf("结论是 %s、模型 %v，样例写的是 %s、%v（%v）", got, models, s.Expect, want, found)
				}
			})
		}
	}
}

// Each build artifact's samples come out as they say: the folder is taken for this kind (its way back is this one's),
// or not at all.
func TestRulesSamplesBuildArtifacts(t *testing.T) {
	for i, a := range artifactRules.Artifacts {
		for j, s := range a.Samples {
			t.Run(fmt.Sprintf("%d-%s/%d", i+1, a.Name, j+1), func(t *testing.T) {
				// Spelled as the folder listing spells what is in it (/private/var, not /var).
				root, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				project := filepath.Join(root, "demo")
				plant(t, project, s.Files)
				got := "none"
				for _, x := range StaleArtifacts(project, 4, 3000) {
					if x.Path == a.Name {
						got = "found"
						if x.Again != a.Again {
							t.Errorf("认成了别的一条（%s）", x.Again)
						}
					}
				}
				if got != s.Expect {
					t.Fatalf("结论是 %s，样例写的是 %s", got, s.Expect)
				}
			})
		}
	}
}

// writeSampleFiles makes a writeSample's files under home.
func writeSampleFiles(t *testing.T, home string, files map[string]json.RawMessage) {
	t.Helper()
	for p, raw := range files {
		content := []byte(raw)
		var s string
		if json.Unmarshal(raw, &s) == nil {
			content = []byte(s)
		}
		u := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(u), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(u, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// settingsOutcome: the rule of the finding about name (in evidence key), or none.
func settingsOutcome(t *testing.T, r Rule, home, key, name, expect string) string {
	t.Helper()
	found, err := r.Run(&Context{Home: home, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	got := "none"
	for _, f := range found {
		if f.Evidence[key] == name && (got == "none" || f.Rule == expect) {
			got = f.Rule
		}
	}
	return got
}

// Each browser's and AI tool's samples come out as they say.
func TestRulesSamplesSettingsFiles(t *testing.T) {
	for _, b := range settingsRules.Browsers {
		for i, s := range b.Samples {
			t.Run(fmt.Sprintf("%s/%d", b.Name, i+1), func(t *testing.T) {
				home := t.TempDir()
				writeSampleFiles(t, home, s.Write)
				if got := settingsOutcome(t, &BrowserRule{}, home, "browser", b.Name, s.Expect); got != s.Expect {
					t.Fatalf("结论是 %s，样例写的是 %s", got, s.Expect)
				}
			})
		}
	}
	for _, m := range settingsRules.MCP {
		for i, s := range m.Samples {
			t.Run(fmt.Sprintf("%s/%d", m.Tool, i+1), func(t *testing.T) {
				home := t.TempDir()
				writeSampleFiles(t, home, s.Write)
				if got := settingsOutcome(t, &McpRule{}, home, "tool", m.Tool, s.Expect); got != s.Expect {
					t.Fatalf("结论是 %s，样例写的是 %s", got, s.Expect)
				}
			})
		}
	}
}
