package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// luoke-scan#234: which copy of a set of duplicates stays is the user's choice. A fake home with three copies of one
// file found by the duplicates rule itself (the one in Downloads kept last), and a big file not opened for years (an
// item of another rule in the same plan).
type dupCase struct {
	s       *Service
	trash   string
	members []string // as the rule orders them: the copy it keeps first
	big     string
	content []byte
}

var dupPlaces = []string{"Downloads", "Desktop", "Documents", "Movies", "Music", "Pictures"}

func dupRule() *core.DuplicateRule {
	return &core.DuplicateRule{Places: dupPlaces, MinBytes: 1 << 20, MinWaste: 1 << 20, MaxSets: 20, MaxFiles: 200_000}
}

// dupFile writes a file under the home, dated as a round finds it: not changed since.
func dupFile(t *testing.T, home, rel string, b []byte) string {
	t.Helper()
	p := filepath.Join(home, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	backdate(p)
	return p
}

func newDupCase(t *testing.T) dupCase {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	content := bytes.Repeat([]byte("copy"), 1<<18) // 1 MiB
	// Made in the order the rule keeps them, the shorter path first: by either of its tie-breaks (the earliest made, the
	// shortest path) the one in Documents comes first; the one in Downloads goes last whatever its age.
	a := dupFile(t, home, "Documents/report.pdf", content)
	b := dupFile(t, home, "Desktop/older/report.pdf", content)
	c := dupFile(t, home, "Downloads/report.pdf", content)
	big := dupFile(t, home, "Movies/old.mov", []byte("movie"))
	store, err := core.OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := core.NewContext(home)
	ctx.Store = store
	yes := true
	ctx.FullDiskAccess = &yes
	rule := dupRule()
	found, err := rule.Run(&ctx)
	if err != nil || len(found) != 1 || found[0].Path != a || found[0].Evidence["targets"] != b+"\n"+c {
		t.Fatalf("the rule found %+v %v", found, err)
	}
	gb := int64(1_240_000_000)
	old := core.Finding{Rule: "stale.large-file", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm, Path: big,
		Bytes: &gb, Title: "old.mov 三年多没打开过", Evidence: map[string]string{"last_opened": "2022-01-01"}}
	now := core.Time{Time: time.Now()}
	if err := store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: append(found, old)}); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig(ctx)
	cfg.Rules = []core.Rule{rule}
	s := New(store, cfg)
	ownTrash(t, s)
	return dupCase{s: s, trash: s.Config.TrashFolders[0], members: []string{a, b, c}, big: big, content: content}
}

// itemsOf: data/category's items of a category.
func itemsOf(t *testing.T, s *Service, id string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, x := range readData(t, s, "data/category?id="+id)["items"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

// dupKeys: the plan, the duplicates item's key and the big file's, as data/category gives them.
func (dc dupCase) keys(t *testing.T) (plan, key, bigKey string) {
	t.Helper()
	dups, bigs := itemsOf(t, dc.s, "duplicate"), itemsOf(t, dc.s, "large-file")
	if len(dups) != 1 || len(bigs) != 1 || dups[0]["plan"] != bigs[0]["plan"] {
		t.Fatalf("items %v %v", dups, bigs)
	}
	return dups[0]["plan"].(string), dups[0]["key"].(string), bigs[0]["key"].(string)
}

// planItemOf: the saved plan's item with this key.
func planItemOf(t *testing.T, s *Service, plan, key string) PlanItem {
	t.Helper()
	p, ok := LoadPlan(s.plansDir(), plan)
	for _, it := range p.Items {
		if ok && it.Key == key {
			return it
		}
	}
	t.Fatalf("no item %s in plan %s", key, plan)
	return PlanItem{}
}

// applyFromPage: scan_apply as the scan page sends it (plan_id added to args).
func applyFromPage(s *Service, plan string, args O) (ToolOutput, error) {
	a := O{"plan_id": plan}
	for k, v := range args {
		a[k] = v
	}
	meta := O{UserAction: map[string]any{"surfaceId": "scan", "componentId": "b", "at": time.Now().Format(time.RFC3339)}}
	return s.apply(a, meta)
}

// snapshot: what is at each path (not following a link), to tell that nothing moved.
func snapshot(paths ...string) map[string]string {
	out := map[string]string{}
	for _, p := range paths {
		dev, ino, link, ok := identity(p)
		out[p] = fmt.Sprint(dev, ino, link, ok)
	}
	return out
}

func TestDuplicateItemMembers(t *testing.T) {
	dc := newDupCase(t)
	items := itemsOf(t, dc.s, "duplicate")
	if len(items) != 1 {
		t.Fatalf("items %v", items)
	}
	facts := items[0]["facts"].(map[string]any)
	// Every copy, in the rule's order: not in Downloads first, then the earliest made, then the shortest path
	want := []any{dc.members[0], dc.members[1], dc.members[2]}
	if !reflect.DeepEqual(facts["members"], want) || facts["keep"] != dc.members[0] {
		t.Errorf("members %v, keep %v", facts["members"], facts["keep"])
	}
	if _, has := facts["keepDefault"]; has {
		t.Error("keepDefault is given: keep is that path")
	}
	// What was there stays as it was: the kept copy in keep, the copies that go in paths and path
	if facts["keep"] != dc.members[0] || facts["copies"] != float64(2) || items[0]["path"] != dc.members[1] ||
		!reflect.DeepEqual(items[0]["paths"], []any{dc.members[1], dc.members[2]}) {
		t.Errorf("item %v", items[0])
	}
	noSentences(t, "duplicate item", items[0])
	// Recorded in the plan with what each copy is, and the contents they share
	plan, key, _ := dc.keys(t)
	it := planItemOf(t, dc.s, plan, key)
	if it.Rule != "space.duplicates" || len(it.Members) != 3 || len(it.Hash) != 64 {
		t.Fatalf("plan item %+v", it)
	}
	for i, m := range it.Members {
		dev, ino, _, _ := identity(dc.members[i])
		if m.Path != dc.members[i] || m.Device != dev || m.Inode != ino {
			t.Errorf("member %d: %+v", i, m)
		}
	}
	if h, ok := core.DigestOf(dc.members[0], it.Members[0].Device, it.Members[0].Inode, nil); !ok || h != it.Hash {
		t.Errorf("hash %s, the file's %s", it.Hash, h)
	}

	// All of them, also where paths lists only the first few
	most := dataPathsMost
	dataPathsMost = 1
	defer func() { dataPathsMost = most }()
	item := itemsOf(t, dc.s, "duplicate")[0]
	if len(item["paths"].([]any)) != 1 || item["pathsMore"] != float64(1) ||
		!reflect.DeepEqual(item["facts"].(map[string]any)["members"], want) {
		t.Errorf("with paths cut: %v", item)
	}
}

func TestDuplicatesCompared(t *testing.T) {
	dc := newDupCase(t)
	cat := readData(t, dc.s, "data/category?id=duplicate")
	never := []any{}
	for _, c := range core.DuplicatesNever {
		never = append(never, c)
	}
	places := []any{}
	for _, p := range dupPlaces {
		places = append(places, p)
	}
	want := map[string]any{"places": places, "noAccess": []any{}, "partial": []any{}, "maxFiles": float64(200_000),
		"minBytes": float64(1 << 20), "minWaste": float64(1 << 20), "maxGroups": float64(20), "finished": true, "never": never}
	if !reflect.DeepEqual(cat["compared"], want) {
		t.Errorf("compared %v", cat["compared"])
	}
	noSentences(t, "compared", cat["compared"])
	// Once, for the category: not in another one, not on the items
	if _, has := readData(t, dc.s, "data/category?id=large-file")["compared"]; has {
		t.Error("compared in large-file")
	}
	if _, has := itemsOf(t, dc.s, "duplicate")[0]["compared"]; has {
		t.Error("compared on an item")
	}

	// Without Full Disk Access the folders macOS asks about are left out, and said to be; Pictures, with more files than
	// the rule looks at, only partly. The copy in Documents is no member of the pair in Movies.
	root := t.TempDir()
	home := filepath.Join(root, "home")
	content := bytes.Repeat([]byte("film"), 1<<18)
	first := dupFile(t, home, "Movies/a.mov", content)
	second := dupFile(t, home, "Movies/a copy.mov", content)
	dupFile(t, home, "Documents/a.mov", content)
	for i := 0; i < 3; i++ {
		dupFile(t, home, fmt.Sprintf("Pictures/p%d.jpg", i), []byte("x"))
	}
	store, err := core.OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := core.NewContext(home)
	ctx.Store = store
	no := false
	ctx.FullDiskAccess = &no
	rule := dupRule()
	rule.MaxFiles = 2
	_, err = rule.Run(&ctx)
	var se *core.SkippedError
	if !errors.As(err, &se) {
		t.Fatalf("not skipped: %v", err)
	}
	now := core.Time{Time: time.Now()}
	// As the round writes it down (core.RunRound)
	r := core.Report{StartedAt: now, FinishedAt: now, Findings: se.Partial, Skipped: []core.Skipped{{Rule: rule.ID(), Reason: se.Reason}}}
	if err := store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig(ctx)
	cfg.Rules = []core.Rule{rule}
	s := New(store, cfg)
	got := readData(t, s, "data/category?id=duplicate")
	cmp := got["compared"].(map[string]any)
	if !reflect.DeepEqual(cmp["places"], []any{"Movies", "Pictures"}) ||
		!reflect.DeepEqual(cmp["noAccess"], []any{"Downloads", "Desktop", "Documents", "Music"}) ||
		!reflect.DeepEqual(cmp["partial"], []any{"Pictures"}) || cmp["maxFiles"] != float64(2) || cmp["finished"] != true {
		t.Errorf("without access %v", cmp)
	}
	items := got["items"].([]any)
	if len(items) != 1 || !reflect.DeepEqual(items[0].(map[string]any)["facts"].(map[string]any)["members"], []any{first, second}) {
		t.Errorf("items %v", items)
	}

	// A round interrupted before the check: not finished, nothing said to be left out
	r.Findings, r.Skipped = []core.Finding{}, []core.Skipped{{Rule: rule.ID(), Reason: core.Interrupted}}
	if err := store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	cmp = readData(t, s, "data/category?id=duplicate")["compared"].(map[string]any)
	if cmp["finished"] != false || len(cmp["noAccess"].([]any)) != 0 || len(cmp["places"].([]any)) != len(dupPlaces) {
		t.Errorf("interrupted %v", cmp)
	}
}

// The copy the user chose stays; the others go, the one kept by default among them; 「放回」 puts back every one of them.
func TestApplyKeepChosenCopy(t *testing.T) {
	dc := newDupCase(t)
	a, b, c := dc.members[0], dc.members[1], dc.members[2]
	plan, key, _ := dc.keys(t)
	out, err := applyFromPage(dc.s, plan, O{"choices": O{key: A{"trash"}}, "keep": O{key: b}})
	if err != nil {
		t.Fatal(err)
	}
	data := out.Extra["data"].(O)
	if data["moved"].(O)["count"] != 1 || data["partly"] != 0 || data["skipped"] != 0 || data["restore"] != plan {
		t.Fatalf("answer %v", data)
	}
	if got, err := os.ReadFile(b); err != nil || !bytes.Equal(got, dc.content) {
		t.Fatalf("the chosen copy: %v", err)
	}
	for _, p := range []string{a, c} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s still there", p)
		}
	}
	if names, _ := os.ReadDir(dc.trash); len(names) != 2 {
		t.Errorf("%d in the Trash", len(names))
	}
	// Written down under the plan, each where it was
	var was []string
	for _, e := range dc.s.Cleaned() {
		if e.Batch == plan && e.Trashed != nil {
			was = append(was, e.Original)
		}
	}
	canonical := func(p string) string { return core.Canonical(filepath.Dir(p)) + "/" + filepath.Base(p) }
	if !reflect.DeepEqual(was, []string{canonical(a), canonical(c)}) {
		t.Errorf("recorded %v", was)
	}
	// Done with: off the page, though the copy kept is one the plan would have moved
	if items := itemsOf(t, dc.s, "duplicate"); len(items) != 0 {
		t.Errorf("still listed: %v", items)
	}

	clickTool(t, dc.s, "scan_restore", O{"id": plan})
	for _, p := range dc.members {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, dc.content) {
			t.Errorf("%s not back: %v", p, err)
		}
	}
	if names, _ := os.ReadDir(dc.trash); len(names) != 0 {
		t.Errorf("%d left in the Trash", len(names))
	}
	if items := itemsOf(t, dc.s, "duplicate"); len(items) != 1 {
		t.Errorf("put back, not listed again: %v", items)
	}
}

// Without keep, as before: the copy the rule keeps stays. keep naming that same copy does the same.
func TestApplyDuplicatesWithoutKeep(t *testing.T) {
	for _, keep := range []string{"", "default"} {
		dc := newDupCase(t)
		a, b, c := dc.members[0], dc.members[1], dc.members[2]
		plan, key, _ := dc.keys(t)
		args := O{"choices": O{key: A{"trash"}}}
		if keep != "" {
			args["keep"] = O{key: a}
		}
		out, err := applyFromPage(dc.s, plan, args)
		if err != nil {
			t.Fatal(err)
		}
		if data := out.Extra["data"].(O); data["moved"].(O)["count"] != 1 || data["skipped"] != 0 {
			t.Fatalf("%q: answer %v", keep, data)
		}
		if got, err := os.ReadFile(a); err != nil || !bytes.Equal(got, dc.content) {
			t.Fatalf("%q: the copy kept: %v", keep, err)
		}
		for _, p := range []string{b, c} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Errorf("%q: %s still there", keep, p)
			}
		}
		if items := itemsOf(t, dc.s, "duplicate"); len(items) != 0 {
			t.Errorf("%q: still listed: %v", keep, items)
		}
	}
}

// keep that does not fit, or copies that are not what the plan saw: the whole call is refused and nothing of it is
// done, not even the other item chosen in the same call.
func TestApplyKeepRefused(t *testing.T) {
	type args func(dc dupCase, key, bigKey string) O
	trashBoth := func(keep func(dc dupCase, key, bigKey string) any) args {
		return func(dc dupCase, key, bigKey string) O {
			return O{"choices": O{key: A{"trash"}, bigKey: A{"trash"}}, "keep": keep(dc, key, bigKey)}
		}
	}
	keepSecond := func(dc dupCase, key, _ string) any { return O{key: dc.members[1]} }
	cases := []struct {
		name    string
		prepare func(t *testing.T, dc dupCase) // what changed on disk since the plan was made
		args    args
		code    string
		says    string
	}{
		{"another file of the plan", nil, trashBoth(func(dc dupCase, key, _ string) any { return O{key: dc.big} }),
			"invalid", "不是这一组里的一份"},
		{"one of them spelled otherwise", nil, trashBoth(func(dc dupCase, key, _ string) any {
			return O{key: strings.Replace(dc.members[1], "/older/", "/./older/", 1)}
		}), "invalid", "不是这一组里的一份"},
		{"not a duplicates item", nil, trashBoth(func(dc dupCase, _, bigKey string) any { return O{bigKey: dc.big} }),
			"invalid", "只有重复文件"},
		{"not an item", nil, trashBoth(func(dc dupCase, _, _ string) any { return O{"i99": dc.members[1]} }),
			"invalid", "方案里没有"},
		{"not an object", nil, trashBoth(func(dc dupCase, _, _ string) any { return dc.members[1] }), "invalid", "要是对象"},
		{"kept, not trashed", nil, func(dc dupCase, key, bigKey string) O {
			return O{"choices": O{key: A{"keep"}, bigKey: A{"trash"}}, "keep": O{key: dc.members[1]}}
		}, "invalid", "要选 trash"},
		{"cloned", nil, func(dc dupCase, key, bigKey string) O {
			return O{"choices": O{key: A{"clone"}, bigKey: A{"trash"}}, "keep": O{key: dc.members[1]}}
		}, "invalid", "要选 trash"},
		{"not chosen", nil, func(dc dupCase, key, bigKey string) O {
			return O{"choices": O{bigKey: A{"trash"}}, "keep": O{key: dc.members[1]}}
		}, "invalid", "要选 trash"},
		{"the chosen copy gone", func(t *testing.T, dc dupCase) { os.Remove(dc.members[1]) }, trashBoth(keepSecond),
			"stale", "要留的那份已经不在了"},
		{"a copy changed", func(t *testing.T, dc dupCase) {
			// In place (the same inode), the same size, dated as before: only its contents tell
			if err := os.WriteFile(dc.members[2], bytes.Repeat([]byte("diff"), len(dc.content)/4), 0o644); err != nil {
				t.Fatal(err)
			}
			backdate(dc.members[2])
		}, trashBoth(keepSecond), "stale", "查过以后改过"},
		{"a copy now a link", func(t *testing.T, dc dupCase) {
			os.Remove(dc.members[2])
			if err := os.Symlink(dc.members[1], dc.members[2]); err != nil {
				t.Fatal(err)
			}
		}, trashBoth(keepSecond), "stale", "链接"},
		{"the chosen copy now a link", func(t *testing.T, dc dupCase) {
			os.Remove(dc.members[1])
			if err := os.Symlink(dc.members[0], dc.members[1]); err != nil {
				t.Fatal(err)
			}
		}, trashBoth(keepSecond), "stale", "链接"},
		{"a copy replaced", func(t *testing.T, dc dupCase) {
			// Another file with the same contents in its place
			os.Remove(dc.members[2])
			dupFile(t, filepath.Dir(dc.members[2]), filepath.Base(dc.members[2]), dc.content)
		}, trashBoth(keepSecond), "stale", "换成了别的东西"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dc := newDupCase(t)
			plan, key, bigKey := dc.keys(t)
			if tc.prepare != nil {
				tc.prepare(t, dc)
			}
			paths := append(append([]string{}, dc.members...), dc.big)
			before := snapshot(paths...)
			_, err := applyFromPage(dc.s, plan, tc.args(dc, key, bigKey))
			var f *ToolFailure
			if !errors.As(err, &f) || f.Code != tc.code || !strings.Contains(f.Message, tc.says) {
				t.Fatalf("answer %v, want %s 「%s」", err, tc.code, tc.says)
			}
			if after := snapshot(paths...); !reflect.DeepEqual(after, before) {
				t.Errorf("moved: %v → %v", before, after)
			}
			if names, _ := os.ReadDir(dc.trash); len(names) != 0 {
				t.Errorf("%d in the Trash", len(names))
			}
			if n := len(dc.s.Cleaned()); n != 0 {
				t.Errorf("%d in the clean-up record", n)
			}
		})
	}
}

// A plan saved by a version before members gets them when this one reads it, and keep works on it.
func TestOldPlanGetsMembers(t *testing.T) {
	dc := newDupCase(t)
	plan, key, _ := dc.keys(t)
	p, _ := LoadPlan(dc.s.plansDir(), plan)
	for i := range p.Items {
		p.Items[i].Members, p.Items[i].Hash = nil, ""
	}
	p.Tool = "0.0.1"
	p.Save(dc.s.plansDir())
	if _, key2, _ := dc.keys(t); key2 != key {
		t.Fatalf("key %s, was %s", key2, key)
	}
	p, _ = LoadPlan(dc.s.plansDir(), plan)
	if it := planItemOf(t, dc.s, plan, key); len(it.Members) != 3 || len(it.Hash) != 64 || p.Tool != ToolVersion {
		t.Fatalf("plan item %+v", it)
	}
	if _, err := applyFromPage(dc.s, plan, O{"choices": O{key: A{"trash"}}, "keep": O{key: dc.members[2]}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dc.members[2]); err != nil {
		t.Errorf("the chosen copy: %v", err)
	}
	for _, m := range dc.members[:2] {
		if _, err := os.Lstat(m); !os.IsNotExist(err) {
			t.Errorf("%s still there", m)
		}
	}
}

// tools/list says what keep is; it is not required.
func TestApplyKeepListed(t *testing.T) {
	dc := newDupCase(t)
	reply, _ := dc.s.Server.Handle(O{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).(O)
	b, _ := json.Marshal(reply["result"])
	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	json.Unmarshal(b, &list)
	for _, tool := range list.Tools {
		if tool.Name != "scan_apply" {
			continue
		}
		keep := tool.InputSchema.Properties["keep"]
		if keep["type"] != "object" || keep["description"] == nil || !reflect.DeepEqual(tool.InputSchema.Required, []string{"plan_id", "choices"}) {
			t.Errorf("scan_apply %+v", tool.InputSchema)
		}
		return
	}
	t.Error("scan_apply not listed")
}
