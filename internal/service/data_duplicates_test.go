package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// luoke-scan#234: data/category says which copies a set of duplicates has and what the round compared. A fake home with
// three copies of one file found by the duplicates rule itself (the one in Downloads kept last), and a big file not
// opened for years (an item of another rule in the same plan).
type dupCase struct {
	s       *Service
	members []string // as the rule orders them: the copy it keeps first
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
	return dupCase{s: s, members: []string{a, b, c}}
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

func TestDuplicateItemMembers(t *testing.T) {
	dc := newDupCase(t)
	items := itemsOf(t, dc.s, "duplicate")
	if len(items) != 1 {
		t.Fatalf("items %v", items)
	}
	facts := items[0]["facts"].(map[string]any)
	// Every copy, in the rule's order: not in Downloads first, then the earliest made, then the shortest path
	want := []any{dc.members[0], dc.members[1], dc.members[2]}
	if !reflect.DeepEqual(facts["members"], want) {
		t.Errorf("members %v", facts["members"])
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
