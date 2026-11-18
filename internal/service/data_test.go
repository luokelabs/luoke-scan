package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The data resources (top-level ADR 0028): what the agent draws the scan page from, as raw facts. Read and acted on as
// the agent does: resources/read, then tools/call with what the data gives (a plan, an item's key, a batch).

// readData: a resource read through the server, its JSON text decoded.
func readData(t *testing.T, s *Service, uri string) map[string]any {
	t.Helper()
	reply, _ := s.Server.Handle(O{"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": O{"uri": uri}}).(O)
	res, _ := reply["result"].(O)
	contents, _ := res["contents"].(A)
	if len(contents) != 1 {
		t.Fatalf("read %s: %v", uri, reply)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(contents[0].(O)["text"].(string)), &out); err != nil {
		t.Fatalf("read %s: %v", uri, err)
	}
	return out
}

// clickTool: a tool called from the agent's page, with where the user clicked.
func clickTool(t *testing.T, s *Service, name string, args O) O {
	t.Helper()
	meta := O{UserAction: map[string]any{"surfaceId": "scan", "componentId": "b", "at": time.Now().Format(time.RFC3339)}}
	reply, _ := s.Server.Handle(O{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": O{"name": name, "arguments": args, "_meta": meta}}).(O)
	res, _ := reply["result"].(O)
	if res == nil || res["isError"] != false {
		t.Fatalf("%s %v: %v", name, args, reply)
	}
	return res
}

func byID(t *testing.T, list any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, x := range list.([]any) {
		m := x.(map[string]any)
		out[m["id"].(string)] = m
	}
	return out
}

func TestReadWithArguments(t *testing.T) {
	srv := NewServer("t", "0")
	var got []map[string]string
	srv.ResourceArgs("x", "x", func(args map[string]string) any { got = append(got, args); return O{} })
	srv.Resource("y", "y", func() any { return O{} })
	read := func(uri string) O {
		r, _ := srv.Handle(O{"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": O{"uri": uri}}).(O)
		return r
	}
	for _, uri := range []string{"x?id=a%20b&k=1&id=c", "x", "x?%zz", "x?"} {
		if r := read(uri); r["error"] != nil {
			t.Fatalf("%s: %v", uri, r)
		}
	}
	want := []map[string]string{{"id": "a b", "k": "1"}, {}, {}, {}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("args %v", got)
	}
	// A resource read without arguments does not take them, nor does an unknown one
	for _, uri := range []string{"y?id=1", "z?id=1"} {
		if e, _ := read(uri)["error"].(O); e == nil || e["code"] != resourceMissing {
			t.Errorf("%s: %v", uri, read(uri))
		}
	}
	list, _ := srv.Handle(O{"jsonrpc": "2.0", "id": 1, "method": "resources/list"}).(O)
	if n := len(list["result"].(O)["resources"].(A)); n != 2 {
		t.Errorf("listed %d", n)
	}
}

func TestDataResourcesListed(t *testing.T) {
	s := newPageCase(t).s
	list, _ := s.Server.Handle(O{"jsonrpc": "2.0", "id": 1, "method": "resources/list"}).(O)
	var uris []string
	for _, r := range list["result"].(O)["resources"].(A) {
		uris = append(uris, r.(O)["uri"].(string))
	}
	for _, u := range []string{"data/overview", "data/category", "data/history", "data/settings", "data/usage"} {
		if !contains(uris, u) {
			t.Errorf("%s not listed: %v", u, uris)
		}
	}
}

// The overview: what can go, by category, with the facts a summary is written from; the big files apart; nothing
// cleaned without a click yet; nothing that wants a look (the plugin is in the plan).
func TestDataOverviewByCategory(t *testing.T) {
	pc := newPageCaseWith(t, false)
	s := pc.s
	ov := readData(t, s, "data/overview")
	if ov["schema"] != float64(1) || ov["scanned"].(map[string]any)["started"] != core.ISOTime(pc.report.StartedAt.Time) {
		t.Errorf("schema, scanned: %v %v", ov["schema"], ov["scanned"])
	}
	var order []string
	for _, c := range ov["reclaimable"].([]any) {
		order = append(order, c.(map[string]any)["id"].(string))
	}
	if !reflect.DeepEqual(order, []string{"cache", "installer", "large-file", "ai-plugin"}) {
		t.Fatalf("categories %v", order)
	}
	cats := byID(t, ov["reclaimable"])
	cache, installer, large := cats["cache"], cats["installer"], cats["large-file"]
	if cache["count"] != float64(1) || cache["bytes"] != float64(62_900_000) || cache["auto"] != "cache" || cache["suggested"] != float64(1) {
		t.Errorf("cache %v", cache)
	}
	cf := cache["facts"].(map[string]any)
	if !reflect.DeepEqual(cf["tools"], []any{"pip"}) || cf["rebuilds"] != float64(1) || cf["userFiles"] != "none" {
		t.Errorf("cache facts %v", cf)
	}
	inf := installer["facts"].(map[string]any)
	if installer["count"] != float64(1) || installer["auto"] != "installer" || !reflect.DeepEqual(inf["apps"], []any{"ModelBox"}) ||
		inf["appsInstalled"] != float64(1) || inf["appsMissing"] != float64(0) || !reflect.DeepEqual(inf["groups"], map[string]any{"installer": float64(1)}) {
		t.Errorf("installer %v", installer)
	}
	if large["auto"] != nil || large["facts"].(map[string]any)["userFiles"] != "yes" {
		t.Errorf("large-file %v", large)
	}
	if !reflect.DeepEqual(ov["largeFiles"], map[string]any{"count": float64(1), "bytes": float64(1_240_000_000)}) {
		t.Errorf("largeFiles %v", ov["largeFiles"])
	}
	if a := ov["attention"].(map[string]any); a["count"] != float64(0) || len(ov["autoCleaned"].([]any)) != 0 || ov["autoclean"] != false {
		t.Errorf("attention %v autoCleaned %v autoclean %v", a, ov["autoCleaned"], ov["autoclean"])
	}
}

// What wants a look and is in no plan (a plugin that came with Claude Code's plugins): listed by its rule.
func TestDataOverviewAttention(t *testing.T) {
	pc := newPageCaseWith(t, true)
	a := readData(t, pc.s, "data/overview")["attention"].(map[string]any)
	items := a["items"].([]any)
	if a["count"] == float64(0) || len(items) == 0 {
		t.Fatalf("attention %v", a)
	}
	for _, x := range items {
		m := x.(map[string]any)
		if !strings.HasPrefix(m["rule"].(string), "skill.") || m["category"] != nil || m["urgent"] != false || m["finding"] == "" {
			t.Errorf("item %v", m)
		}
	}
}

// One category, each file: its key in the plan, where, how big, why; scan_apply with just that key moves just it,
// data/history shows the batch, scan_restore with the batch puts it back.
func TestDataCategoryToTheTrashAndBack(t *testing.T) {
	pc := newPageCaseWith(t, false)
	s := pc.s
	ownTrash(t, s)
	backdate(pc.installer.Path, pc.big.Path)
	d := readData(t, s, "data/category?id=installer")
	items := d["items"].([]any)
	if d["known"] != true || d["count"] != float64(1) || len(items) != 1 {
		t.Fatalf("installer %v", d)
	}
	it := items[0].(map[string]any)
	wantFacts := map[string]any{"app": "ModelBox", "days": float64(24), "appVersion": "0.7.0", "installerVersion": "0.7.0",
		"sameApp": true, "fromInternet": true, "signed": true}
	if it["path"] != pc.installer.Path || it["reveal"] != pc.installer.Path || !reflect.DeepEqual(it["paths"], []any{pc.installer.Path}) ||
		it["bytes"] != float64(830_900_000) ||
		it["group"] != "installer" || it["reason"] != "installed" || !reflect.DeepEqual(it["facts"], wantFacts) ||
		it["restorable"] != true || it["appInstalled"] != true || it["password"] != false || it["rule"] != "leftover.installer" {
		t.Errorf("item %v", it)
	}
	clickTool(t, s, "scan_apply", O{"plan_id": it["plan"], "choices": map[string]any{it["key"].(string): []any{ChoiceTrash}}})
	if core.Exists(pc.installer.Path) || !core.Exists(pc.big.Path) {
		t.Fatalf("moved: installer there %v, big file there %v", core.Exists(pc.installer.Path), core.Exists(pc.big.Path))
	}
	if d := readData(t, s, "data/category?id=installer"); d["count"] != float64(0) {
		t.Errorf("still offered %v", d)
	}
	if _, has := byID(t, readData(t, s, "data/overview")["reclaimable"])["installer"]; has {
		t.Error("overview still lists the installer")
	}
	rows := readData(t, s, "data/history")["batches"].([]any)
	if len(rows) != 1 {
		t.Fatalf("history %v", rows)
	}
	b := rows[0].(map[string]any)
	if b["batch"] != it["plan"] || b["auto"] != false || b["count"] != float64(1) || b["restorable"] != float64(1) ||
		b["restored"] != float64(0) || b["deleted"] != float64(0) || b["bytes"] != float64(830_900_000) ||
		!reflect.DeepEqual(b["categories"], []any{map[string]any{"id": "installer", "count": float64(1), "bytes": float64(830_900_000)}}) {
		t.Errorf("batch %v", b)
	}
	clickTool(t, s, "scan_restore", O{"id": b["batch"]})
	if !core.Exists(pc.installer.Path) {
		t.Fatal("not put back")
	}
	b = readData(t, s, "data/history")["batches"].([]any)[0].(map[string]any)
	if b["restored"] != float64(1) || b["restorable"] != float64(0) {
		t.Errorf("after putting back %v", b)
	}
}

func TestDataUnknownCategory(t *testing.T) {
	s := newPageCase(t).s
	for _, uri := range []string{"data/category?id=nope", "data/category", "data/category?id="} {
		d := readData(t, s, uri)
		if d["known"] != false || d["count"] != float64(0) || len(d["items"].([]any)) != 0 {
			t.Errorf("%s: %v", uri, d)
		}
	}
}

// An automatic clean in the overview (by kind, what can still be put back) and in the history; the settings before and
// after it is put back (its kind turns off), and what was put away with 「以后别提」.
func TestDataAutoCleanedAndSettings(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	ownTrash(t, s)
	set := readData(t, s, "data/settings")
	if !reflect.DeepEqual(set["autoclean"], map[string]any{"on": false, "offSince": nil, "neverOn": true}) {
		t.Errorf("fresh %v", set["autoclean"])
	}
	home := s.Config.Context.Home
	dmg := filepath.Join(home, "Downloads/Foo-1.0.dmg")
	os.WriteFile(dmg, []byte("x"), 0o644)
	at := s.now()
	batch := "auto-" + core.ISOTime(at)
	if _, _, err := s.trashAndRecord(dmg, batch, "leftover.installer", "安装包 Foo-1.0.dmg", core.Size(5<<20), core.AutoInstaller, nil); err != nil {
		t.Fatal(err)
	}
	s.recordRemoved(filepath.Join(home, "Library/Caches/pip"), batch, "cache.rebuildable.pip", "pip 的缓存", core.Size(60<<20), core.AutoCache)
	round := pc.report.StartedAt
	s.mutate(func(st *State) {
		st.AutocleanOff = nil
		st.AutoDone = append(st.AutoDone, AutoDone{ID: core.ISOTime(at), At: core.Time{Time: at}, Tools: []string{"pip"}, Bytes: 60 << 20,
			ToolBytes: map[string]int64{"pip": 60 << 20}, Batch: batch, Round: &round,
			Moved: []Moved{{Kind: "installer", Items: 1, Bytes: 5 << 20, Names: []string{"安装包 Foo-1.0.dmg"}}}})
	})
	auto := readData(t, s, "data/overview")["autoCleaned"].([]any)
	if len(auto) != 1 {
		t.Fatalf("autoCleaned %v", auto)
	}
	want := map[string]any{"batch": batch, "at": core.ISOTime(at), "bytes": float64(65 << 20), "restorable": float64(1),
		"failed": []any{}, "unrecorded": float64(0), "kinds": []any{
			map[string]any{"kind": "cache", "count": float64(1), "bytes": float64(60 << 20), "tools": []any{"pip"}, "partial": []any{},
				"restorable": float64(0), "restored": float64(0)},
			map[string]any{"kind": "installer", "count": float64(1), "bytes": float64(5 << 20), "restorable": float64(1), "restored": float64(0)}}}
	if !reflect.DeepEqual(auto[0], want) {
		t.Errorf("auto clean\n%v\nwant\n%v", auto[0], want)
	}
	h := readData(t, s, "data/history")["batches"].([]any)[0].(map[string]any)
	if h["auto"] != true || h["count"] != float64(2) || h["deleted"] != float64(1) || h["restorable"] != float64(1) ||
		!reflect.DeepEqual(h["categories"], []any{map[string]any{"id": "cache", "count": float64(1), "bytes": float64(60 << 20)},
			map[string]any{"id": "installer", "count": float64(1), "bytes": float64(5 << 20)}}) {
		t.Errorf("history %v", h)
	}
	if set := readData(t, s, "data/settings"); !reflect.DeepEqual(set["autoclean"], map[string]any{"on": true, "offSince": nil, "neverOn": false}) {
		t.Errorf("on %v", set["autoclean"])
	}
	clickTool(t, s, "scan_restore", O{"id": batch})
	k := readData(t, s, "data/overview")["autoCleaned"].([]any)[0].(map[string]any)["kinds"].([]any)[1].(map[string]any)
	if k["restored"] != float64(1) || k["restorable"] != float64(0) {
		t.Errorf("after putting back %v", k)
	}
	set = readData(t, s, "data/settings")
	for _, x := range set["kinds"].([]any) {
		m := x.(map[string]any)
		if off := m["kind"] == "installer"; m["off"] != off || (m["offSince"] != nil) != off {
			t.Errorf("kind %v", m)
		}
	}
	clickTool(t, s, "scan_ignore", O{"finding_id": s.fid(pc.big)})
	ig := readData(t, s, "data/settings")["ignored"].([]any)
	if len(ig) != 1 {
		t.Fatalf("ignored %v", ig)
	}
	if m := ig[0].(map[string]any); m["finding"] != s.fid(pc.big) || m["rule"] != "stale.large-file" || m["category"] != "large-file" || m["path"] != pc.big.Path {
		t.Errorf("ignored %v", m)
	}
	if _, has := byID(t, readData(t, s, "data/overview")["reclaimable"])["large-file"]; has {
		t.Error("ignored file still offered")
	}
}

// Raw facts, no sentences: no text in any of them is in Chinese but where it is a path (the big file's name is).
func TestDataHasNoSentences(t *testing.T) {
	for _, plugin := range []bool{false, true} {
		s := newPageCaseWith(t, plugin).s
		uris := []string{"data/overview", "data/history", "data/settings"}
		for _, c := range append(append([]string{}, dataCategories...), "other") {
			uris = append(uris, "data/category?id="+c)
		}
		for _, uri := range uris {
			var walk func(key string, v any)
			walk = func(key string, v any) {
				switch x := v.(type) {
				case map[string]any:
					for k, e := range x {
						walk(k, e)
					}
				case []any:
					for _, e := range x {
						walk(key, e)
					}
				case string:
					if key == "path" || key == "paths" || key == "reveal" || key == "keep" || key == "template" {
						return
					}
					for _, r := range x {
						if r >= 0x2E80 {
							t.Errorf("%s: %s = %q", uri, key, x)
							return
						}
					}
				}
			}
			walk("", readData(t, s, uri))
		}
	}
}

func TestDataCategoryOfEachRule(t *testing.T) {
	for rule, want := range map[string]string{"cache.rebuildable.pip": "cache", "cache.app": "cache", "space.ai-model": "cache",
		"leftover.installer": "installer", "space.duplicates": "duplicate", "leak.temp-prefix": "temp", "leftover.app-data": "leftover",
		"leftover.intel-homebrew": "leftover", "stale.project": "project", "stale.artifacts": "project", "stale.large-file": "large-file",
		"persistence.new": "startup", "skill.exfil": "ai-plugin", "model.chat-template": "ai-plugin", core.InstallScriptsRuleID: "install-scripts",
		"malware.clamav": "malware", "malware.yara.x": "malware", "space.growth": "other"} {
		if got := dataCategory(rule); got != want {
			t.Errorf("%s: %s, want %s", rule, got, want)
		}
	}
}

// The manifest lists the data resources (capabilities.data): the agent core draws the scan page itself only when it
// sees them. Each one listed is served as data/<name>, and each data/… served is listed.
func TestManifestListsDataResources(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/luoke-accessory.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Capabilities struct {
			Data []string `json:"data"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	s := newPageCase(t).s
	list, _ := s.Server.Handle(O{"jsonrpc": "2.0", "id": 1, "method": "resources/list"}).(O)
	var served []string
	for _, r := range list["result"].(O)["resources"].(A) {
		if u := r.(O)["uri"].(string); strings.HasPrefix(u, "data/") {
			served = append(served, strings.TrimPrefix(u, "data/"))
		}
	}
	listed := append([]string{}, m.Capabilities.Data...)
	sort.Strings(listed)
	sort.Strings(served)
	if len(listed) == 0 || !reflect.DeepEqual(listed, served) {
		t.Errorf("manifest lists %v, served %v", listed, served)
	}
}

// A category lists at most dataItemsMost items and an item at most dataPathsMost places; what is left out is counted.
func TestDataCategoryLimits(t *testing.T) {
	s := newPageCase(t).s
	items, places := dataItemsMost, dataPathsMost
	defer func() { dataItemsMost, dataPathsMost = items, places }()
	dataPathsMost = 0
	it := readData(t, s, "data/category?id=installer")["items"].([]any)[0].(map[string]any)
	if len(it["paths"].([]any)) != 0 || it["pathsMore"] != float64(1) || it["path"] == nil {
		t.Errorf("places %v", it)
	}
	dataItemsMost = 0
	d := readData(t, s, "data/category?id=installer")
	if len(d["items"].([]any)) != 0 || d["more"] != float64(1) || d["count"] != float64(1) {
		t.Errorf("items %v", d)
	}
}

// A path the rule writes from the home (~/…) is absolute in the data, as every other path.
func TestDataFactsPathsAbsolute(t *testing.T) {
	s := newPageCase(t).s
	home := s.Config.Context.Home
	f := core.Finding{Rule: "persistence.new", Category: core.CatPersistence, Severity: core.Medium, Verdict: core.Confirm,
		Path: filepath.Join(home, "Library/LaunchAgents/io.example.job.plist"),
		Evidence: map[string]string{"label": "io.example.job", "program": "~/bin/job", "scope": "user-agent"}}
	if got := s.itemFacts(f, 1).facts["program"]; got != filepath.Join(home, "bin/job") {
		t.Errorf("program %v", got)
	}
}
