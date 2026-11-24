package service

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// data/usage: the folders that take the most room, from what the space rule measured.

const usageMB = int64(1 << 20)

// usageCase: a service whose store holds the given sizes (path relative to the home, or absolute → day → bytes).
type usageCase struct {
	s    *Service
	home string
	day  string // today
	week string // eight days ago
}

func newUsageCase(t *testing.T) *usageCase {
	t.Helper()
	pc := newPageCaseWith(t, false)
	now := time.Now()
	return &usageCase{s: pc.s, home: core.Canonical(pc.s.Config.Context.Home), day: now.Format("2006-01-02"),
		week: now.AddDate(0, 0, -8).Format("2006-01-02")}
}

func (c *usageCase) path(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return c.home + "/" + rel
}

func (c *usageCase) sizes(t *testing.T, rows map[string]map[string]int64) {
	t.Helper()
	set := map[string]map[string]int64{}
	for rel, days := range rows {
		set[c.path(rel)] = days
	}
	if err := core.NewTable[map[string]int64](c.s.Store, "sizes", 1).Apply(set, nil, false); err != nil {
		t.Fatal(err)
	}
}

func (c *usageCase) folders(t *testing.T) (map[string]any, []map[string]any) {
	t.Helper()
	u := readData(t, c.s, "data/usage")
	var out []map[string]any
	for _, f := range u["folders"].([]any) {
		out = append(out, f.(map[string]any))
	}
	return u, out
}

func usagePaths(f map[string]any) []string {
	var out []string
	for _, p := range f["paths"].([]any) {
		out = append(out, p.(string))
	}
	return out
}

// Before the first round, and with nothing measured: the keys are there, the lists empty.
func TestDataUsageBeforeTheFirstRound(t *testing.T) {
	c := newUsageCase(t)
	os.Remove(c.s.Store.LastReportPath())
	u, folders := c.folders(t)
	if u["schema"] != float64(1) || u["scanned"] != nil || u["complete"] != nil || len(folders) != 0 ||
		len(u["unseen"].([]any)) != 0 || u["more"] != float64(0) || u["listedBytes"] != float64(0) || u["measuredBytes"] != float64(0) {
		t.Errorf("before the first round: %v", u)
	}
}

// The biggest first, at most dataUsageMost; the rest counted; under a megabyte not listed; what is outside the home
// and the temporary folder not listed.
func TestDataUsageOrderAndCount(t *testing.T) {
	c := newUsageCase(t)
	rows := map[string]map[string]int64{
		"Downloads": {c.day: 900 * usageMB}, "Documents": {c.day: 2000 * usageMB}, "Movies": {c.day: 500 * usageMB},
		"tiny": {c.day: usageMB - 1}, "/opt/elsewhere": {c.day: 5000 * usageMB},
		"/private/var/folders/ab/cd/T": {c.day: 300 * usageMB}, "Projects": {c.day: 700 * usageMB},
		"Library/Fonts": {c.day: 40 * usageMB}, ".weird": {c.day: 30 * usageMB},
	}
	c.sizes(t, rows)
	u, folders := c.folders(t)
	want := []struct{ kind, id, name string }{{usageKnown, "Documents", ""}, {usageKnown, "Downloads", ""}, {usageFolder, "", "Projects"},
		{usageKnown, "Movies", ""}, {usageTemp, "", ""}, {usageKnown, "Library/Fonts", ""}, {usageHidden, "", "weird"}}
	if len(folders) != len(want) {
		t.Fatalf("folders: %v", folders)
	}
	var sum float64
	for i, w := range want {
		f := folders[i]
		id, _ := f["id"].(string)
		name, _ := f["name"].(string)
		if f["kind"] != w.kind || id != w.id || name != w.name {
			t.Errorf("row %d: %v %v %v, want %v", i, f["kind"], f["id"], f["name"], w)
		}
		if f["day"] != c.day || f["grew7d"] != nil || f["pathsMore"] != float64(0) || len(usagePaths(f)) != 1 {
			t.Errorf("row %d: %v", i, f)
		}
		sum += f["bytes"].(float64)
	}
	if got := usagePaths(folders[0]); got[0] != c.path("Documents") {
		t.Errorf("path: %v", got)
	}
	if u["listedBytes"] != sum || u["measuredBytes"] != sum || u["more"] != float64(0) || u["complete"] != true {
		t.Errorf("totals: %v %v %v %v (sum %v)", u["listedBytes"], u["measuredBytes"], u["more"], u["complete"], sum)
	}

	old := dataUsageMost
	dataUsageMost = 3
	defer func() { dataUsageMost = old }()
	u, folders = c.folders(t)
	if len(folders) != 3 || u["more"] != float64(4) || u["listedBytes"] != float64(3600*usageMB) || u["measuredBytes"] != sum {
		t.Errorf("at most 3: %d rows, more %v, listed %v, measured %v", len(folders), u["more"], u["listedBytes"], u["measuredBytes"])
	}
}

// grew7d: against the newest measurement a week or more before the last one, as it is (also when it shrank, also
// under a gigabyte); null without one.
func TestDataUsageGrowth(t *testing.T) {
	c := newUsageCase(t)
	recent := time.Now().AddDate(0, 0, -3).Format("2006-01-02")
	older := time.Now().AddDate(0, 0, -20).Format("2006-01-02")
	c.sizes(t, map[string]map[string]int64{
		"Documents": {c.day: 2000 * usageMB, c.week: 1500 * usageMB, older: 100 * usageMB},
		"Downloads": {c.day: 900 * usageMB, c.week: 950 * usageMB},
		"Movies":    {c.day: 500 * usageMB, recent: 100 * usageMB},
		"Music":     {c.day: 400 * usageMB},
	})
	_, folders := c.folders(t)
	want := map[string]any{"Documents": float64(500 * usageMB), "Downloads": float64(-50 * usageMB), "Movies": nil, "Music": nil}
	for _, f := range folders {
		if w, ok := want[f["id"].(string)]; !ok || f["grew7d"] != w {
			t.Errorf("%v grew %v, want %v", f["id"], f["grew7d"], w)
		}
	}
}

// What an app or a tool keeps: an installed app by its name with its bundle id, its data and its caches apart, two
// folders of one app's data in one row; developer tools' caches in one row; what removed apps left in one row with
// how many apps. A folded row lists its folders, the biggest first, and they are its top.
func TestDataUsageFoldedRows(t *testing.T) {
	c := newUsageCase(t)
	c.s.Config.AppName = func(id string) string {
		if id == "com.example.chat" {
			return "Example Chat"
		}
		return ""
	}
	c.sizes(t, map[string]map[string]int64{
		"Library/Application Support/com.example.chat": {c.day: 300 * usageMB, c.week: 100 * usageMB},
		"Library/Containers/com.example.chat":          {c.day: 500 * usageMB},
		"Library/Caches/com.example.chat":              {c.day: 90 * usageMB},
		"Library/Application Support/Obsidian":         {c.day: 60 * usageMB},
		"Library/Caches/pip":                           {c.day: 200 * usageMB, c.week: 150 * usageMB},
		".cache/uv":                                    {c.day: 700 * usageMB, c.week: 100 * usageMB},
		".npm":                                         {c.day: 50 * usageMB},
		"Library/Application Support/com.gone.app":     {c.day: 40 * usageMB},
		"Library/Containers/ABCDE12345.com.gone.app":   {c.day: 20 * usageMB},
		"Library/Caches/org.other.gone":                {c.day: 10 * usageMB},
	})
	_, folders := c.folders(t)
	by := map[string]map[string]any{}
	for _, f := range folders {
		k := f["kind"].(string)
		if n, ok := f["name"].(string); ok {
			k += "|" + n
		}
		if h, ok := f["holds"].(string); ok {
			k += "|" + h
		}
		by[k] = f
	}
	if len(folders) != 5 || folders[0]["kind"] != usageDev {
		t.Fatalf("rows: %v", folders)
	}
	dev := by[usageDev]
	if dev["bytes"] != float64(950*usageMB) || dev["grew7d"] != float64(650*usageMB) || dev["name"] != nil || dev["id"] != nil {
		t.Errorf("dev caches: %v", dev)
	}
	if got := usagePaths(dev); len(got) != 3 || got[0] != c.path(".cache/uv") || got[1] != c.path("Library/Caches/pip") || got[2] != c.path(".npm") {
		t.Errorf("dev caches' folders: %v", got)
	}
	top := dev["top"].([]any)
	if len(top) != 3 || top[0].(map[string]any)["name"] != "uv" || top[0].(map[string]any)["path"] != c.path(".cache/uv") ||
		top[0].(map[string]any)["bytes"] != float64(700*usageMB) || top[0].(map[string]any)["dir"] != true {
		t.Errorf("dev caches' top: %v", top)
	}
	data := by[usageApp+"|Example Chat|data"]
	if data == nil || data["bytes"] != float64(800*usageMB) || data["bundleId"] != "com.example.chat" || data["grew7d"] != float64(200*usageMB) ||
		len(usagePaths(data)) != 2 || usagePaths(data)[0] != c.path("Library/Containers/com.example.chat") {
		t.Errorf("the app's data: %v", data)
	}
	cache := by[usageApp+"|Example Chat|cache"]
	if cache == nil || cache["bytes"] != float64(90*usageMB) || cache["bundleId"] != "com.example.chat" {
		t.Errorf("the app's caches: %v", cache)
	}
	tool := by[usageApp+"|Obsidian|data"]
	if tool == nil || tool["bundleId"] != nil || tool["apps"] != nil {
		t.Errorf("a tool's data: %v", tool)
	}
	gone := by[usageRemoved]
	if gone == nil || gone["bytes"] != float64(70*usageMB) || gone["apps"] != float64(2) || gone["name"] != nil || len(usagePaths(gone)) != 3 {
		t.Errorf("removed apps: %v", gone)
	}

	old := dataUsagePathsMost
	dataUsagePathsMost = 2
	defer func() { dataUsagePathsMost = old }()
	_, folders = c.folders(t)
	if f := folders[0]; len(usagePaths(f)) != 2 || f["pathsMore"] != float64(1) || f["bytes"] != float64(950*usageMB) {
		t.Errorf("at most 2 folders: %v", f)
	}
}

// top of a row of one folder: its subfolders as last measured and its own biggest files, the biggest first, at most
// dataUsageTop; not what is deeper, not another folder's.
func TestDataUsageTop(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{"Downloads": {c.day: 900 * usageMB}, "Documents": {c.day: 100 * usageMB}})
	dl := c.path("Downloads")
	measured := map[string]core.SpaceMeasured{
		dl:                          {Bytes: 900 * usageMB},
		dl + "/old-project":         {Bytes: 200 * usageMB},
		dl + "/old-project/vendor":  {Bytes: 150 * usageMB},
		dl + "/photos":              {Bytes: 90 * usageMB},
		c.path("Documents") + "/x":  {Bytes: 50 * usageMB},
		c.path("Downloads2") + "/y": {Bytes: 999 * usageMB},
	}
	if err := core.SpaceMeasuredTable(c.s.Store).Apply(measured, nil, false); err != nil {
		t.Fatal(err)
	}
	files := map[string][]core.SpaceFile{dl: {{Name: "系统镜像.dmg", Bytes: 400 * usageMB}, {Name: "movie.mp4", Bytes: 120 * usageMB},
		{Name: "a.zip", Bytes: 30 * usageMB}, {Name: "b.zip", Bytes: 20 * usageMB}}}
	if err := core.SpaceTopFilesTable(c.s.Store).Apply(files, nil, false); err != nil {
		t.Fatal(err)
	}
	_, folders := c.folders(t)
	top := folders[0]["top"].([]any)
	want := []struct {
		name  string
		bytes int64
		dir   bool
	}{{"系统镜像.dmg", 400, false}, {"old-project", 200, true}, {"movie.mp4", 120, false}, {"photos", 90, true}, {"a.zip", 30, false}}
	if len(top) != len(want) {
		t.Fatalf("top: %v", top)
	}
	for i, w := range want {
		x := top[i].(map[string]any)
		if x["name"] != w.name || x["bytes"] != float64(w.bytes*usageMB) || x["dir"] != w.dir || x["path"] != dl+"/"+w.name {
			t.Errorf("top %d: %v, want %v", i, x, w)
		}
	}
	if docs := folders[1]["top"].([]any); len(docs) != 1 || docs[0].(map[string]any)["name"] != "x" {
		t.Errorf("another folder's top: %v", docs)
	}
}

// Without Full Disk Access in the last round: not complete, with the folders that round did not measure; what is
// listed of them is from an earlier round, by its day.
func TestDataUsageWithoutFullDiskAccess(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{"Downloads": {c.week: 900 * usageMB}, "Library/Caches/pip": {c.day: 100 * usageMB}})
	now := core.Time{Time: time.Now()}
	if err := c.s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now,
		Skipped: []core.Skipped{{Rule: "space", Reason: core.NotLooked("桌面、文稿、下载和别的应用的数据占多大")}}}); err != nil {
		t.Fatal(err)
	}
	u, folders := c.folders(t)
	if u["complete"] != false {
		t.Errorf("complete: %v", u["complete"])
	}
	unseen := map[string]bool{}
	for _, x := range u["unseen"].([]any) {
		unseen[x.(string)] = true
	}
	if len(unseen) != len(core.Guarded) || !unseen["Downloads"] || !unseen["Library/Containers"] {
		t.Errorf("unseen: %v", u["unseen"])
	}
	if len(folders) != 2 || folders[0]["id"] != "Downloads" || folders[0]["day"] != c.week || folders[1]["day"] != c.day {
		t.Errorf("folders: %v", folders)
	}
}

// The same rows, in the same order, with the same sizes as the 「状态」 page's folders (macFolders), which the agent
// reads until it draws from this.
func TestDataUsageMatchesThePage(t *testing.T) {
	c := newUsageCase(t)
	c.s.Config.AppName = func(id string) string {
		if id == "com.example.chat" {
			return "Example Chat"
		}
		return ""
	}
	c.sizes(t, map[string]map[string]int64{
		"Documents": {c.day: 2000 * usageMB}, "Downloads": {c.day: 900 * usageMB}, "Projects": {c.day: 700 * usageMB},
		"Library/Application Support/com.example.chat": {c.day: 300 * usageMB}, "Library/Containers/com.example.chat": {c.day: 500 * usageMB},
		"Library/Caches/com.example.chat": {c.day: 90 * usageMB}, "Library/Caches/pip": {c.day: 200 * usageMB},
		".cache/uv": {c.day: 710 * usageMB}, "Library/Application Support/com.gone.app": {c.day: 40 * usageMB},
		"Library/Caches/org.other.gone": {c.day: 10 * usageMB}, ".weird": {c.day: 30 * usageMB}, "Library/Odd": {c.day: 25 * usageMB},
		"/private/var/folders/ab/cd/T": {c.day: 310 * usageMB},
	})
	lines, _ := c.s.macFolders()
	_, folders := c.folders(t)
	if len(lines) != macMaxFolders || len(folders) < len(lines) {
		t.Fatalf("page %d rows, data %d", len(lines), len(folders))
	}
	for i, l := range lines {
		if folders[i]["bytes"] != float64(l.bytes) {
			t.Errorf("row %d: the page has %s (%d bytes), the data %v %v %v (%v bytes)", i, l.name, l.bytes, folders[i]["kind"],
				folders[i]["id"], folders[i]["name"], folders[i]["bytes"])
		}
	}
}

// reclaim: what can go in a row, from the last round's plans (data/overview's reclaimable, by where it is).

// file: a file made under the home (rel relative to it, or absolute); its path.
func (c *usageCase) file(t *testing.T, rel string) string {
	t.Helper()
	p := c.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// dir: a folder made under the home; its path.
func (c *usageCase) dir(t *testing.T, rel string) string {
	t.Helper()
	p := c.path(rel)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// round: the last round found these and nothing else (a new round, so a new plan).
func (c *usageCase) round(t *testing.T, found ...core.Finding) {
	t.Helper()
	now := core.Time{Time: time.Now()}
	if err := c.s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: found}); err != nil {
		t.Fatal(err)
	}
}

func usageCacheFinding(path string, mb int64) core.Finding {
	return core.Finding{Rule: "cache.rebuildable.pip", Category: core.CatCache, Severity: core.Low, Verdict: core.Safe, Path: path,
		Bytes: core.Size(mb * usageMB)}
}

func usageInstallerFinding(path string, mb int64) core.Finding {
	return core.Finding{Rule: "leftover.installer", Category: core.CatLeftover, Severity: core.Low, Verdict: core.Confirm, Path: path,
		Bytes: core.Size(mb * usageMB)}
}

func usageLargeFinding(path string, mb int64) core.Finding {
	return core.Finding{Rule: "stale.large-file", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm, Path: path,
		Bytes: core.Size(mb * usageMB)}
}

// usageCopiesFinding: copies of keep (which stays); the item is the copies.
func usageCopiesFinding(keep string, mb int64, copies ...string) core.Finding {
	return core.Finding{Rule: "space.duplicates", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm, Path: keep,
		Bytes: core.Size(mb * usageMB), Evidence: map[string]string{"targets": strings.Join(copies, "\n")}}
}

// usageByRow: the rows by kind and id or name ("known|Downloads", "dev-caches|").
func usageByRow(folders []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, f := range folders {
		k := f["kind"].(string) + "|"
		if id, ok := f["id"].(string); ok {
			k += id
		} else if n, ok := f["name"].(string); ok {
			k += n
		}
		out[k] = f
	}
	return out
}

// usageReclaimed: a row's reclaim written out, "<MB>×<count>: <id> <MB>×<count>, …" with the categories in their
// order ("0×0" for nothing); checked to be an object whose categories add up to it.
func usageReclaimed(t *testing.T, f map[string]any) string {
	t.Helper()
	r, ok := f["reclaim"].(map[string]any)
	if !ok {
		t.Fatalf("no reclaim: %v", f)
	}
	cats, ok := r["categories"].([]any)
	if !ok {
		t.Fatalf("categories not a list: %v", r)
	}
	var bytes, count float64
	var parts []string
	for _, x := range cats {
		m := x.(map[string]any)
		bytes += m["bytes"].(float64)
		count += m["count"].(float64)
		parts = append(parts, fmt.Sprintf("%s %g×%g", m["id"], m["bytes"].(float64)/float64(usageMB), m["count"]))
	}
	if r["bytes"] != bytes || r["count"] != count {
		t.Errorf("reclaim does not add up: %v", r)
	}
	out := fmt.Sprintf("%g×%g", r["bytes"].(float64)/float64(usageMB), r["count"])
	if len(parts) > 0 {
		out += ": " + strings.Join(parts, ", ")
	}
	return out
}

// A row with nothing that can go: an object of zeros with an empty list, not null; also before the first round.
func TestDataUsageReclaimNothing(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{"Documents": {c.day: 900 * usageMB}, "Music": {c.day: 100 * usageMB}})
	for _, first := range []bool{false, true} {
		if first {
			os.Remove(c.s.Store.LastReportPath())
		}
		_, folders := c.folders(t)
		if len(folders) != 2 {
			t.Fatalf("folders: %v", folders)
		}
		for _, f := range folders {
			if got := usageReclaimed(t, f); got != "0×0" {
				t.Errorf("before the first round %v: %v reclaims %s", first, f["id"], got)
			}
		}
	}
}

// An item counts in a row when what it takes is inside one of the row's folders, or is that folder; by whole path
// segments (a file in 「Movies Old」 is not in 「Movies」).
func TestDataUsageReclaimUnderAndAtAFolder(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{"Downloads": {c.day: 900 * usageMB}, "Movies": {c.day: 600 * usageMB},
		"Movies Old": {c.day: 500 * usageMB}, "Library/Caches/pip": {c.day: 200 * usageMB}})
	c.round(t, usageInstallerFinding(c.file(t, "Downloads/apps/App-1.0.dmg"), 300),
		usageLargeFinding(c.file(t, "Movies Old/clip.avi"), 400), usageCacheFinding(c.dir(t, "Library/Caches/pip"), 150))
	_, folders := c.folders(t)
	by := usageByRow(folders)
	want := map[string]string{"known|Downloads": "300×1: installer 300×1", "folder|Movies Old": "400×1: large-file 400×1",
		"known|Movies": "0×0", "dev-caches|": "150×1: cache 150×1"}
	for k, w := range want {
		if by[k] == nil {
			t.Fatalf("no row %s: %v", k, folders)
		}
		if got := usageReclaimed(t, by[k]); got != w {
			t.Errorf("%s: %s, want %s", k, got, w)
		}
	}
}

// What an item takes is compared as the rows' folders are written (canonical): a home reached through a link.
func TestDataUsageReclaimThroughALinkedHome(t *testing.T) {
	c := newUsageCase(t)
	link := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(c.home, link); err != nil {
		t.Fatal(err)
	}
	c.s.Config.Context.Home = link
	if core.Canonical(link) != c.home {
		t.Fatalf("the link: %s, the home %s", core.Canonical(link), c.home)
	}
	c.sizes(t, map[string]map[string]int64{"Downloads": {c.day: 900 * usageMB}})
	c.file(t, "Downloads/App-2.0.dmg")
	c.round(t, usageInstallerFinding(filepath.Join(link, "Downloads/App-2.0.dmg"), 300))
	_, folders := c.folders(t)
	if len(folders) != 1 || usagePaths(folders[0])[0] != c.path("Downloads") {
		t.Fatalf("folders: %v", folders)
	}
	if got := usageReclaimed(t, folders[0]); got != "300×1: installer 300×1" {
		t.Errorf("through the link: %s", got)
	}
}

// A folded row counts what is in any of its folders, also the ones past the paths listed; an app's data in several
// folders is one item.
func TestDataUsageReclaimFoldedRows(t *testing.T) {
	c := newUsageCase(t)
	c.s.Config.AppName = func(string) string { return "" }
	c.sizes(t, map[string]map[string]int64{
		"Library/Application Support/com.gone.app": {c.day: 400 * usageMB}, "Library/Containers/com.gone.app": {c.day: 300 * usageMB},
		"Library/Caches/com.gone.app": {c.day: 50 * usageMB}, ".cache/uv": {c.day: 700 * usageMB},
		"Library/Caches/pip": {c.day: 200 * usageMB}, ".npm": {c.day: 60 * usageMB},
	})
	for _, rel := range []string{"Library/Application Support/com.gone.app", "Library/Containers/com.gone.app", "Library/Caches/com.gone.app"} {
		c.file(t, rel+"/data")
	}
	c.round(t, core.Finding{Rule: "leftover.app-data", Category: core.CatLeftover, Severity: core.Low, Verdict: core.Confirm,
		Path: c.path("Library/Application Support/com.gone.app"), Bytes: core.Size(750 * usageMB),
		Evidence: map[string]string{"bundle_id": "com.gone.app"}},
		usageCacheFinding(c.dir(t, ".npm"), 40))
	old := dataUsagePathsMost
	dataUsagePathsMost = 1
	defer func() { dataUsagePathsMost = old }()
	_, folders := c.folders(t)
	by := usageByRow(folders)
	gone, dev := by[usageRemoved+"|"], by[usageDev+"|"]
	if gone == nil || dev == nil || gone["pathsMore"] != float64(2) || dev["pathsMore"] != float64(2) {
		t.Fatalf("rows: %v", folders)
	}
	if got := usageReclaimed(t, gone); got != "750×1: leftover 750×1" {
		t.Errorf("removed apps: %s", got)
	}
	if got := usageReclaimed(t, dev); got != "40×1: cache 40×1" {
		t.Errorf("dev caches (.npm the third of its folders): %s", got)
	}
}

// An item whose targets are in several rows counts once, in the row holding the most of them, the bigger row where
// rows hold as many; its bytes all go there. What is in no row does not count.
func TestDataUsageReclaimAcrossRows(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{"Documents": {c.day: 2000 * usageMB}, "Downloads": {c.day: 900 * usageMB},
		"Desktop": {c.day: 300 * usageMB}})
	c.round(t,
		// two copies in Downloads, one in Documents: Downloads, though Documents is the bigger row
		usageCopiesFinding(c.file(t, "Pictures/a.jpg"), 30, c.file(t, "Downloads/a1.jpg"), c.file(t, "Downloads/a2.jpg"), c.file(t, "Documents/a3.jpg")),
		// one in Desktop, one in Documents: Documents, the bigger
		usageCopiesFinding(c.file(t, "Pictures/b.jpg"), 20, c.file(t, "Desktop/b1.jpg"), c.file(t, "Documents/b2.jpg")),
		// one in no row (Pictures is not measured), one in Desktop: Desktop
		usageCopiesFinding(c.file(t, "Pictures/d.jpg"), 10, c.file(t, "Pictures/d1.jpg"), c.file(t, "Desktop/d2.jpg")),
		// all in no row: nowhere
		usageCopiesFinding(c.file(t, "Pictures/e.jpg"), 5, c.file(t, "Pictures/e1.jpg")))
	_, folders := c.folders(t)
	by := usageByRow(folders)
	want := map[string]string{"known|Downloads": "30×1: duplicate 30×1", "known|Documents": "20×1: duplicate 20×1",
		"known|Desktop": "10×1: duplicate 10×1"}
	for k, w := range want {
		if got := usageReclaimed(t, by[k]); got != w {
			t.Errorf("%s: %s, want %s", k, got, w)
		}
	}
}

// Rows nested in one another (a folder measured whole once, its subfolder measured too) both count what is in the
// inner one, as both count its bytes; an item across two inner rows counts only in the outer one, which holds it all.
func TestDataUsageReclaimNestedRows(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{"Library/Caches": {c.day: 900 * usageMB}, "Library/Caches/pip": {c.day: 200 * usageMB},
		"Library/Caches/SomeTool": {c.day: 90 * usageMB}})
	pip, tool := c.dir(t, "Library/Caches/pip"), c.dir(t, "Library/Caches/SomeTool")
	c.round(t, usageCacheFinding(pip, 150), core.Finding{Rule: "cache.electron", Category: core.CatCache, Severity: core.Low,
		Verdict: core.Safe, Path: tool, Bytes: core.Size(60 * usageMB),
		Evidence: map[string]string{"targets": c.dir(t, "Library/Caches/SomeTool/Cache") + "\n" + c.dir(t, "Library/Caches/pip/wheels")}})
	_, folders := c.folders(t)
	by := usageByRow(folders)
	want := map[string]string{"known|Library/Caches": "210×2: cache 210×2", "dev-caches|": "150×1: cache 150×1", "app|SomeTool": "0×0"}
	for k, w := range want {
		if by[k] == nil {
			t.Fatalf("no row %s: %v", k, folders)
		}
		if got := usageReclaimed(t, by[k]); got != w {
			t.Errorf("%s: %s, want %s", k, got, w)
		}
	}
}

// A package manager running install scripts is a setting, not space: its item (the config file the fix writes) counts
// in no row, as it is not in the overview's reclaimable but in its settings (data/category has it); what else is in the
// row counts as before.
func TestDataUsageReclaimLeavesOutInstallScripts(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{".config": {c.day: 300 * usageMB}, "Downloads": {c.day: 900 * usageMB}})
	cfg := c.file(t, ".config/uv/uv.toml")
	if cfg != core.ScriptsConfigPath("uv", c.home) {
		t.Fatalf("uv's config: %s, the rule's %s", cfg, core.ScriptsConfigPath("uv", c.home))
	}
	scripts := core.Finding{Rule: core.InstallScriptsRuleID, Category: core.CatPosture, Severity: core.Low, Verdict: core.Confirm,
		Path: cfg, Evidence: map[string]string{"tool": "uv", "name": "uv", "config": cfg, "append": "no-build = true"}}
	c.round(t, scripts, usageLargeFinding(c.file(t, ".config/old.iso"), 200), usageInstallerFinding(c.file(t, "Downloads/App.dmg"), 300))
	if n := readData(t, c.s, "data/category?id=install-scripts")["count"]; n != float64(1) {
		t.Fatalf("data/category?id=install-scripts: %v items, the item is not in the plan", n)
	}
	ov := readData(t, c.s, "data/overview")
	if _, has := byID(t, ov["reclaimable"])["install-scripts"]; has {
		t.Errorf("install-scripts in the overview's reclaimable")
	}
	if s := ov["settings"].([]any); len(s) != 1 || s[0].(map[string]any)["id"] != "install-scripts" ||
		s[0].(map[string]any)["count"] != float64(1) || s[0].(map[string]any)["bytes"] != float64(0) ||
		s[0].(map[string]any)["files"] != float64(0) {
		t.Errorf("the overview's settings: %v", ov["settings"])
	}
	_, folders := c.folders(t)
	want := map[string]string{c.path(".config"): "200×1: large-file 200×1", c.path("Downloads"): "300×1: installer 300×1"}
	for _, f := range folders {
		w, ok := want[usagePaths(f)[0]]
		if !ok {
			t.Fatalf("a row: %v", f)
		}
		if got := usageReclaimed(t, f); got != w {
			t.Errorf("%s: %s, want %s", usagePaths(f)[0], got, w)
		}
	}
	// Alone in its row: the row has nothing that can go
	c.round(t, scripts)
	_, folders = c.folders(t)
	for _, f := range folders {
		if got := usageReclaimed(t, f); got != "0×0" {
			t.Errorf("%s with only install-scripts: %s", usagePaths(f)[0], got)
		}
	}
	// Not to be brought up again: the entry says which tool's setting it is.
	clickTool(t, c.s, "scan_ignore", O{"finding_id": c.s.fid(scripts)})
	ig := readData(t, c.s, "data/settings")["ignored"].([]any)
	if len(ig) != 1 || ig[0].(map[string]any)["rule"] != core.InstallScriptsRuleID || ig[0].(map[string]any)["name"] != "uv" {
		t.Errorf("ignored: %v", ig)
	}
}

// The categories of a row, the biggest first; as big, in the overview's order.
func TestDataUsageReclaimCategoriesBiggestFirst(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{"Downloads": {c.day: 5000 * usageMB}})
	c.round(t, usageInstallerFinding(c.file(t, "Downloads/App.dmg"), 900), usageInstallerFinding(c.file(t, "Downloads/Other.pkg"), 100),
		usageCopiesFinding(c.file(t, "Documents/photo.jpg"), 334, c.file(t, "Downloads/photo.jpg")),
		usageLargeFinding(c.file(t, "Downloads/film.mov"), 1000))
	_, folders := c.folders(t)
	if got := usageReclaimed(t, folders[0]); got != "2334×4: installer 1000×2, large-file 1000×1, duplicate 334×1" {
		t.Errorf("categories: %s", got)
	}
}

// Rows that do not overlap add up to no more than data/overview's reclaimable, by category; to the same when every
// item is in one of them.
func TestDataUsageReclaimAddsUpToTheOverview(t *testing.T) {
	c := newUsageCase(t) // the page case's round: pip's cache, an installer in Downloads, a large file in Movies, an AI plugin
	rows := map[string]map[string]int64{"Downloads": {c.day: 900 * usageMB}, "Movies": {c.day: 1300 * usageMB},
		"Library/Caches/pip": {c.day: 70 * usageMB}, ".claude": {c.day: 5 * usageMB}, "Documents": {c.day: 2000 * usageMB}}
	c.sizes(t, rows)
	type sum struct{ bytes, count float64 }
	overview := map[string]sum{}
	for _, x := range readData(t, c.s, "data/overview")["reclaimable"].([]any) {
		m := x.(map[string]any)
		overview[m["id"].(string)] = sum{m["bytes"].(float64), m["count"].(float64)}
	}
	if len(overview) != 4 {
		t.Fatalf("the overview: %v", overview)
	}
	byCategory := func() map[string]sum {
		_, folders := c.folders(t)
		out := map[string]sum{}
		for _, f := range folders {
			usageReclaimed(t, f)
			for _, x := range f["reclaim"].(map[string]any)["categories"].([]any) {
				m := x.(map[string]any)
				s := out[m["id"].(string)]
				out[m["id"].(string)] = sum{s.bytes + m["bytes"].(float64), s.count + m["count"].(float64)}
			}
		}
		return out
	}
	if got := byCategory(); !reflect.DeepEqual(got, overview) {
		t.Errorf("every item in a row: %v, the overview %v", got, overview)
	}
	// Without the AI plugin's folder: it counts nowhere, the rest as before
	if err := core.NewTable[map[string]int64](c.s.Store, "sizes", 1).Apply(nil, []string{c.path(".claude")}, false); err != nil {
		t.Fatal(err)
	}
	got := byCategory()
	if _, ok := got["ai-plugin"]; ok || len(got) != 3 {
		t.Errorf("without .claude: %v", got)
	}
	for id, s := range got {
		if s != overview[id] {
			t.Errorf("%s: %v, the overview %v", id, s, overview[id])
		}
	}
}

// data/usage carries the last round's account of the disk: null before one is made; unexplained is
// null while something that can be large was not measured.
func TestDataUsageReconcile(t *testing.T) {
	c := newUsageCase(t)
	if u, _ := c.folders(t); u["reconcile"] != nil {
		t.Fatalf("before an account: %v", u["reconcile"])
	}
	a := core.Reconcile{Day: c.day, Total: 1000, Used: 800, Purgeable: 50, Complete: true, Unexplained: 250, Threshold: 100, Snapshots: -1,
		Parts: []core.ReconcilePart{{ID: core.PartHome, Bytes: 400}, {ID: core.PartMacOS, Bytes: 100}},
		Gaps:  []core.ReconcileGap{{ID: core.GapSpotlight, Why: core.WhyRoot}}}
	put := func() map[string]any {
		if err := core.ReconcileTable(c.s.Store).Apply(map[string]core.Reconcile{"last": a}, nil, false); err != nil {
			t.Fatal(err)
		}
		u, _ := c.folders(t)
		return u["reconcile"].(map[string]any)
	}
	r := put()
	parts, gaps := r["parts"].([]any), r["unmeasured"].([]any)
	if r["used"] != float64(800) || r["total"] != float64(1000) || r["purgeable"] != float64(50) || r["measured"] != float64(500) ||
		r["unexplained"] != float64(250) || r["threshold"] != float64(100) || r["complete"] != true || r["over"] != true ||
		r["day"] != c.day || len(parts) != 2 || parts[0].(map[string]any)["id"] != "home" || len(gaps) != 1 {
		t.Errorf("complete: %v", r)
	}
	if g := gaps[0].(map[string]any); g["id"] != "spotlight-index" || g["why"] != "root" || g["blocks"] != false {
		t.Errorf("gap: %v", g)
	}
	a.Complete = false
	a.Gaps = append(a.Gaps, core.ReconcileGap{ID: core.GapHomeGuarded, Why: core.WhyAccess, Open: true})
	if r = put(); r["unexplained"] != nil || r["complete"] != false || r["over"] != false {
		t.Errorf("not complete: %v", r)
	}
}

// what: whose a row is, what it holds and what deleting it loses. By rules/folders.json where the folder is listed;
// else only what the kind makes certain; a thing in top has its own entry when it is listed, else the row's.
func TestDataUsageWhat(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{
		"Library/Messages":                {c.day: 9000 * usageMB},
		"Library/Developer/CoreSimulator": {c.day: 8000 * usageMB},
		"Projects":                        {c.day: 7000 * usageMB},
		"Library/Caches/Acme":             {c.day: 6000 * usageMB},
		"/private/var/folders/ab/cd/T":    {c.day: 5000 * usageMB},
		".weird":                          {c.day: 4000 * usageMB},
		"Library/Caches/pip":              {c.day: 2500 * usageMB},
		".cache/uv":                       {c.day: 2000 * usageMB},
		"Library/Application Support/Zz":  {c.day: 1000 * usageMB},
	})
	sims := c.path("Library/Developer/CoreSimulator")
	measured := map[string]core.SpaceMeasured{
		c.path("Library/Messages/Attachments"): {Bytes: 8000 * usageMB},
		sims + "/Devices":                      {Bytes: 5000 * usageMB},
		sims + "/Caches":                       {Bytes: 2000 * usageMB},
		sims + "/Temp":                         {Bytes: 500 * usageMB},
	}
	if err := core.SpaceMeasuredTable(c.s.Store).Apply(measured, nil, false); err != nil {
		t.Fatal(err)
	}
	_, folders := c.folders(t)
	type what struct{ owner, content, ifDeleted any }
	of := func(m map[string]any) what {
		w := m["what"].(map[string]any)
		return what{w["owner"], w["content"], w["ifDeleted"]}
	}
	want := []what{
		{"messages", "user", "synced"}, // listed
		{nil, "app-data", nil},         // an app's data: not known what deleting it loses
		{"user", "user", "lost"},       // a folder of the user's own
		{nil, "cache", "rebuilds"},     // an app's cache
		{nil, "temp", "rebuilds"},      // the temporary folder
		{nil, "cache", "rebuilds"},     // developer caches: two folders under two entries (Library/Caches, .cache) → by kind
		{nil, nil, nil},                // a hidden folder
		{nil, "app-data", nil},
	}
	if len(folders) != len(want) {
		t.Fatalf("%d rows, want %d: %v", len(folders), len(want), folders)
	}
	for i, w := range want {
		if got := of(folders[i]); got != w {
			t.Errorf("row %d (%v %v): %v, want %v", i, folders[i]["kind"], folders[i]["paths"], got, w)
		}
	}
	// top: a listed subfolder says its own, an unlisted one what its row says
	if top := folders[0]["top"].([]any); len(top) != 1 || of(top[0].(map[string]any)) != (what{"messages", "user", "synced"}) {
		t.Errorf("Messages' top: %v", top)
	}
	tops := map[string]what{}
	for _, x := range folders[1]["top"].([]any) {
		tops[x.(map[string]any)["name"].(string)] = of(x.(map[string]any))
	}
	for name, w := range map[string]what{"Devices": {"xcode", "app-data", "resets"}, "Caches": {"xcode", "cache", "rebuilds"},
		"Temp": {nil, "app-data", nil}} {
		if tops[name] != w {
			t.Errorf("CoreSimulator's %s: %v, want %v", name, tops[name], w)
		}
	}
}

// mix: what a row is made of, from the mixes the space rule remembered: the kinds the biggest first (other last), the
// years the newest first (no date last), the biggest files with their full paths; a folded row's folders together;
// null when no folder of the row has one; unknown: what was not looked into.
func TestDataUsageMix(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{
		"Library/Messages":   {c.day: 9000 * usageMB},
		"Library/Caches/pip": {c.day: 3000 * usageMB},
		".cache/uv":          {c.day: 2000 * usageMB},
		"Projects":           {c.day: 1000 * usageMB},
	})
	mixes := map[string]core.SpaceMix{
		c.path("Library/Messages"): {
			Kinds: map[string]core.SpaceTally{"photo": {Bytes: 3000 * usageMB, Count: 900}, "video": {Bytes: 5000 * usageMB, Count: 40},
				core.KindOther: {Bytes: 600 * usageMB, Count: 7}, "database": {Bytes: 400 * usageMB, Count: 2}},
			Years: map[string]int64{"2026": 1000 * usageMB, "2024": 6000 * usageMB, "2025": 1500 * usageMB, "": 500 * usageMB},
			Top: []core.SpaceBigFile{{Path: "Attachments/0b/11/clip.mov", Bytes: 800 * usageMB, Modified: "2024-03-02"},
				{Path: "chat.db", Bytes: 390 * usageMB, Modified: "2026-11-20"}},
			Unknown: 5 * usageMB,
		},
		c.path("Library/Caches/pip"): {Kinds: map[string]core.SpaceTally{"archive": {Bytes: 2900 * usageMB, Count: 50}},
			Years: map[string]int64{"2026": 2900 * usageMB}, Top: []core.SpaceBigFile{{Path: "http/a.whl", Bytes: 90 * usageMB, Modified: "2026-01-01"}}},
	}
	if err := core.SpaceMixTable(c.s.Store).Apply(mixes, nil, false); err != nil {
		t.Fatal(err)
	}
	_, folders := c.folders(t)
	m := folders[0]["mix"].(map[string]any)
	if m["bytes"] != float64(9000*usageMB) || m["count"] != float64(949) || m["unknown"] != float64(5*usageMB) {
		t.Errorf("Messages' mix: %v", m)
	}
	var kinds, years []string
	for _, k := range m["kinds"].([]any) {
		kinds = append(kinds, k.(map[string]any)["id"].(string))
	}
	for _, y := range m["years"].([]any) {
		years = append(years, fmt.Sprint(y.(map[string]any)["year"]))
	}
	if strings.Join(kinds, " ") != "video photo database other" || strings.Join(years, " ") != "2026 2025 2024 <nil>" {
		t.Errorf("kinds %v, years %v", kinds, years)
	}
	f := m["files"].([]any)[0].(map[string]any)
	if f["name"] != "clip.mov" || f["path"] != c.path("Library/Messages")+"/Attachments/0b/11/clip.mov" || f["kind"] != "video" ||
		f["modified"] != "2024-03-02" || f["bytes"] != float64(800*usageMB) {
		t.Errorf("the biggest file: %v", f)
	}
	// the folded row: one of its two folders has a mix; the other's bytes are unknown
	dev := folders[1]["mix"].(map[string]any)
	if folders[1]["kind"] != usageDev || dev["bytes"] != float64(2900*usageMB) || dev["unknown"] != float64(2000*usageMB) {
		t.Errorf("the folded row's mix: %v", dev)
	}
	if folders[2]["mix"] != nil {
		t.Errorf("a row without a mix: %v", folders[2]["mix"])
	}
	// more years than listed: the oldest folded into the last one
	old := dataUsageMixYears
	dataUsageMixYears = 2
	defer func() { dataUsageMixYears = old }()
	_, folders = c.folders(t)
	ys := folders[0]["mix"].(map[string]any)["years"].([]any)
	last := ys[1].(map[string]any)
	if len(ys) != 3 || last["year"] != float64(2025) || last["bytes"] != float64(7500*usageMB) || last["before"] != true {
		t.Errorf("years folded: %v", ys)
	}
}

// actions: what can be done about a row. The scan's own cleaning first, when something in the row can go, with the
// categories; then what the list says for the row's folders, each once; a thing in top has its own folder's, never
// clean; nothing for a row the list does not know and with nothing to clean. Every action has every key.
func TestDataUsageActions(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{
		"Library/Messages":                {c.day: 9000 * usageMB},
		"Downloads":                       {c.day: 8000 * usageMB},
		"Library/Developer/CoreSimulator": {c.day: 7000 * usageMB},
		"Projects":                        {c.day: 6000 * usageMB},
		"Library/Mobile Documents":        {c.day: 5000 * usageMB},
		"Library/CloudStorage":            {c.day: 10 * usageMB},
	})
	sims := c.path("Library/Developer/CoreSimulator")
	measured := map[string]core.SpaceMeasured{
		c.path("Library/Messages/Attachments"): {Bytes: 8000 * usageMB},
		sims + "/Devices":                      {Bytes: 5000 * usageMB},
		sims + "/Caches":                       {Bytes: 1000 * usageMB},
	}
	if err := core.SpaceMeasuredTable(c.s.Store).Apply(measured, nil, false); err != nil {
		t.Fatal(err)
	}
	c.round(t, usageInstallerFinding(c.file(t, "Downloads/a.dmg"), 300), usageLargeFinding(c.file(t, "Downloads/big.mov"), 900))
	_, folders := c.folders(t)
	rows := usageByRow(folders)
	ids := func(m map[string]any) string {
		var out []string
		for _, a := range m["actions"].([]any) {
			a := a.(map[string]any)
			for _, k := range []string{"id", "by", "pane", "app", "bundleId", "command", "categories"} {
				if _, ok := a[k]; !ok {
					t.Errorf("an action without %s: %v", k, a)
				}
			}
			out = append(out, a["id"].(string)+"@"+a["by"].(string))
		}
		return strings.Join(out, " ")
	}
	for row, want := range map[string]string{
		"known|Library/Messages":         "storage-settings@system-settings messages-keep@app",
		"known|Downloads":                "clean@scan review@finder",
		"app|CoreSimulator":              "xcode-simulators@command", // measured a level above the list's entry (Devices)
		"folder|Projects":                "",
		"known|Library/Mobile Documents": "remove-download@finder icloud-optimize@system-settings",
	} {
		f, ok := rows[row]
		if !ok {
			t.Fatalf("no row %s: %v", row, rows)
		}
		if got := ids(f); got != want {
			t.Errorf("%s: %q, want %q", row, got, want)
		}
	}
	clean := rows["known|Downloads"]["actions"].([]any)[0].(map[string]any)
	if cats := fmt.Sprint(clean["categories"]); cats != "[large-file installer]" || clean["command"] != nil {
		t.Errorf("clean: %v", clean)
	}
	keep := rows["known|Library/Messages"]["actions"].([]any)[1].(map[string]any)
	if keep["app"] != "信息" || keep["bundleId"] != "com.apple.MobileSMS" || keep["pane"] != nil || keep["categories"] != nil {
		t.Errorf("messages-keep: %v", keep)
	}
	// top: a listed subfolder says its own; clean is the row's, not a thing's
	if top := rows["known|Library/Messages"]["top"].([]any); len(top) != 1 ||
		ids(top[0].(map[string]any)) != "storage-settings@system-settings messages-keep@app" {
		t.Errorf("Messages' top: %v", top)
	}
	tops := map[string]string{}
	for _, x := range rows["app|CoreSimulator"]["top"].([]any) {
		tops[x.(map[string]any)["name"].(string)] = ids(x.(map[string]any))
	}
	if tops["Devices"] != "xcode-simulators@command" || tops["Caches"] != "" {
		t.Errorf("CoreSimulator's top: %v", tops)
	}
	for _, x := range rows["known|Downloads"]["top"].([]any) {
		if got := ids(x.(map[string]any)); got != "review@finder" {
			t.Errorf("a file in Downloads: %q", got)
		}
	}
}

// A row measured a level above the list's entries gets what the entries inside it say (the row of ~/.ollama: models/
// is the entry), each once; developer tools' caches, folded into one row, get Xcode's. What apps that are gone left
// gets nothing done in an app or by a command, the row and its things alike: the app and its command are gone too.
// A thing inside the Trash is not told to empty the whole Trash; the Trash itself is.
func TestDataUsageActionsOfFoldersAboveTheListAndOfRemovedApps(t *testing.T) {
	c := newUsageCase(t)
	c.s.Config.AppName = func(string) string { return "" } // no app is installed: com.docker.docker is what one left
	docker := "Library/Containers/com.docker.docker"
	c.sizes(t, map[string]map[string]int64{
		".ollama":                         {c.day: 9000 * usageMB},
		".lmstudio":                       {c.day: 8000 * usageMB},
		"Library/Developer/CoreSimulator": {c.day: 7000 * usageMB},
		"Library/Developer/Xcode":         {c.day: 6000 * usageMB},
		"Library/Caches/pip":              {c.day: 100 * usageMB},
		docker:                            {c.day: 5000 * usageMB},
		".Trash":                          {c.day: 4000 * usageMB},
	})
	measured := map[string]core.SpaceMeasured{
		c.path(docker + "/Data"):  {Bytes: 4900 * usageMB},
		c.path(".Trash/old-disk"): {Bytes: 3000 * usageMB},
		c.path(".ollama/models"):  {Bytes: 8900 * usageMB},
	}
	if err := core.SpaceMeasuredTable(c.s.Store).Apply(measured, nil, false); err != nil {
		t.Fatal(err)
	}
	_, folders := c.folders(t)
	ids := func(m map[string]any) string {
		var out []string
		for _, a := range m["actions"].([]any) {
			out = append(out, a.(map[string]any)["id"].(string)+"@"+a.(map[string]any)["by"].(string))
		}
		return strings.Join(out, " ")
	}
	rows, home := map[string]map[string]any{}, filepath.Dir(c.path("x"))
	for _, f := range folders {
		for _, p := range f["paths"].([]any) {
			rows[strings.TrimPrefix(p.(string), home+"/")] = f
		}
	}
	for rel, want := range map[string]string{
		".ollama":                         "ollama-rm@command",
		".lmstudio":                       "lm-studio-models@app",
		"Library/Developer/CoreSimulator": "xcode-simulators@command",
		// Xcode's folder is in the row of developer tools' caches, with pip's (which the case's round has to clean)
		"Library/Developer/Xcode": "clean@scan xcode-archives@app",
		docker:                    "", // docker-prune: there is no docker to run it
		".Trash":                  "empty-trash@finder",
	} {
		f, ok := rows[rel]
		if !ok {
			t.Fatalf("no row with %s: %v", rel, folders)
		}
		if got := ids(f); got != want {
			t.Errorf("%s (%v): %q, want %q", rel, f["kind"], got, want)
		}
	}
	if k := rows[docker]["kind"]; k != usageRemoved {
		t.Fatalf("Docker's folder is in a row of kind %v", k)
	}
	if k := rows["Library/Developer/Xcode"]["kind"]; k != usageDev || rows["Library/Caches/pip"]["kind"] != usageDev {
		t.Errorf("Xcode's folder is in a row of kind %v", k)
	}
	top := func(rel, name string) map[string]any {
		for _, x := range rows[rel]["top"].([]any) {
			if x.(map[string]any)["name"] == name {
				return x.(map[string]any)
			}
		}
		t.Fatalf("%s has no %s in top: %v", rel, name, rows[rel]["top"])
		return nil
	}
	// what one of the row's things says: Docker's data in the row of removed apps, the models under ~/.ollama (its
	// own entry), a thing in the Trash
	if got := ids(top(docker, "Data")); got != "" {
		t.Errorf("what Docker left, in top: %q", got)
	}
	models := top(".ollama", "models")
	if got := ids(models); got != "ollama-rm@command" {
		t.Errorf("~/.ollama/models: %q", got)
	}
	if cmd := models["actions"].([]any)[0].(map[string]any)["command"]; cmd != "ollama rm <model>" {
		t.Errorf("ollama-rm's command: %v", cmd)
	}
	if got := ids(top(".Trash", "old-disk")); got != "" {
		t.Errorf("a thing in the Trash: %q", got)
	}
}

// Clones (luoke-scan#226): a row's bytes stay what its files add up to; exclusiveBytes is what deleting the row gives
// back (a group of clones all in the row once, a group with one elsewhere not at all, of a changed clone its own
// bytes), sharedBytes what it holds that files elsewhere hold too; the sum with shared blocks counted once is
// measuredBytes (listedBytes stays the listed rows' bytes added up). A row not looked at for sharing has null, and its bytes in shareUncheckedBytes.
func TestDataUsageCountsClonesOnce(t *testing.T) {
	c := newUsageCase(t)
	c.sizes(t, map[string]map[string]int64{
		"Models":             {c.day: 20000 * usageMB},
		"Projects":           {c.day: 5000 * usageMB},
		"Library/Caches/pip": {c.day: 3000 * usageMB},
		".cache/uv":          {c.day: 2000 * usageMB},
		"Movies":             {c.day: 4000 * usageMB},
	})
	group := func(count, size, refs int64) core.SpaceCloneGroup {
		return core.SpaceCloneGroup{Count: count, Bytes: count * size * usageMB, Size: size * usageMB, Refs: refs}
	}
	clones := map[string]core.SpaceClones{
		// two of a pair inside (8000 each), one of a pair with Projects (3000), 1000 plain
		c.path("Models"):   {Volume: "V", Groups: map[string]core.SpaceCloneGroup{"1": group(2, 8000, 2), "2": group(1, 3000, 2)}},
		c.path("Models/a"): {Volume: "V", Groups: map[string]core.SpaceCloneGroup{"1": group(1, 8000, 2)}},
		// the other of the pair, a changed clone (1000, 400 of its own), 1000 plain
		c.path("Projects"): {Volume: "V", Groups: map[string]core.SpaceCloneGroup{"2": group(1, 3000, 2)},
			LooseBytes: 1000 * usageMB, LoosePrivate: 400 * usageMB},
		// a pair across the two folders of one folded row; the volume did not say how many there are
		c.path("Library/Caches/pip"): {Volume: "V", Groups: map[string]core.SpaceCloneGroup{"3": group(1, 500, 0)}},
		c.path(".cache/uv"):          {Volume: "V", Groups: map[string]core.SpaceCloneGroup{"3": group(1, 500, 0)}, Unchecked: 7 * usageMB},
	}
	if err := core.SpaceClonesTable(c.s.Store).Apply(clones, nil, false); err != nil {
		t.Fatal(err)
	}
	measured := map[string]core.SpaceMeasured{c.path("Models/a"): {Bytes: 8000 * usageMB}, c.path("Models/b"): {Bytes: 12000 * usageMB}}
	if err := core.SpaceMeasuredTable(c.s.Store).Apply(measured, nil, false); err != nil {
		t.Fatal(err)
	}
	u, folders := c.folders(t)
	rows := map[string]map[string]any{}
	for _, f := range folders {
		rows[fmt.Sprint(f["kind"], " ", f["id"], " ", f["name"])] = f
	}
	mb := func(n int64) any { return float64(n * usageMB) }
	for name, want := range map[string][4]any{
		"folder <nil> Models":    {mb(20000), mb(9000), mb(3000), mb(0)},
		"folder <nil> Projects":  {mb(5000), mb(1400), mb(3600), mb(0)},
		"dev-caches <nil> <nil>": {mb(5000), mb(4500), mb(0), mb(7)},
		"known Movies <nil>":     {mb(4000), nil, nil, mb(4000)},
	} {
		f := rows[name]
		if f == nil {
			t.Fatalf("no row %q: %v", name, rows)
		}
		if got := [4]any{f["bytes"], f["exclusiveBytes"], f["sharedBytes"], f["shareUncheckedBytes"]}; got != want {
			t.Errorf("%s: bytes, exclusiveBytes, sharedBytes, shareUncheckedBytes %v, want %v", name, got, want)
		}
	}
	// 34000 measured; repeats: 8000 (the pair in Models), 3000 (Models and Projects), 500 (the caches), 300 (half of
	// what the changed clone shares)
	if u["listedBytes"] != mb(34000) || u["measuredBytes"] != mb(22200) || u["shareUncheckedBytes"] != mb(4007) {
		t.Errorf("listedBytes %v, measuredBytes %v, shareUncheckedBytes %v", u["listedBytes"], u["measuredBytes"], u["shareUncheckedBytes"])
	}
	if _, ok := u["measuredUniqueBytes"]; ok {
		t.Error("measuredUniqueBytes is given: measuredBytes is that number")
	}
	// the biggest things: a subfolder looked at has its own exclusiveBytes; one not looked at, and a file, null
	top := map[string]any{}
	for _, x := range rows["folder <nil> Models"]["top"].([]any) {
		top[x.(map[string]any)["name"].(string)] = x.(map[string]any)["exclusiveBytes"]
	}
	if e, ok := top["a"]; !ok || e != mb(0) {
		t.Errorf("Models/a: %v", top)
	}
	if e, ok := top["b"]; !ok || e != nil {
		t.Errorf("Models/b: %v", top)
	}
	top = map[string]any{}
	for _, x := range rows["dev-caches <nil> <nil>"]["top"].([]any) {
		top[x.(map[string]any)["name"].(string)] = x.(map[string]any)["exclusiveBytes"]
	}
	if top["pip"] != mb(2500) || top["uv"] != mb(1500) {
		t.Errorf("the folded row's folders: %v", top)
	}
}

// Hard links, on real ones: a 4 MiB file with a second name in another subfolder of the same row, and one with its
// second name in another row. A subfolder alone gives nothing back (the other name stays), the row that holds both
// names gives the file back once, and of the two rows that hold a name each neither gives anything back; the sum
// counts each file once.
func TestDataUsageOfAFileHardLinkedIntoAnotherFolder(t *testing.T) {
	c := newUsageCase(t)
	home := c.s.Config.Context.Home
	const size = 4 * usageMB
	file := func(rel string) string {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		return p
	}
	for _, pair := range [][2]string{{"envs/base/lib.bin", "envs/other/lib.bin"}, {"linked-here/x.bin", "linked-there/x.bin"}} {
		if err := os.WriteFile(file(pair[0]), bytes.Repeat([]byte{7}, int(size)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(file(pair[0]), file(pair[1])); err != nil {
			t.Skip("no hard links here: " + err.Error())
		}
	}
	ctx := c.s.Config.Context
	ctx.Store, ctx.Now, ctx.Tmp = c.s.Store, time.Now(), ""
	if _, err := core.NewSpaceRule(nil, nil).Run(&ctx); err != nil {
		t.Fatal(err)
	}
	u, folders := c.folders(t)
	want := map[string][3]any{ // bytes, exclusiveBytes, sharedBytes
		"envs":         {float64(2 * size), float64(size), float64(0)},
		"linked-here":  {float64(size), float64(0), float64(size)},
		"linked-there": {float64(size), float64(0), float64(size)},
	}
	seen := 0
	var others float64 // what else the case's home holds, a megabyte or more
	for _, f := range folders {
		name, _ := f["name"].(string)
		w, ok := want[name]
		if !ok {
			others += f["bytes"].(float64)
			continue
		}
		seen++
		if got := [3]any{f["bytes"], f["exclusiveBytes"], f["sharedBytes"]}; got != w || f["shareUncheckedBytes"] != float64(0) {
			t.Errorf("%s: bytes, exclusiveBytes, sharedBytes %v, want %v; shareUncheckedBytes %v", name, got, w, f["shareUncheckedBytes"])
		}
		if name != "envs" {
			continue
		}
		// each subfolder holds one name: deleting it alone gives nothing back
		top := map[string]any{}
		for _, x := range f["top"].([]any) {
			x := x.(map[string]any)
			top[x["name"].(string)] = [2]any{x["bytes"], x["exclusiveBytes"]}
		}
		for _, sub := range []string{"base", "other"} {
			if top[sub] != [2]any{float64(size), float64(0)} {
				t.Errorf("envs/%s: bytes, exclusiveBytes %v", sub, top[sub])
			}
		}
	}
	if seen != len(want) || u["more"] != float64(0) {
		t.Fatalf("%d of the three rows listed, %v more", seen, u["more"])
	}
	// four names of 4 MiB listed, two files on disk
	if u["listedBytes"] != others+float64(4*size) || u["measuredBytes"] != others+float64(2*size) {
		t.Errorf("listedBytes %v, measuredBytes %v; the rest of the home %v", u["listedBytes"], u["measuredBytes"], others)
	}
}

// The case of luoke-scan#226, on real clones (cp -c): one model file cloned into five folders. Each row's bytes stay
// the file's size, none of the rows would give anything back alone, and the five together count once.
func TestDataUsageOfAModelClonedIntoFiveFolders(t *testing.T) {
	c := newUsageCase(t)
	home := c.s.Config.Context.Home
	const size = 8 * usageMB
	names := []string{"models-a", "models-b", "models-c", "models-d", "models-e"}
	for i, n := range names {
		p := filepath.Join(home, n, "weights", "model.safetensors")
		os.MkdirAll(filepath.Dir(p), 0o755)
		if i == 0 {
			if err := os.WriteFile(p, bytes.Repeat([]byte{9}, int(size)), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if exec.Command("/bin/cp", "-c", filepath.Join(home, names[0], "weights", "model.safetensors"), p).Run() != nil {
			t.Skip("no clones here")
		}
	}
	ctx := c.s.Config.Context
	ctx.Store, ctx.Now, ctx.Tmp = c.s.Store, time.Now(), ""
	if _, err := core.NewSpaceRule(nil, nil).Run(&ctx); err != nil {
		t.Fatal(err)
	}
	if len(core.SpaceClonesTable(c.s.Store).Load()[c.path(names[0])].Groups) == 0 {
		t.Skip("the volume does not say which files share blocks")
	}
	u, folders := c.folders(t)
	seen := 0
	var others float64 // what else the case's home holds, a megabyte or more
	for _, f := range folders {
		name, _ := f["name"].(string)
		if !slices.Contains(names, name) {
			others += f["bytes"].(float64)
			continue
		}
		seen++
		if f["bytes"] != float64(size) || f["exclusiveBytes"] != float64(0) || f["sharedBytes"] != float64(size) ||
			f["shareUncheckedBytes"] != float64(0) {
			t.Errorf("%s: bytes %v, exclusiveBytes %v, sharedBytes %v, shareUncheckedBytes %v", name, f["bytes"], f["exclusiveBytes"],
				f["sharedBytes"], f["shareUncheckedBytes"])
		}
		top := f["top"].([]any)[0].(map[string]any)
		if top["name"] != "weights" || top["bytes"] != float64(size) || top["exclusiveBytes"] != float64(0) {
			t.Errorf("%s: its biggest thing %v", name, top)
		}
	}
	if seen != len(names) || u["more"] != float64(0) {
		t.Fatalf("%d of the five rows listed, %v more", seen, u["more"])
	}
	if u["listedBytes"] != others+float64(5*size) || u["measuredBytes"] != others+float64(size) {
		t.Errorf("listedBytes %v, measuredBytes %v; the rest of the home %v", u["listedBytes"], u["measuredBytes"], others)
	}
}
