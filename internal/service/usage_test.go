package service

import (
	"os"
	"path/filepath"
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
