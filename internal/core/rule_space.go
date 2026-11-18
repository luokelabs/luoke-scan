package core

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() {
	Register("space.low", NewFreeSpaceRule)
	Register("space", NewSpaceRule)
}

// FreeSpaceRule reports low free space, with the swap size as context (swap grows fast under memory pressure, e.g.
// when several local model jobs run at once, and eats the same disk). Its own rule so it reports even without history.
type FreeSpaceRule struct {
	// Free space below this is reported (bytes, or the fraction of the volume, whichever is larger).
	MinFreeBytes    int64
	MinFreeFraction float64
	// Volume is the free and total bytes of the volume home is on; ok false when not known. nil: this Mac's.
	Volume func(home string) (free, total int64, ok bool)
	// Swap is the bytes of swap in use; ok false when not known. nil: this Mac's.
	Swap func() (int64, bool)
}

// NewFreeSpaceRule makes the rule; for a fake home the volume and swap are its fakes'.
func NewFreeSpaceRule(l *Layout, f *Fakes) Rule {
	r := &FreeSpaceRule{MinFreeBytes: 20 << 30, MinFreeFraction: 0.10}
	if l != nil {
		v := f.Volume
		r.Volume = func(string) (int64, int64, bool) {
			if v == nil {
				return 0, 0, false
			}
			return v.Free, v.Total, true
		}
		r.Swap = func() (int64, bool) {
			if v == nil || v.Swap == nil {
				return 0, false
			}
			return *v.Swap, true
		}
	}
	return r
}

func (r *FreeSpaceRule) ID() string      { return "space.low" }
func (r *FreeSpaceRule) Emits() []string { return []string{"space.low"} }

func (r *FreeSpaceRule) Run(ctx *Context) ([]Finding, error) {
	volume, swap := r.Volume, r.Swap
	if volume == nil {
		volume = volumeCapacity
	}
	if swap == nil {
		swap = swapUsed
	}
	free, total, ok := volume(ctx.Home)
	if !ok || total <= 0 {
		return nil, nil
	}
	floor := r.MinFreeBytes
	if f := int64(float64(total) * r.MinFreeFraction); f > floor {
		floor = f
	}
	if free >= floor {
		return nil, nil
	}
	// total_bytes, swap_bytes: the same as numbers, for what is drawn from data (the service's spaceData)
	ev := map[string]string{"free": FormatBytes(free), "total": FormatBytes(total), "threshold": FormatBytes(floor),
		"total_bytes": strconv.FormatInt(total, 10)}
	if s, ok := swap(); ok {
		ev["swap"] = FormatBytes(s)
		ev["swap_bytes"] = strconv.FormatInt(s, 10)
	}
	return []Finding{{Rule: "space.low", Category: CatSpace, Severity: Medium, Verdict: Info, Path: ctx.Home, Bytes: Size(free),
		Title: "可用空间只剩 " + FormatBytes(free), Evidence: ev}}, nil
}

// importantCapacity is the volume's "available capacity for important usage" (purgeable space counted, as Finder
// does) and its total; set by the cgo file. ok false: not known, then statfs's available blocks.
var importantCapacity = func(path string) (int64, int64, bool) { return 0, 0, false }

// volumeCapacity is this Mac's free and total bytes of the volume home is on.
// VolumeCapacity is the free and total bytes of the volume home is on (the 「状态」 page reads it when drawn).
func VolumeCapacity(home string) (int64, int64, bool) { return volumeCapacity(home) }

func volumeCapacity(home string) (int64, int64, bool) {
	return mergeCapacity(importantCapacity, statfsCapacity, home)
}

// statfsCapacity is the available and total bytes statfs gives for the volume path is on.
func statfsCapacity(path string) (int64, int64, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return 0, 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), true
}

// mergeCapacity takes the "important usage" figure when it is known, but never less than what statfs says is
// available: purgeable space only adds to it. The system answers 0 for important usage to a process without a
// graphical session (over ssh, a job started outside the login session); taken as it is, that reads as a full disk.
func mergeCapacity(important, plain func(string) (int64, int64, bool), path string) (int64, int64, bool) {
	free, total, ok := important(path)
	avail, all, plainOK := plain(path)
	switch {
	case ok && plainOK && free < avail:
		return avail, total, true
	case ok:
		return free, total, true
	case plainOK:
		return avail, all, true
	}
	return 0, 0, false
}

// swapUsed is the bytes of swap in use (vm.swapusage), or ok false.
func swapUsed() (int64, bool) {
	s, err := syscall.Sysctl("vm.swapusage")
	if err != nil || len(s) < 24 {
		return 0, false
	}
	// struct xsw_usage { u_int64_t xsu_total, xsu_avail, xsu_used; ... }
	return int64(binary.LittleEndian.Uint64([]byte(s[16:24]))), true
}

// SpaceRule finds where the space goes and what keeps growing. Records today's size of the watched folders, then
// compares with the history: something that grows by gigabytes a day is worth pointing at, whatever it is.
type SpaceRule struct {
	// MinGrowthPerDay is the growth worth reporting.
	MinGrowthPerDay int64
	// Window: look back this many days for the baseline.
	Window int
	// Budget: stop measuring after this long; what is left is reported as not measured (and measured first next round).
	Budget time.Duration
	// Journal: what changed since a folder was last measured (FSEvents), and how long a size found unchanged is reused.
	Journal JournalSource
	// SplitDepth: how many levels below a watched folder sizes are remembered, so a big folder that changed is walked
	// again only where it changed (one busy repo in ~/Documents, not all of ~/Documents).
	SplitDepth int
	// RememberAbove: subfolders smaller than this are not remembered on their own (walking them again is cheap).
	RememberAbove int64
}

// NewSpaceRule makes the rule; for a fake home growth counts from 1 MiB a day.
func NewSpaceRule(l *Layout, f *Fakes) Rule {
	r := &SpaceRule{MinGrowthPerDay: 1 << 30, Window: 7, Budget: 600 * time.Second, Journal: NewJournalSource(), SplitDepth: 2,
		RememberAbove: 1 << 20}
	if l != nil {
		r.MinGrowthPerDay = 1 << 20
	}
	return r
}

func (r *SpaceRule) ID() string      { return "space" }
func (r *SpaceRule) Emits() []string { return []string{"space"} }

// spaceSplit are the folders measured by their children, not whole: where apps and tools keep their data.
var spaceSplit = map[string]map[string]bool{
	"":        spaceSet("Library", ".cache", ".local"),
	"Library": spaceSet("Caches", "Application Support", "Containers", "Developer"),
	".local":  spaceSet("share"),
}

// SpaceWatched are the folders measured each round: home's direct children, with the ones where apps and tools keep
// their data split one level further (split, not nested: a folder is measured whole or by its children, never both),
// and the temp folder. left: some were not looked at for want of Full Disk Access.
func SpaceWatched(ctx *Context) (folders []string, left bool) {
	folders, _, left = spaceWatching(ctx)
	return folders, left
}

// spaceWatching is SpaceWatched, and the split folders that could not be listed this round (canonical paths): what is
// remembered under them is kept, not forgotten as "no longer there". Without Full Disk Access the guarded folders are
// not listed or measured (left), and what is remembered of them is kept the same way.
func spaceWatching(ctx *Context) (folders, unlisted []string, left bool) {
	var out []string
	home := Canonical(ctx.Home)
	var walk func(rel string)
	walk = func(rel string) {
		base := ctx.Home
		if rel != "" {
			base = filepath.Join(ctx.Home, rel)
		}
		if !ctx.MayLook(base) {
			left = true
			unlisted = append(unlisted, home+"/"+rel)
			return
		}
		items, ok := List(base)
		if !ok {
			if Exists(base) {
				unlisted = append(unlisted, Canonical(base))
			}
			return
		}
		for _, u := range items {
			name := filepath.Base(u)
			// CloudStorage: files a cloud app (Dropbox, OneDrive…) manages, mostly not on this disk. Never measured.
			if strings.HasPrefix(name, ".Trash") || (rel == "Library" && name == "CloudStorage") {
				continue
			}
			child := name
			if rel != "" {
				child = rel + "/" + name
			}
			if !ctx.MayLook(u) {
				left = true
				unlisted = append(unlisted, home+"/"+child)
				continue
			}
			if spaceSplit[rel][name] {
				walk(child)
			} else {
				out = append(out, u)
			}
		}
	}
	walk("")
	if ctx.Tmp != "" {
		out = append(out, ctx.Tmp)
	}
	for _, u := range out {
		if spaceIsDir(u) {
			folders = append(folders, u)
		}
	}
	return folders, unlisted, left
}

// SpaceSizes is the size history the space rule keeps (canonical path → day → bytes), for the 「状态」 page.
func SpaceSizes(s *Store) map[string]map[string]int64 { return spaceSizes(s).Load() }

// spaceSizes is the size history: path → day → bytes.
func spaceSizes(s *Store) Table[map[string]int64] { return NewTable[map[string]int64](s, "sizes", 1) }

// SpaceMeasured is the last full measurement of a folder: the journal's event id just before it was measured, its
// inode, its size.
type SpaceMeasured struct {
	// EventID: known unchanged up to this journal event id.
	EventID uint64 `json:"eventID"`
	Inode   uint64 `json:"inode"`
	Bytes   int64  `json:"bytes"`
	// MeasuredAt is when the folder was last actually walked (not just found unchanged).
	MeasuredAt time.Time `json:"measuredAt"`
}

// SpaceMeasuredTable keeps SpaceMeasured by canonical path.
func SpaceMeasuredTable(s *Store) Table[SpaceMeasured] {
	return NewTable[SpaceMeasured](s, "measured", 1)
}

// SpaceFile is one of the biggest files directly in a measured folder: its name and allocated size.
type SpaceFile struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

// spaceTopFiles: how many of a measured folder's own files are remembered (the biggest, from RememberAbove up).
const spaceTopFiles = 5

// SpaceTopFilesTable keeps, by a measured folder's canonical path, the biggest files directly in it as they were when
// it was last walked (data/usage: what is in a folder, beside the subfolders in SpaceMeasuredTable).
func SpaceTopFilesTable(s *Store) Table[[]SpaceFile] {
	return NewTable[[]SpaceFile](s, "topfiles", 1)
}

func sameSpaceFiles(a, b []SpaceFile) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// spaceListEntries are a folder's entries (not following links), in the file system's order; ok false when it cannot
// be listed.
func spaceListEntries(dir string) ([]Entry, bool) {
	if !mayOpen(dir) {
		return nil, false
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil && len(names) == 0 {
		return nil, false
	}
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		if e, ok := Item(dir + "/" + n); ok {
			out = append(out, e)
		}
	}
	return out, true
}

func (r *SpaceRule) Run(ctx *Context) ([]Finding, error) {
	if ctx.Store == nil {
		return nil, Skip("没有数据目录，算不了增长（--data）")
	}
	store := ctx.Store
	day := ISODay(ctx.Now)
	// Incremental: a folder nothing changed in since it was last measured (same inode, no FSEvents under it) keeps that
	// size; only the rest is walked. Taken before measuring, so changes made meanwhile count next round. A size is never
	// reused for more than MaxReuse: the journal can lose history (purged when the disk fills, turned off for a volume)
	// without telling.
	measuredTable := SpaceMeasuredTable(store)
	known := measuredTable.Load()
	roots := []string{ctx.Home}
	if ctx.Tmp != "" {
		roots = append(roots, ctx.Tmp)
	}
	folders, unlisted, left := spaceWatching(ctx)
	type watchedFolder struct{ path, key string }
	watched := make([]watchedFolder, 0, len(folders))
	tops := map[string]bool{}
	for _, p := range folders {
		w := watchedFolder{p, Canonical(p)}
		watched = append(watched, w)
		tops[w.key] = true
	}
	// Replay from the oldest watched folder: a subfolder is unchanged at least as long as its folder was.
	var ids []uint64
	for k, m := range known {
		if tops[k] {
			ids = append(ids, m.EventID)
		}
	}
	inc, err := BeginIncrement(ctx, "fsevents.journal", roots, minEventID(ids), r.Journal, func() error {
		known = map[string]SpaceMeasured{}
		return measuredTable.Apply(nil, nil, true)
	})
	if err != nil {
		return nil, err
	}
	start, changes, verified := inc.Start, inc.Changes, inc.Verified()
	deadline := time.Now().Add(r.Budget)
	sizes := map[string]int64{}
	unmeasured, reused := 0, 0
	rows := map[string]SpaceMeasured{}
	// Folders whose contents were listed; subfolders found there; remembered subfolders now too small to remember
	// (their old size must go).
	listed, seen, dropped := map[string]bool{}, map[string]bool{}, map[string]bool{}

	unchanged := func(key string, ino uint64, floor uint64) (SpaceMeasured, bool) {
		k, ok := known[key]
		if !ok || k.Inode != ino || !r.Journal.Reusable(k.MeasuredAt, ctx.Now) || changes.Touched(key, max(k.EventID, floor)) {
			return SpaceMeasured{}, false
		}
		return k, true
	}

	// One watched folder's walk: what it found goes into these, and into the round's only when it finished.
	var wRows map[string]SpaceMeasured
	var wFiles []SpaceFile // the watched folder's own files from RememberAbove up (not its subfolders')
	topFiles := map[string][]SpaceFile{}
	var wListed, wSeen, wDropped map[string]bool
	// measure is the size of path, walking only the subfolders (down to depth levels) that changed, and the oldest
	// real measurement inside it (reused sizes keep their age, so the 7-day limit holds for them too). floor: the
	// folder's own event id from before this round. ok false when the round was cancelled meanwhile.
	var measure func(path, key string, depth int, floor uint64, volume *int32) (int64, time.Time, bool)
	measure = func(path, key string, depth int, floor uint64, volume *int32) (int64, time.Time, bool) {
		var items []Entry
		ok := false
		if depth > 0 {
			items, ok = spaceListEntries(path)
		}
		if !ok {
			f, ok := WalkFacts(path, time.Time{}, ctx.IsCancelled)
			return f.Bytes, ctx.Now, ok
		}
		wListed[key] = true
		var total int64
		oldest := ctx.Now
		for _, e := range items {
			if ctx.IsCancelled() {
				return 0, time.Time{}, false
			}
			if e.IsLink {
				continue
			}
			if !e.IsDir {
				total += e.Bytes
				if depth == r.SplitDepth && e.Bytes >= r.RememberAbove {
					wFiles = append(wFiles, SpaceFile{Name: e.Name, Bytes: e.Bytes})
				}
				continue
			}
			ck := key + "/" + e.Name
			// A folder another volume is mounted on lists with the covered folder's device; lstat sees the mount.
			if volume != nil && e.Device != *volume {
				continue
			}
			ino := Inode(e.Path)
			wSeen[ck] = true
			if k, ok := unchanged(ck, ino, floor); ok {
				total += k.Bytes
				if k.MeasuredAt.Before(oldest) {
					oldest = k.MeasuredAt
				}
				if id := max(k.EventID, floor, verified); id > k.EventID {
					wRows[ck] = SpaceMeasured{EventID: id, Inode: ino, Bytes: k.Bytes, MeasuredAt: k.MeasuredAt}
				}
				continue
			}
			sub := floor
			if k, ok := known[ck]; ok {
				sub = max(k.EventID, floor)
			}
			b, o, ok := measure(e.Path, ck, depth-1, sub, volume)
			if !ok {
				return 0, time.Time{}, false
			}
			total += b
			if o.Before(oldest) {
				oldest = o
			}
			if b >= r.RememberAbove {
				wRows[ck] = SpaceMeasured{EventID: start, Inode: ino, Bytes: b, MeasuredAt: o}
			} else if _, ok := known[ck]; ok {
				wDropped[ck] = true
			}
		}
		return total, oldest, true
	}

	// Never measured first, then the ones measured longest ago: a folder skipped last time is not skipped again, and
	// the oldest event id (where the next replay starts) keeps moving forward.
	var fresh, old []watchedFolder
	for _, w := range watched {
		if _, ok := known[w.key]; ok {
			old = append(old, w)
		} else {
			fresh = append(fresh, w)
		}
	}
	sort.SliceStable(old, func(i, j int) bool { return known[old[i].key].EventID < known[old[j].key].EventID })
	interrupted := false
	for _, w := range append(fresh, old...) {
		ino := Inode(w.path)
		if k, ok := unchanged(w.key, ino, 0); ok {
			sizes[w.key] = k.Bytes
			reused++
			if verified > k.EventID {
				rows[w.key] = SpaceMeasured{EventID: verified, Inode: ino, Bytes: k.Bytes, MeasuredAt: k.MeasuredAt}
			}
			continue
		}
		if ctx.IsCancelled() {
			interrupted = true
			unmeasured++
			continue
		}
		if time.Now().After(deadline) {
			unmeasured++
			continue
		}
		var volume *int32
		if e, ok := Item(w.path); ok {
			volume = &e.Device
		}
		wRows, wListed, wSeen, wDropped = map[string]SpaceMeasured{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
		wFiles = nil
		bytes, oldest, ok := measure(w.path, w.key, r.SplitDepth, known[w.key].EventID, volume)
		if !ok {
			// Not finished: nothing under it is written, so no subfolder is remembered without its folder, and nothing
			// under it is forgotten either (what the walk did not reach was not found gone).
			interrupted = true
			unmeasured++
			continue
		}
		for k, v := range wRows {
			rows[k] = v
		}
		for _, m := range []struct{ from, to map[string]bool }{{wListed, listed}, {wSeen, seen}, {wDropped, dropped}} {
			for k := range m.from {
				m.to[k] = true
			}
		}
		sizes[w.key] = bytes
		rows[w.key] = SpaceMeasured{EventID: start, Inode: ino, Bytes: bytes, MeasuredAt: oldest}
		sort.Slice(wFiles, func(i, j int) bool {
			if wFiles[i].Bytes != wFiles[j].Bytes {
				return wFiles[i].Bytes > wFiles[j].Bytes
			}
			return wFiles[i].Name < wFiles[j].Name
		})
		if len(wFiles) > spaceTopFiles {
			wFiles = wFiles[:spaceTopFiles]
		}
		topFiles[w.key] = append([]SpaceFile{}, wFiles...) // walked again: what was remembered of its files is replaced
		// One batch per folder: what is done survives an interruption.
		if err := measuredTable.Apply(rows, nil, false); err != nil {
			return nil, Skip("数据写不进去：" + err.Error())
		}
		rows = map[string]SpaceMeasured{}
	}
	// Forget folders no longer watched, subfolders deeper than remembered, subfolders gone from a folder listed this
	// round, and the ones now too small. A subfolder of one found unchanged keeps what is under it, and so does
	// everything under a folder that could not be listed this round.
	var gone []string
	for path := range known {
		if tops[path] {
			continue
		}
		under := false
		for _, u := range unlisted {
			under = under || path == u || strings.HasPrefix(path, u+"/")
		}
		if under {
			continue
		}
		if dropped[path] {
			gone = append(gone, path)
			continue
		}
		parent := filepath.Dir(path)
		up, level := parent, 1
		for !tops[up] && level < r.SplitDepth && len(up) > 1 {
			up = filepath.Dir(up)
			level++
		}
		if !tops[up] || (listed[parent] && !seen[path]) {
			gone = append(gone, path)
		}
	}
	sort.Strings(gone)
	// The biggest files: of folders walked this round as found; of folders found unchanged, as remembered; of folders
	// no longer watched, forgotten (kept under what could not be listed, like the sizes).
	topTable := SpaceTopFilesTable(store)
	topKnown := topTable.Load()
	for k, files := range topFiles { // the same as remembered: not written again
		if old, ok := topKnown[k]; ok && sameSpaceFiles(old, files) {
			delete(topFiles, k)
		}
	}
	var topGone []string
	for path := range topKnown {
		under := false
		for _, u := range unlisted {
			under = under || path == u || strings.HasPrefix(path, u+"/")
		}
		if !tops[path] && !under {
			topGone = append(topGone, path)
		}
	}
	sort.Strings(topGone)

	table := spaceSizes(store)
	history := table.Load()
	set := map[string]map[string]int64{}
	for k, b := range sizes {
		row := map[string]int64{}
		for d, v := range history[k] {
			row[d] = v
		}
		row[day] = b
		history[k], set[k] = row, row
	}
	if interrupted {
		// What was measured is kept for the next round; this round's space findings come from the last full one. The
		// interruption is what counts: a failed write must not turn it into an error (then nothing is carried).
		measuredTable.Apply(rows, nil, false)
		measuredTable.Apply(nil, gone, false)
		topTable.Apply(topFiles, nil, false)
		table.Apply(set, nil, false)
		return nil, Skip(Interrupted)
	}
	if err := measuredTable.Apply(rows, nil, false); err != nil {
		return nil, Skip("数据写不进去：" + err.Error())
	}
	if err := measuredTable.Apply(nil, gone, false); err != nil {
		return nil, Skip("数据写不进去：" + err.Error())
	}
	if len(topFiles) > 0 || len(topGone) > 0 {
		if err := topTable.Apply(topFiles, topGone, false); err != nil {
			return nil, Skip("数据写不进去：" + err.Error())
		}
	}
	cut := ISODay(ctx.Now.Add(-90 * 24 * time.Hour))
	var del []string
	for k, row := range history {
		pruned := map[string]int64{}
		for d, v := range row {
			if d >= cut {
				pruned[d] = v
			}
		}
		switch {
		case len(pruned) == 0:
			del = append(del, k)
			delete(set, k)
			delete(history, k)
		case len(pruned) != len(row):
			history[k], set[k] = pruned, pruned
		}
	}
	if err := table.Apply(set, del, false); err != nil {
		return nil, Skip("数据写不进去：" + err.Error())
	}

	var out []Finding
	since := ISODay(ctx.Now.Add(-time.Duration(r.Window) * 24 * time.Hour))
	paths := make([]string, 0, len(sizes))
	for p := range sizes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		now := sizes[path]
		base := ""
		for d := range history[path] {
			if d >= since && d < day && (base == "" || d < base) {
				base = d
			}
		}
		if base == "" {
			continue
		}
		then := history[path][base]
		days := max(1, spaceDayDistance(base, day))
		perDay := (now - then) / int64(days)
		if perDay < r.MinGrowthPerDay {
			continue
		}
		out = append(out, Finding{Rule: "space.growth", Category: CatSpace, Severity: Medium, Verdict: Info, Path: path, Bytes: Size(now),
			Title: DisplayName(path) + " 每天涨 " + FormatBytes(perDay),
			Evidence: map[string]string{"since": base, "then": FormatBytes(then), "now": FormatBytes(now), "per_day": FormatBytes(perDay),
				"hint": "找出是谁在往这里写：一直这样涨，清一次也很快又满"}})
	}
	if unmeasured > 0 {
		why := "这一轮的时间用完了"
		if ctx.IsCancelled() {
			why = "这一轮被打断了"
		}
		out = append(out, Finding{Rule: "space.partial", Category: CatSpace, Severity: Low, Verdict: Info, Path: ctx.Home,
			Title: fmt.Sprintf("这一轮还有 %d 个文件夹没量，下一轮先量它们", unmeasured),
			Evidence: map[string]string{"budget_seconds": strconv.Itoa(int(r.Budget.Seconds())), "reused": strconv.Itoa(reused),
				"why": why}})
	}
	if left {
		return nil, Skip(NotLooked("桌面、文稿、下载和别的应用的数据占多大"), out...)
	}
	return out, nil
}

// spaceDayDistance is the number of days from day a to day b (yyyy-MM-dd, this Mac's time zone), rounded; 1 when
// either cannot be read.
func spaceDayDistance(a, b string) int {
	x, err1 := time.ParseInLocation("2006-01-02", a, time.Local)
	y, err2 := time.ParseInLocation("2006-01-02", b, time.Local)
	if err1 != nil || err2 != nil {
		return 1
	}
	return int(math.Round(y.Sub(x).Hours() / 24))
}
