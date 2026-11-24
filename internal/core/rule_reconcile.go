package core

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func init() { Register("space.reconcile", NewReconcileRule) }

// ReconcileRule sets what the disk says is used against what can be measured, and tells how much is left that nothing
// measured explains: space taken where only the system can look (the system's Spotlight index, local
// snapshots, document versions, the system's databases) shows nowhere in the folder sizes. What it found is kept
// (ReconcileTable) for data/usage; when the rest is large it is a finding, naming where it may be.
//
// Nothing is called unexplained while something that can be large for ordinary reasons was not measured (the home's
// guarded folders without Full Disk Access, another user's home, a round that ran out of time): then the round's
// figures are given as incomplete and there is no finding.
type ReconcileRule struct {
	// The rest is reported from this many bytes, or this fraction of the disk, whichever is larger.
	MinBytes    int64
	MinFraction float64
	// Budget: stop measuring outside the home after this long; what is left is measured first next round.
	Budget time.Duration
	// Reuse: a place outside the home is not walked again for this long.
	Reuse time.Duration
	// Disk is what the system says of the disk home is on; ok false when not known. nil: this Mac's.
	Disk func(home string) (DiskUse, bool)
	// Snapshots as SystemSpaceRule's. nil: this Mac's.
	Snapshots func() ([]time.Time, bool)
}

// DiskUse is what the system says of the disk (the APFS container) the home is on. Used is everything taken on it
// right now, the system's own volumes and what it says it could purge included (total less what can be written now).
type DiskUse struct {
	Total, Used int64
	// Purgeable: what the system says it could free when it gets to it (the Finder's free less what can be written
	// now; the same figure as space.low's purgeable). Counted in Used.
	Purgeable int64
	// System: the container's other volumes together (macOS itself, Preboot, Recovery) without the swap volume; Swap:
	// the swap volume (swap files and the sleep image). Known false: not known, then left out.
	System, Swap           int64
	SystemKnown, SwapKnown bool
}

// NewReconcileRule makes the rule; for a fake home the disk is its fakes' volume (no "used" there: not known).
func NewReconcileRule(l *Layout, f *Fakes) Rule {
	r := &ReconcileRule{MinBytes: 30 << 30, MinFraction: 0.05, Budget: 300 * time.Second, Reuse: 7 * 24 * time.Hour}
	if l != nil {
		v, snaps := f.Volume, f.Snapshots
		r.Disk = func(string) (DiskUse, bool) {
			if v == nil || v.Used == nil {
				return DiskUse{}, false
			}
			d := DiskUse{Total: v.Total, Used: *v.Used, Purgeable: v.Free - v.available()}
			if v.System != nil {
				d.System, d.SystemKnown = *v.System, true
			}
			if v.Swap != nil {
				d.Swap, d.SwapKnown = *v.Swap, true
			}
			return d, true
		}
		r.Snapshots = func() ([]time.Time, bool) {
			if snaps == nil {
				return nil, false
			}
			return *snaps, true
		}
	}
	return r
}

func (r *ReconcileRule) ID() string      { return "space.reconcile" }
func (r *ReconcileRule) Emits() []string { return []string{"space.unaccounted"} }

// The parts of the disk that are measured (ReconcilePart.ID).
const (
	PartHome         = "home"         // the user's home: the folders the space rule measures (clones and a file's names once), its loose files, the Trash
	PartApplications = "applications" // /Applications
	PartLibrary      = "library"      // /Library
	PartSystemData   = "system-data"  // what macOS keeps on the data volume (/System on it, software updates)
	PartPrivate      = "private"      // /private: the system's caches, logs, databases and temporary files it lets be read
	PartTools        = "tools"        // /opt, /usr/local: command-line tools (Homebrew)
	PartShared       = "shared"       // /Users/Shared
	PartOtherUsers   = "other-users"  // what could be read of other users' homes
	PartOther        = "other"        // anything else at the top of the data volume
	PartMacOS        = "macos"        // the container's other volumes: macOS itself, Preboot, Recovery
	PartSwap         = "swap"         // the swap volume
)

// What was not measured (ReconcileGap.ID).
const (
	GapHomeGuarded = "home-guarded"      // the home's guarded folders (Core.Guarded), without Full Disk Access
	GapHome        = "home"              // folders of the home the space rule did not get to this round
	GapTrash       = "trash"             // the Trash could not be listed, or the round had no time for it
	GapCloud       = "cloud-storage"     // the cloud apps' folder (~/Library/CloudStorage): no time for it, or part not listable
	GapVolume      = "volume"            // everything outside the home (not walked without Full Disk Access, or no time)
	GapOtherUsers  = "other-users"       // another user's home
	GapSpotlight   = "spotlight-index"   // the system's Spotlight index (/.Spotlight-V100): only root reads it
	GapVersions    = "document-versions" // the saved versions of documents (/.DocumentRevisions-V100)
	GapFSEvents    = "fsevents"          // the file system's change log (/.fseventsd)
	GapSystemDB    = "system-db"         // the system's databases (/private/var/db)
	GapSystemTemp  = "system-private"    // other folders of /private only the system reads
	GapSystemOther = "system-other"      // other folders only the system reads
)

// Why something was not measured (ReconcileGap.Why).
const (
	WhyRoot    = "root"    // only the system (root) can read it: what is in it shows up in the rest
	WhyAccess  = "fda"     // no Full Disk Access
	WhyPartial = "partial" // the round did not get to it
)

// ReconcilePart is one measured part of the disk.
type ReconcilePart struct {
	ID    string `json:"id"`
	Bytes int64  `json:"bytes"`
}

// ReconcileGap is something that was not measured. Open: it can be large for ordinary reasons, so with it the round
// cannot say what is unexplained.
type ReconcileGap struct {
	ID   string `json:"id"`
	Why  string `json:"why"`
	Open bool   `json:"open"`
}

// Reconcile is one round's account of the disk.
type Reconcile struct {
	Day       string          `json:"day"`
	Total     int64           `json:"total"`
	Used      int64           `json:"used"`
	Purgeable int64           `json:"purgeable"`
	Parts     []ReconcilePart `json:"parts"`
	Gaps      []ReconcileGap  `json:"gaps"`
	// Complete: no open gap. Unexplained (Used less the parts and Purgeable, not below 0) means something only then.
	Complete    bool  `json:"complete"`
	Unexplained int64 `json:"unexplained"`
	// Threshold: from how much the rest is reported.
	Threshold int64 `json:"threshold"`
	// Snapshots: Time Machine's local snapshots; -1 not known.
	Snapshots int `json:"snapshots"`
}

// Measured is what the parts come to.
func (a Reconcile) Measured() int64 {
	var sum int64
	for _, p := range a.Parts {
		sum += p.Bytes
	}
	return sum
}

// Over says whether the rest is worth a finding.
func (a Reconcile) Over() bool { return a.Complete && a.Unexplained >= a.Threshold }

// reconcileRow is the one row of ReconcileTable.
const reconcileRow = "last"

// ReconcileTable keeps the last round's account (row "last"), for data/usage.
func ReconcileTable(s *Store) Table[Reconcile] { return NewTable[Reconcile](s, "reconcile", 1) }

// LastReconcile is the last round's account; ok false when there is none.
func LastReconcile(s *Store) (Reconcile, bool) {
	if s == nil {
		return Reconcile{}, false
	}
	a, ok := ReconcileTable(s).Load()[reconcileRow]
	return a, ok
}

// reconcilePlace is the last measurement of a place outside the home: its size, what could not be listed in it.
type reconcilePlace struct {
	Bytes      int64     `json:"bytes"`
	Gaps       []string  `json:"gaps"`
	MeasuredAt time.Time `json:"measuredAt"`
}

func reconcilePlaces(s *Store) Table[reconcilePlace] {
	return NewTable[reconcilePlace](s, "reconcile_places", 1)
}

var containerOf = regexp.MustCompile(`^/dev/(disk\d+)s\d+`)

// swapVolume is where macOS mounts the volume its swap files and sleep image are on.
const swapVolume = "/System/Volumes/VM"

// volumeUsed is what the volume mounted at mount itself takes (getattrlist's ATTR_VOL_SPACEUSED: for an APFS volume
// its own share of the container, which statfs does not tell apart); ok false when not known.
func volumeUsed(mount string) (int64, bool) {
	al := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Volattr: unix.ATTR_VOL_INFO | unix.ATTR_VOL_SPACEUSED}
	buf := make([]byte, 16)
	if getattrlist(mount, &al, buf, 0) != nil || le32(buf, 0) < 12 {
		return 0, false
	}
	used := int64(le64(buf, 4))
	return used, used >= 0
}

// thisMacDisk: statfs gives the container's size and what it has left (for an APFS volume both are the container's);
// what the home's volume takes of it is asked of the volume itself, and the rest of what is used is the container's
// other volumes: the swap volume, asked the same way, and the system's own.
func thisMacDisk(home string) (DiskUse, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(home, &st) != nil || st.Blocks == 0 || st.Bavail > st.Blocks {
		return DiskUse{}, false
	}
	size := int64(st.Bsize)
	d := DiskUse{Total: int64(st.Blocks) * size, Used: int64(st.Blocks-st.Bavail) * size}
	if free, _, ok := volumeCapacity(home); ok {
		if p := free - int64(st.Bavail)*size; p > 0 {
			d.Purgeable = p
		}
	}
	container := containerOf.FindStringSubmatch(cString(st.Mntfromname[:]))
	own, ok := volumeUsed(cString(st.Mntonname[:]))
	if container == nil || !ok || own > d.Used {
		return d, true
	}
	others := d.Used - own
	var vm syscall.Statfs_t
	if syscall.Statfs(swapVolume, &vm) == nil && cString(vm.Mntonname[:]) == swapVolume {
		if c := containerOf.FindStringSubmatch(cString(vm.Mntfromname[:])); c != nil && c[1] == container[1] {
			if s, ok := volumeUsed(swapVolume); ok && s <= others {
				d.Swap, d.SwapKnown = s, true
				others -= s
			}
		}
	}
	d.System, d.SystemKnown = others, true
	return d, true
}

// countTree is the allocated size of the files under root (links not followed, other volumes not entered, folders
// skip names left out) and the folders in it that could not be listed. finished false when stop said so.
func countTree(root string, skip func(path string) bool, stop func() bool) (bytes int64, denied []string, finished bool) {
	top, ok := Item(root)
	if !ok || top.IsLink {
		return 0, nil, true
	}
	if !top.IsDir {
		return top.Bytes, nil, true
	}
	read := readFolderStat
	if bulkVolume(root) {
		read = readFolder
	}
	n := 0
	var walk func(dir string) bool
	walk = func(dir string) bool {
		var entries []Entry
		listed := false
		if mayOpen(dir) {
			entries, listed = read(dir)
		}
		if !listed {
			if Exists(dir) {
				denied = append(denied, dir)
			}
			return true
		}
		for _, e := range entries {
			n++
			if n%2000 == 0 && stop != nil && stop() {
				return false
			}
			switch {
			case e.IsLink:
			case !e.IsDir:
				bytes += e.Bytes
			case e.Device != top.Device || (skip != nil && skip(e.Path)):
			default:
				if !walk(e.Path) {
					return false
				}
			}
		}
		return true
	}
	finished = walk(root)
	return bytes, denied, finished
}

// volumeParts: which part a folder at the top of the data volume is counted in; "" not looked at (mount points).
var volumeParts = map[string]string{"Applications": PartApplications, "Library": PartLibrary, "System": PartSystemData,
	"MobileSoftwareUpdate": PartSystemData, "private": PartPrivate, "opt": PartTools, "usr": PartTools,
	"Volumes": "", "home": "", "dev": "", ".vol": "", "mnt": ""}

// gapOf names a folder that could not be listed, by where it is under the data volume (rel: its path from the top).
func gapOf(rel string) string {
	switch first := strings.SplitN(rel, "/", 2)[0]; {
	case first == ".Spotlight-V100":
		return GapSpotlight
	case first == ".DocumentRevisions-V100":
		return GapVersions
	case first == ".fseventsd":
		return GapFSEvents
	case first == "Users" && !strings.HasPrefix(rel, "Users/Shared/") && rel != "Users/Shared":
		return GapOtherUsers
	case rel == "private/var/db" || strings.HasPrefix(rel, "private/var/db/"):
		return GapSystemDB
	case first == "private":
		return GapSystemTemp
	}
	return GapSystemOther
}

// notOnThisMac says whether a folder is kept only by a cloud app (File Provider's dataless flag): it takes no room
// here, and listing it would have the cloud app fetch it. A variable for the tests.
var notOnThisMac = func(path string) bool {
	var st syscall.Stat_t
	return syscall.Lstat(path, &st) == nil && st.Flags&sfDataless != 0
}

// homeLoose is what the space rule's folders leave out of the home: the files directly in the home and in the folders
// it measures by their children, and the Trash. denied: some of the Trash could not be listed; finished false: stop
// said so partway. cloud: the cloud apps' folder (~/Library/CloudStorage) when it may be looked at; not measured here
// (it can be large and slow: measured as a place, see cloudStorage).
func homeLoose(ctx *Context, stop func() bool) (bytes int64, denied, finished bool, cloud string) {
	finished = true
	var walk func(rel string)
	walk = func(rel string) {
		base := ctx.Home
		if rel != "" {
			base = filepath.Join(ctx.Home, rel)
		}
		if !ctx.MayLook(base) {
			return
		}
		entries, ok := spaceListEntries(base, ctx.IsCancelled) // stopped: Run sees it right after and skips the round
		if !ok {
			return
		}
		for _, e := range entries {
			switch {
			case e.IsLink:
			case !e.IsDir:
				bytes += e.Bytes
			case rel == "Library" && e.Name == "CloudStorage":
				if ctx.MayLook(e.Path) {
					cloud = e.Path
				}
			case strings.HasPrefix(e.Name, ".Trash"):
				if !ctx.MayLook(e.Path) || !finished {
					continue
				}
				b, no, done := countTree(e.Path, nil, stop)
				bytes += b
				denied = denied || len(no) > 0
				finished = done
			case spaceSplit[rel][e.Name]:
				child := e.Name
				if rel != "" {
					child = rel + "/" + e.Name
				}
				walk(child)
			}
		}
	}
	walk("")
	return bytes, denied, finished, cloud
}

// How measuring a place went.
const (
	placeMeasured = iota // walked now, or its size is from within Reuse
	placeNoTime          // the round's time was up before or while walking it: its last size (0 without one) is given
)

// places are the sizes kept of what is walked outside the space rule's folders: each walked at most once in Reuse,
// and not at all once the round's time is up.
type places struct {
	table Table[reconcilePlace]
	known map[string]reconcilePlace
	seen  map[string]bool
}

// measure is the size of the place at path: its last one within Reuse, else walked now (skip leaves folders out;
// name says what a folder that could not be listed counts as). The walk stops when the round is cancelled (an error)
// or its time is up (placeNoTime, nothing kept of the half walk).
func (r *ReconcileRule) measure(ctx *Context, ps *places, path string, deadline time.Time, skip func(string) bool,
	name func(dir string) string) (reconcilePlace, int, error) {
	ps.seen[path] = true
	row, have := ps.known[path]
	if age := ctx.Now.Sub(row.MeasuredAt); have && age >= 0 && age < r.Reuse {
		return row, placeMeasured, nil
	}
	if ctx.IsCancelled() {
		return row, placeNoTime, Skip(Interrupted)
	}
	if time.Now().After(deadline) {
		return row, placeNoTime, nil
	}
	bytes, denied, finished := countTree(path, skip, func() bool { return ctx.IsCancelled() || time.Now().After(deadline) })
	if !finished {
		if ctx.IsCancelled() {
			return row, placeNoTime, Skip(Interrupted)
		}
		return row, placeNoTime, nil
	}
	ids := map[string]bool{}
	for _, dir := range denied {
		ids[name(dir)] = true
	}
	row = reconcilePlace{Bytes: bytes, Gaps: []string{}, MeasuredAt: ctx.Now}
	for id := range ids {
		row.Gaps = append(row.Gaps, id)
	}
	sort.Strings(row.Gaps)
	if err := ps.table.Apply(map[string]reconcilePlace{path: row}, nil, false); err != nil {
		return row, placeNoTime, Skip("数据写不进去：" + err.Error())
	}
	ps.known[path] = row
	return row, placeMeasured, nil
}

func (r *ReconcileRule) Run(ctx *Context) ([]Finding, error) {
	disk := r.Disk
	if disk == nil {
		disk = thisMacDisk
	}
	// No data volume to look at (a home given with --home: the disk it happens to be on is not its own): no account.
	d, ok := DiskUse{}, false
	if ctx.VolumeRoot != "" {
		d, ok = disk(ctx.Home)
	}
	if !ok || d.Total <= 0 || d.Used <= 0 {
		if ctx.Store != nil {
			ReconcileTable(ctx.Store).Apply(nil, []string{reconcileRow}, false)
		}
		return nil, nil
	}
	if ctx.Store == nil {
		return nil, Skip("没有数据目录，对不了账（--data）")
	}
	a := Reconcile{Day: ISODay(ctx.Now), Total: d.Total, Used: d.Used, Purgeable: max(0, d.Purgeable), Snapshots: -1}
	a.Threshold = max(r.MinBytes, int64(float64(d.Total)*r.MinFraction))
	parts := map[string]int64{}
	gaps := map[string]ReconcileGap{}
	gap := func(id, why string, open bool) {
		if g, ok := gaps[id]; !ok || (open && !g.Open) {
			gaps[id] = ReconcileGap{ID: id, Why: why, Open: open}
		}
	}
	noAccess := ctx.FullDiskAccess != nil && !*ctx.FullDiskAccess

	// The home: what the space rule measured this round (a folder it did not get to counts with its last size, and
	// the round is not complete), and what it leaves out.
	deadline := time.Now().Add(r.Budget)
	folders, left := SpaceWatched(ctx)
	sizes := spaceSizes(ctx.Store).Load()
	// The temporary folder is the space rule's too (it can hold a million entries: walked once a round, not twice).
	// It is in /private: counted there when the data volume is looked at, and left out of the walk of /private.
	tmpPart := ""
	if ctx.Tmp != "" && ctx.VolumeRoot != "" && !noAccess && onVolume(ctx, ctx.Tmp) != "" {
		tmpPart = PartPrivate
	}
	// A folder's size counts every clone and every name of a file in full. What the space rule remembered of the
	// files that share blocks (SpaceClonesTable) takes the repeats out of the home's sum, as data/usage's
	// measuredBytes does; a folder with nothing remembered counts in full.
	clones := SpaceClonesTable(ctx.Store).Load()
	var share SpaceCloneSum
	for _, f := range folders {
		part := PartHome
		if ctx.Tmp != "" && f == ctx.Tmp {
			if part = tmpPart; part == "" {
				continue
			}
		}
		row := sizes[Canonical(f)]
		if c, ok := clones[Canonical(f)]; ok && part == PartHome && len(row) > 0 {
			share.Add(c)
		}
		if b, ok := row[a.Day]; ok {
			parts[part] += b
			continue
		}
		// Never measured: one made since the space rule listed the home (a tool's new cache folder; a round takes
		// minutes), or one it had no time for. Measured here while there is time.
		if len(row) == 0 && time.Now().Before(deadline) {
			b, _, finished := countTree(f, nil, func() bool { return ctx.IsCancelled() || time.Now().After(deadline) })
			if finished {
				parts[part] += b
				continue
			}
			if ctx.IsCancelled() {
				return nil, Skip(Interrupted)
			}
		}
		gap(GapHome, WhyPartial, true)
		last := ""
		for day := range row {
			if day > last {
				last = day
			}
		}
		parts[part] += row[last]
	}
	parts[PartHome] = max(0, parts[PartHome]-share.Repeated())
	if left {
		gap(GapHomeGuarded, WhyAccess, true)
	}
	loose, trashDenied, trashDone, cloud := homeLoose(ctx, func() bool { return ctx.IsCancelled() || time.Now().After(deadline) })
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}
	parts[PartHome] += loose
	if trashDenied {
		why := WhyRoot
		if noAccess {
			why = WhyAccess
		}
		gap(GapTrash, why, true)
	}
	if !trashDone {
		gap(GapTrash, WhyPartial, true)
	}
	ps := &places{table: reconcilePlaces(ctx.Store), seen: map[string]bool{}}
	ps.known = ps.table.Load()
	// The cloud apps' folder: only what is on this Mac. A folder not downloaded takes no room here and is not listed
	// (listing it has the cloud app fetch it). Walked at most once in Reuse, like the places outside the home.
	if cloud != "" && !notOnThisMac(cloud) {
		row, state, err := r.measure(ctx, ps, cloud, deadline, notOnThisMac, func(string) string { return GapCloud })
		if err != nil {
			return nil, err
		}
		parts[PartHome] += row.Bytes
		if state == placeNoTime {
			gap(GapCloud, WhyPartial, true)
		}
		for range row.Gaps {
			gap(GapCloud, WhyRoot, false)
		}
	}

	// Outside the home: the folders at the top of the data volume. Not walked without Full Disk Access (the home is
	// not complete then anyway, and nothing outside it is opened that macOS might ask about).
	switch {
	case !Exists(ctx.VolumeRoot):
	case noAccess:
		gap(GapVolume, WhyAccess, true)
	default:
		if err := r.volume(ctx, ps, deadline, parts, gap); err != nil {
			return nil, err
		}
	}
	if d.SystemKnown {
		parts[PartMacOS] = d.System
	}
	if d.SwapKnown {
		parts[PartSwap] = d.Swap
	}

	for id, b := range parts {
		if b > 0 || id == PartHome {
			a.Parts = append(a.Parts, ReconcilePart{ID: id, Bytes: b})
		}
	}
	sort.Slice(a.Parts, func(i, j int) bool {
		if a.Parts[i].Bytes != a.Parts[j].Bytes {
			return a.Parts[i].Bytes > a.Parts[j].Bytes
		}
		return a.Parts[i].ID < a.Parts[j].ID
	})
	a.Complete = true
	a.Gaps = []ReconcileGap{}
	for _, g := range gaps {
		a.Gaps = append(a.Gaps, g)
		a.Complete = a.Complete && !g.Open
	}
	sort.Slice(a.Gaps, func(i, j int) bool { return a.Gaps[i].ID < a.Gaps[j].ID })
	a.Unexplained = max(0, a.Used-a.Measured()-a.Purgeable)
	snapshots := r.Snapshots
	if snapshots == nil {
		snapshots = thisMacSnapshots
	}
	if a.Over() {
		if dates, ok := snapshots(); ok {
			a.Snapshots = len(dates)
		}
	}
	if err := ReconcileTable(ctx.Store).Apply(map[string]Reconcile{reconcileRow: a}, nil, false); err != nil {
		return nil, Skip("数据写不进去：" + err.Error())
	}
	if !a.Over() {
		return nil, nil
	}
	return []Finding{r.finding(ctx, a)}, nil
}

// onVolume is where path is under the data volume looked at: the volume's top and the path with its links resolved
// (/var/folders/… is /private/var/folders/… there; Canonical drops that /private, so it is not used here). "" when it
// is not there.
func onVolume(ctx *Context, path string) string {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	if at := ctx.VolumeRoot + real; Exists(at) {
		return at
	}
	return ""
}

// volume measures the folders at the top of the data volume into parts, each at most once in Reuse; what cannot be
// listed in them goes to gap. A place the round has no time left for keeps its last size, and the round is not
// complete.
func (r *ReconcileRule) volume(ctx *Context, ps *places, deadline time.Time, parts map[string]int64,
	gap func(id, why string, open bool)) error {
	root := ctx.VolumeRoot
	entries, ok := spaceListEntries(root, ctx.IsCancelled)
	if !ok {
		if ctx.IsCancelled() { // stopped while listing: not a place that cannot be listed
			return Skip(Interrupted)
		}
		gap(GapVolume, WhyRoot, true)
		return nil
	}
	tmp := ""
	if ctx.Tmp != "" {
		tmp = onVolume(ctx, ctx.Tmp)
	}
	// What is measured elsewhere and left out of the walk: the home, and the temporary folder (the space rule's).
	isHome := func(path string) bool {
		if tmp != "" && path == tmp {
			return true
		}
		low := strings.ToLower(path)
		for _, s := range ctx.spellings() {
			if low == s {
				return true
			}
		}
		return false
	}
	type place struct{ path, part string }
	var list []place
	for _, e := range entries {
		part, known := volumeParts[e.Name]
		switch {
		case e.IsLink || (known && part == ""):
		case !e.IsDir:
			parts[PartOther] += e.Bytes
		case e.Name == "Users":
			users, ok := spaceListEntries(e.Path, ctx.IsCancelled)
			if !ok {
				if ctx.IsCancelled() {
					return Skip(Interrupted)
				}
				gap(GapOtherUsers, WhyRoot, true)
				continue
			}
			for _, u := range users {
				switch {
				case u.IsLink || isHome(u.Path):
				case !u.IsDir:
					parts[PartOther] += u.Bytes
				case u.Name == "Shared":
					list = append(list, place{u.Path, PartShared})
				default:
					list = append(list, place{u.Path, PartOtherUsers})
				}
			}
		case known:
			list = append(list, place{e.Path, part})
		default:
			list = append(list, place{e.Path, PartOther})
		}
	}
	// Never measured first, then the ones measured longest ago.
	sort.SliceStable(list, func(i, j int) bool {
		return ps.known[list[i].path].MeasuredAt.Before(ps.known[list[j].path].MeasuredAt)
	})
	name := func(dir string) string {
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return GapSystemOther
		}
		return gapOf(rel)
	}
	for _, p := range list {
		row, state, err := r.measure(ctx, ps, p.path, deadline, isHome, name)
		if err != nil {
			return err
		}
		if state == placeNoTime {
			gap(GapVolume, WhyPartial, true)
		}
		parts[p.part] += row.Bytes
		for _, id := range row.Gaps {
			// Another user's home can be as large as this one: with it unread nothing can be called unexplained.
			gap(id, WhyRoot, id == GapOtherUsers)
		}
	}
	// What is no longer there (a folder gone from the top of the volume, the cloud apps' folder) is forgotten.
	var gone []string
	for path := range ps.known {
		if !ps.seen[path] {
			gone = append(gone, path)
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		ps.table.Apply(nil, gone, false)
	}
	return nil
}

// gapNames: how the finding names what only the system can read.
var gapNames = map[string]string{GapSpotlight: "系统的 Spotlight 索引（/.Spotlight-V100）", GapVersions: "文稿的历史版本（/.DocumentRevisions-V100）",
	GapFSEvents: "文件改动记录（/.fseventsd）", GapSystemDB: "系统的数据库（/private/var/db）", GapSystemTemp: "系统的缓存和临时文件（/private 里只有系统能看的）",
	GapSystemOther: "别的只有系统能看的文件夹"}

func (r *ReconcileRule) finding(ctx *Context, a Reconcile) Finding {
	measured := a.Measured()
	var where, ids []string
	spotlight := false
	// The Spotlight index first: the one the request names (said to grow very large when it is damaged; not verified).
	order := []string{GapSpotlight, GapVersions, GapSystemDB, GapSystemTemp, GapFSEvents, GapSystemOther}
	have := map[string]bool{}
	for _, g := range a.Gaps {
		have[g.ID] = true
		ids = append(ids, g.ID)
	}
	for _, id := range order {
		if have[id] {
			where = append(where, gapNames[id])
			spotlight = spotlight || id == GapSpotlight
		}
	}
	switch {
	case a.Snapshots > 0:
		where = append(where, fmt.Sprintf("本地快照（现在有 %d 个 Time Machine 的）", a.Snapshots))
	case a.Snapshots < 0:
		where = append(where, "本地快照")
	}
	why := fmt.Sprintf("硬盘已用 %s，量得到的加起来 %s", FormatBytes(a.Used), FormatBytes(measured))
	if a.Purgeable > 0 {
		why += "，系统说可以清除的 " + FormatBytes(a.Purgeable)
	}
	why += "，还差 " + FormatBytes(a.Unexplained) + " 对不上"
	if len(where) > 0 {
		why += "。扫描量不了、可能占着它的地方：" + strings.Join(where, "、")
	}
	ev := map[string]string{"used": FormatBytes(a.Used), "measured": FormatBytes(measured), "unexplained": FormatBytes(a.Unexplained),
		"threshold": FormatBytes(a.Threshold), "used_bytes": strconv.FormatInt(a.Used, 10),
		"measured_bytes": strconv.FormatInt(measured, 10), "purgeable_bytes": strconv.FormatInt(a.Purgeable, 10),
		"unexplained_bytes": strconv.FormatInt(a.Unexplained, 10), "unmeasured": strings.Join(ids, ","), "why": why,
		"how": "在「系统设置 → 通用 → 储存空间」里看「系统数据」有多大。怀疑是 Spotlight 的索引时可以让系统重建它：" +
			"系统设置 → Spotlight → 搜索隐私，把这块硬盘加进去再移除；或者在终端运行 sudo mdutil -E /（要管理员密码）。" +
			"重建要一段时间，这期间搜索不全。扫描不会自己做这件事"}
	if spotlight {
		ev["spotlight"] = "unmeasured"
	}
	if a.Purgeable > 0 {
		ev["purgeable"] = FormatBytes(a.Purgeable)
	}
	if a.Snapshots >= 0 {
		ev["snapshots"] = strconv.Itoa(a.Snapshots)
	}
	return Finding{Rule: "space.unaccounted", Category: CatSpace, Severity: Low, Verdict: Info, Path: ctx.Home,
		Bytes: Size(a.Unexplained), Title: "硬盘上有 " + FormatBytes(a.Unexplained) + " 说不清是谁占的", Evidence: ev}
}
