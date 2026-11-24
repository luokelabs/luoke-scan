package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reconcileCase is a home with two measured folders, a loose file and something in the Trash, and a data volume with
// apps, another user's home (readable) and the system's Spotlight index, which cannot be listed.
type reconcileCase struct {
	ctx  Context
	rule *ReconcileRule
	used int64
	root string
}

func reconcileFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newReconcileCase(t *testing.T) *reconcileCase {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "volume", "Users", "me")
	for path, size := range map[string]int{
		home + "/Documents/a.bin": 64 << 10, home + "/Projects/b.bin": 32 << 10, home + "/loose.bin": 16 << 10,
		home + "/.Trash/old.bin": 8 << 10, home + "/Library/Caches/tool/c.bin": 4 << 10, home + "/Library/loose.plist": 4 << 10,
		root + "/volume/Applications/App.app/Contents/MacOS/app": 128 << 10, filepath.Join(root, "volume", "Users", "Shared", "s.bin"): 4 << 10,
		root + "/volume/.Spotlight-V100/store.db": 4 << 10, root + "/volume/Volumes/Other/x.bin": 4 << 10} {
		reconcileFile(t, path, size)
	}
	locked := filepath.Join(root, "volume/.Spotlight-V100")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	c := &reconcileCase{root: root}
	c.ctx = NewContext(home)
	c.ctx.Store, c.ctx.VolumeRoot = store, filepath.Join(root, "volume")
	c.ctx.Now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.Local)
	c.rule = &ReconcileRule{MinBytes: 1 << 20, MinFraction: 0, Budget: time.Minute, Reuse: 7 * 24 * time.Hour,
		Disk: func(string) (DiskUse, bool) {
			return DiskUse{Total: 1 << 40, Used: c.used, Purgeable: 1 << 20, System: 10 << 20, SystemKnown: true, Swap: 2 << 20, SwapKnown: true}, true
		},
		Snapshots: func() ([]time.Time, bool) { return []time.Time{c.ctx.Now, c.ctx.Now}, true }}
	c.measureHome(t)
	return c
}

// measureHome writes today's sizes of the home's folders, as the space rule's round does.
func (c *reconcileCase) measureHome(t *testing.T) {
	t.Helper()
	folders, _ := SpaceWatched(&c.ctx)
	set := map[string]map[string]int64{}
	for _, f := range folders {
		set[Canonical(f)] = map[string]int64{ISODay(c.ctx.Now): AllocatedSize(f)}
	}
	if err := spaceSizes(c.ctx.Store).Apply(set, nil, false); err != nil {
		t.Fatal(err)
	}
}

func (c *reconcileCase) run(t *testing.T) ([]Finding, Reconcile) {
	t.Helper()
	got, err := c.rule.Run(&c.ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	a, ok := LastReconcile(c.ctx.Store)
	if !ok {
		t.Fatal("no account kept")
	}
	return got, a
}

func reconcilePart(a Reconcile, id string) int64 {
	for _, p := range a.Parts {
		if p.ID == id {
			return p.Bytes
		}
	}
	return -1
}

func reconcileGap(a Reconcile, id string) (ReconcileGap, bool) {
	for _, g := range a.Gaps {
		if g.ID == id {
			return g, true
		}
	}
	return ReconcileGap{}, false
}

// What is measured is told by part, what only root reads is named without holding the account up, and the rest is a
// finding only from the threshold up.
func TestReconcileTellsTheRestAndNamesTheSpotlightIndex(t *testing.T) {
	c := newReconcileCase(t)
	c.used = 1 << 30
	got, a := c.run(t)
	home := AllocatedSize(c.ctx.Home) // everything in the home: the folders, the loose files, the Trash
	if reconcilePart(a, PartHome) != home || reconcilePart(a, PartApplications) != 128<<10 || reconcilePart(a, PartShared) != 4<<10 ||
		reconcilePart(a, PartMacOS) != 10<<20 || reconcilePart(a, PartSwap) != 2<<20 || reconcilePart(a, PartOther) != -1 {
		t.Errorf("parts: %+v (home %d)", a.Parts, home)
	}
	if g, ok := reconcileGap(a, GapSpotlight); !ok || g.Open || g.Why != WhyRoot || len(a.Gaps) != 1 {
		t.Errorf("gaps: %+v", a.Gaps)
	}
	measured := a.Measured()
	if !a.Complete || a.Unexplained != c.used-measured-(1<<20) || a.Threshold != 1<<20 || a.Snapshots != 2 {
		t.Errorf("account: %+v (measured %d)", a, measured)
	}
	if len(got) != 1 || got[0].Rule != "space.unaccounted" || got[0].Verdict != Info || *got[0].Bytes != a.Unexplained {
		t.Fatalf("finding: %+v", got)
	}
	ev := got[0].Evidence
	if ev["spotlight"] != "unmeasured" || !strings.Contains(ev["why"], ".Spotlight-V100") || !strings.Contains(ev["why"], "2 个") ||
		!strings.Contains(ev["how"], "mdutil -E /") || ev["unmeasured"] != GapSpotlight {
		t.Errorf("evidence: %v", ev)
	}

	// just under the threshold: the figures are there, no finding (and Time Machine is not asked)
	c.used = measured + (1 << 20) + (1 << 20) - 1
	got, a = c.run(t)
	if len(got) != 0 || !a.Complete || a.Unexplained != 1<<20-1 || a.Over() || a.Snapshots != -1 {
		t.Errorf("under the threshold: %v %+v", got, a)
	}
	// at it: a finding
	c.used++
	if got, _ = c.run(t); len(got) != 1 {
		t.Errorf("at the threshold: %v", got)
	}
	// more measured than the disk says is used: nothing unexplained, not negative
	c.used = 1 << 10
	if got, a = c.run(t); len(got) != 0 || a.Unexplained != 0 {
		t.Errorf("measured above used: %v %+v", got, a)
	}
}

// Without Full Disk Access the guarded folders and everything outside the home are not measured: the account says so
// and calls nothing unexplained, however much is left.
func TestReconcileWithoutFullDiskAccessIsNotComplete(t *testing.T) {
	c := newReconcileCase(t)
	no := false
	c.ctx.FullDiskAccess = &no
	c.used = 1 << 39
	got, a := c.run(t)
	if len(got) != 0 || a.Complete || a.Over() {
		t.Fatalf("no access: %v %+v", got, a)
	}
	for _, id := range []string{GapHomeGuarded, GapVolume} {
		if g, ok := reconcileGap(a, id); !ok || !g.Open || g.Why != WhyAccess {
			t.Errorf("gap %s: %+v", id, a.Gaps)
		}
	}
	if reconcilePart(a, PartApplications) != -1 || reconcilePart(a, PartMacOS) != 10<<20 {
		t.Errorf("parts: %+v", a.Parts)
	}
}

// Another user's home that cannot be read can be as large as this one: no finding; one that can be read is a part.
func TestReconcileAnotherUsersHome(t *testing.T) {
	c := newReconcileCase(t)
	other := filepath.Join(c.root, "volume", "Users", "x")
	reconcileFile(t, other+"/Documents/big.bin", 256<<10)
	c.used = 1 << 30
	got, a := c.run(t)
	if len(got) != 1 || reconcilePart(a, PartOtherUsers) != 256<<10 {
		t.Fatalf("readable: %v %+v", got, a)
	}
	if err := os.Chmod(other+"/Documents", 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(other+"/Documents", 0o755)
	c.ctx.Now = c.ctx.Now.Add(8 * 24 * time.Hour) // past Reuse: walked again
	c.measureHome(t)
	got, a = c.run(t)
	if g, ok := reconcileGap(a, GapOtherUsers); len(got) != 0 || a.Complete || !ok || !g.Open {
		t.Errorf("unreadable: %v %+v", got, a)
	}
}

// A folder of the home the space rule did not get to this round counts with its last size, and the round is not
// complete; a place outside the home is walked again only after Reuse.
func TestReconcilePartialHomeAndReuse(t *testing.T) {
	c := newReconcileCase(t)
	c.used = 1 << 30
	_, first := c.run(t)
	reconcileFile(t, filepath.Join(c.root, "volume/Applications/New.app/x"), 64<<10)
	c.ctx.Now = c.ctx.Now.Add(24 * time.Hour)
	got, a := c.run(t) // no sizes for the new day
	if g, ok := reconcileGap(a, GapHome); len(got) != 0 || a.Complete || !ok || g.Why != WhyPartial ||
		reconcilePart(a, PartHome) != reconcilePart(first, PartHome) {
		t.Errorf("home not measured today: %v %+v", got, a)
	}
	c.measureHome(t)
	if _, a = c.run(t); !a.Complete || reconcilePart(a, PartApplications) != 128<<10 {
		t.Errorf("within Reuse: %+v", a)
	}
	c.ctx.Now = c.ctx.Now.Add(7 * 24 * time.Hour)
	c.measureHome(t)
	if _, a = c.run(t); reconcilePart(a, PartApplications) != (128+64)<<10 {
		t.Errorf("after Reuse: %+v", a)
	}
}

// A folder made in the home after the space rule listed it (never measured) is measured on the spot: the round stays
// complete.
func TestReconcileMeasuresAFolderMadeDuringTheRound(t *testing.T) {
	c := newReconcileCase(t)
	c.used = 1 << 30
	_, before := c.run(t)
	reconcileFile(t, filepath.Join(c.ctx.Home, "Library/Caches/newtool/blob.bin"), 64<<10)
	_, a := c.run(t)
	if !a.Complete || reconcilePart(a, PartHome) != reconcilePart(before, PartHome)+64<<10 {
		t.Errorf("new folder: %+v (before %d)", a, reconcilePart(before, PartHome))
	}
}

// The temporary folder is taken from the space rule's sizes and not walked again with /private.
func TestReconcileTakesTheTemporaryFolderFromTheSpaceRule(t *testing.T) {
	c := newReconcileCase(t)
	c.used = 1 << 30
	real, err := filepath.EvalSymlinks(c.root)
	if err != nil {
		t.Fatal(err)
	}
	tmp := real + "/tmpreal"
	reconcileFile(t, tmp+"/a.bin", 32<<10)
	// on the fake data volume the same folder is spelled <volume><canonical path>; it holds more than was measured
	reconcileFile(t, c.ctx.VolumeRoot+tmp+"/a.bin", 32<<10)
	reconcileFile(t, c.ctx.VolumeRoot+tmp+"/not-counted-twice.bin", 512<<10)
	reconcileFile(t, filepath.Dir(c.ctx.VolumeRoot+tmp)+"/beside.bin", 8<<10)
	c.ctx.Tmp = tmp
	c.measureHome(t)
	_, a := c.run(t)
	// which part the folders above it count in goes by where the test's own temporary folder is: both together
	got := reconcilePart(a, PartPrivate) + max(0, reconcilePart(a, PartOther))
	if !a.Complete || got != (32+8)<<10 {
		t.Errorf("temporary folder and what is beside it: %d, want %d: %+v", got, 40<<10, a)
	}
}

func TestGapOf(t *testing.T) {
	for rel, want := range map[string]string{".Spotlight-V100": GapSpotlight, ".Spotlight-V100/Store-V2": GapSpotlight,
		".DocumentRevisions-V100": GapVersions, ".fseventsd": GapFSEvents, "Users" + "/x/Documents": GapOtherUsers,
		"Users" + "/Shared/locked": GapSystemOther, "private/var/db": GapSystemDB, "private/var/db/uuidtext": GapSystemDB,
		"private/var/dbx": GapSystemTemp, "private/var/folders/zz/x": GapSystemTemp, "Library/Caches/x": GapSystemOther} {
		if got := gapOf(rel); got != want {
			t.Errorf("%s: %s, want %s", rel, got, want)
		}
	}
}

// The cloud apps' folder: only what is on this Mac counts, a folder not downloaded is not listed (listing it would
// have the cloud app fetch it); walked once in Reuse; with no time left the round is not complete.
func TestReconcileCloudStorage(t *testing.T) {
	c := newReconcileCase(t)
	c.used = 1 << 30
	_, before := c.run(t)
	cloud := filepath.Join(c.ctx.Home, "Library", "CloudStorage")
	reconcileFile(t, cloud+"/Drive/here.bin", 64<<10)
	reconcileFile(t, cloud+"/Drive/Remote/never-listed.bin", 512<<10)
	remote := cloud + "/Drive/Remote"
	if err := os.Chmod(remote, 0); err != nil { // were it listed, it would show as a folder that cannot be
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(remote, 0o755) })
	old := notOnThisMac
	notOnThisMac = func(path string) bool { return path == remote }
	t.Cleanup(func() { notOnThisMac = old })
	home := reconcilePart(before, PartHome)
	_, a := c.run(t)
	if _, listed := reconcileGap(a, GapCloud); listed || !a.Complete || reconcilePart(a, PartHome) != home+64<<10 {
		t.Fatalf("on this Mac only: %+v (home before %d)", a, home)
	}
	// within Reuse: not walked again
	reconcileFile(t, cloud+"/Drive/more.bin", 32<<10)
	if _, a = c.run(t); reconcilePart(a, PartHome) != home+64<<10 {
		t.Errorf("within Reuse: %+v", a)
	}
	// after Reuse, with no time left: its last size, and the round is not complete
	c.ctx.Now = c.ctx.Now.Add(8 * 24 * time.Hour)
	c.measureHome(t)
	c.rule.Budget = -time.Second
	got, a := c.run(t)
	if g, ok := reconcileGap(a, GapCloud); len(got) != 0 || a.Complete || !ok || !g.Open || g.Why != WhyPartial ||
		reconcilePart(a, PartHome) != home+64<<10 {
		t.Errorf("no time left: %v %+v", got, a)
	}
	if g, ok := reconcileGap(a, GapVolume); !ok || g.Why != WhyPartial {
		t.Errorf("no time left, outside the home: %+v", a.Gaps)
	}
	// with time again: walked, the new file counts
	c.rule.Budget = time.Minute
	if _, a = c.run(t); !a.Complete || reconcilePart(a, PartHome) != home+(64+32)<<10 {
		t.Errorf("after Reuse: %+v", a)
	}
	// the whole folder not on this Mac: not looked at
	notOnThisMac = func(path string) bool { return path == cloud }
	c.ctx.Now = c.ctx.Now.Add(8 * 24 * time.Hour)
	c.measureHome(t)
	if _, a = c.run(t); !a.Complete || reconcilePart(a, PartHome) != home {
		t.Errorf("not on this Mac at all: %+v", a)
	}
}

// A walk stops partway when told to: nothing is kept of it.
func TestCountTreeStopsPartway(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2100; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%04d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, finished := countTree(dir, nil, func() bool { return true }); finished {
		t.Error("not stopped")
	}
	if _, _, finished := countTree(dir, nil, func() bool { return false }); !finished {
		t.Error("stopped")
	}
}

// One place that takes longer than the round has: the round is not complete, and the half walk is not kept.
func TestReconcileStopsAWalkWhenTheTimeIsUp(t *testing.T) {
	c := newReconcileCase(t)
	c.used = 1 << 30
	big := filepath.Join(c.root, "volume", "Applications", "Many.app")
	if err := os.MkdirAll(big, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2100; i++ {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("f%04d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c.rule.Budget = 30 * time.Millisecond // enough to get to the places, up before the 2000th entry is reached
	slow := true
	c.ctx.Cancelled = func() bool {
		if slow {
			time.Sleep(40 * time.Millisecond)
			slow = false
		}
		return false
	}
	got, a := c.run(t)
	if g, ok := reconcileGap(a, GapVolume); len(got) != 0 || a.Complete || !ok || g.Why != WhyPartial {
		t.Fatalf("time up: %v %+v", got, a)
	}
	if len(reconcilePlaces(c.ctx.Store).Load()) != 0 {
		t.Errorf("half walks kept: %v", reconcilePlaces(c.ctx.Store).Load())
	}
}

// No account without a data volume to look at (a home given with --home), or when the disk's use is not known: what
// was kept goes.
func TestReconcileNotMadeWithoutAVolumeOrItsUse(t *testing.T) {
	c := newReconcileCase(t)
	c.used = 1 << 30
	c.run(t)
	root := c.ctx.VolumeRoot
	c.ctx.VolumeRoot = ""
	if got, err := c.rule.Run(&c.ctx); err != nil || len(got) != 0 {
		t.Errorf("no volume: %v %v", got, err)
	}
	if _, ok := LastReconcile(c.ctx.Store); ok {
		t.Error("the old account was kept")
	}
	c.ctx.VolumeRoot = root
	c.rule.Disk = func(string) (DiskUse, bool) { return DiskUse{}, false }
	if got, err := c.rule.Run(&c.ctx); err != nil || len(got) != 0 {
		t.Errorf("use not known: %v %v", got, err)
	}
	if _, ok := LastReconcile(c.ctx.Store); ok {
		t.Error("an account without the disk's use")
	}
}

// This Mac's own figures hold together: the disk's use is not above its size, and its parts not above its use.
func TestThisMacDisk(t *testing.T) {
	d, ok := thisMacDisk("/")
	if !ok {
		t.Skip("statfs did not answer")
	}
	if d.Total <= 0 || d.Used <= 0 || d.Used > d.Total || d.System < 0 || d.Swap < 0 || d.System+d.Swap > d.Used {
		t.Errorf("disk: %+v", d)
	}
	// the startup volume takes something of its own, and it is not all of what is used (statfs alone says neither)
	if own, ok := volumeUsed("/"); !ok || own <= 0 || own >= d.Used {
		t.Errorf("the startup volume's own use: %d %v of %d", own, ok, d.Used)
	}
}

// The user's Spotlight index is told from MinSpotlightBytes up, with how to have it rebuilt; nothing is run.
func TestSpotlightIndexOutOfTheOrdinary(t *testing.T) {
	home := t.TempDir()
	ctx := NewContext(home)
	reconcileFile(t, filepath.Join(home, userSpotlight, "index.spotlightV3/store.db"), 64<<10)
	r := &SystemSpaceRule{MinSpotlightBytes: 64 << 10}
	got := r.spotlight(&ctx)
	if len(got) != 1 || got[0].Rule != "space.spotlight-index" || got[0].Verdict != Info || *got[0].Bytes != 64<<10 ||
		!strings.Contains(got[0].Evidence["how"], "mdutil -E /") {
		t.Fatalf("large: %+v", got)
	}
	r.MinSpotlightBytes = 64<<10 + 1
	if got := r.spotlight(&ctx); len(got) != 0 {
		t.Errorf("ordinary: %v", got)
	}
	// access not confirmed: not looked at
	no := false
	ctx.FullDiskAccess, ctx.AccessOff = &no, true
	r.MinSpotlightBytes = 1
	if got := r.spotlight(&ctx); len(got) != 0 {
		t.Errorf("no access: %v", got)
	}
}

// Clones and the names of one file count once in the home: two clones in one folder, one each in two folders, two
// names of a file. Counted in full each, the home would come out above what the disk says is used and the rest would
// be cut to nothing; counted once, the rest is told.
func TestReconcileCountsClonesAndHardLinksOnce(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "volume", "Users", "me")
	const mb = int64(1 << 20)
	cloneTestFile(t, filepath.Join(home, "Models/a/model.bin"), 8, 1)
	cloneTestClone(t, filepath.Join(home, "Models/a/model.bin"), filepath.Join(home, "Models/b/model.bin"))
	cloneTestFile(t, filepath.Join(home, "Cross1/weights.bin"), 4, 2)
	cloneTestClone(t, filepath.Join(home, "Cross1/weights.bin"), filepath.Join(home, "Cross2/weights.bin"))
	cloneTestFile(t, filepath.Join(home, "Linked/a/lib.bin"), 4, 3)
	linkTestLink(t, filepath.Join(home, "Linked/a/lib.bin"), filepath.Join(home, "Linked/b/lib.bin"))
	if volumeType(home) != "apfs" {
		t.Skip("clones, but not APFS: nothing says which files share")
	}
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewContext(home)
	ctx.Store, ctx.Now, ctx.Tmp, ctx.VolumeRoot = store, time.Now(), "", filepath.Join(root, "volume")
	space := &SpaceRule{MinGrowthPerDay: 1 << 20, Window: 7, Budget: time.Minute, Journal: NewJournalSource(), SplitDepth: 2,
		RememberAbove: 1 << 20}
	if _, err := space.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	var full int64 // as the folders' sizes add up: every clone, every name
	for _, row := range SpaceSizes(store) {
		full += row[ISODay(ctx.Now)]
	}
	if full != 32*mb {
		t.Fatalf("the folders' sizes add up to %d, not every clone and name in full", full)
	}
	// the disk: the 16 MiB these take, 1 MiB that can be purged, 2 MiB nothing explains
	used := 16*mb + mb + 2*mb
	rule := &ReconcileRule{MinBytes: 1 << 20, MinFraction: 0, Budget: time.Minute, Reuse: 7 * 24 * time.Hour,
		Disk:      func(string) (DiskUse, bool) { return DiskUse{Total: 1 << 40, Used: used, Purgeable: 1 << 20}, true },
		Snapshots: func() ([]time.Time, bool) { return nil, true }}
	got, err := rule.Run(&ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := LastReconcile(store)
	if !ok {
		t.Fatal("no account kept")
	}
	if reconcilePart(a, PartHome) != 16*mb || a.Measured() != 16*mb {
		t.Errorf("home %d, measured %d: each group once is %d (parts %+v)", reconcilePart(a, PartHome), a.Measured(), 16*mb, a.Parts)
	}
	if !a.Complete || a.Unexplained != 2*mb || len(got) != 1 || got[0].Rule != "space.unaccounted" {
		t.Errorf("the rest: %+v, findings %v (in full the home alone is %d of %d used)", a, got, full, used)
	}
}
