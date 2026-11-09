package core

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChangesBookkeeping(t *testing.T) {
	c := NewChanges([]ChangeEvent{{10, "/h/a/x"}}, []ChangeEvent{{20, "/h/b"}}, false, 20)
	for _, x := range []struct {
		path  string
		since uint64
		want  bool
		why   string
	}{
		{"/h/a", 5, true, "an event under a folder counts for it"},
		{"/h/a/x", 9, true, "and for the folder itself"},
		{"/h/a", 10, false, "only what came after counts"},
		{"/h/ab", 0, false, "a prefix is not inside"},
		{"/h/a/y", 0, false, "a sibling did not change"},
		{"/h/b/deep", 0, true, "a subtree that lost detail counts as changed all the way down"},
		{"/h/b/deep", 20, false, "but only after its event"},
		{"/h", 0, true, "ancestors see everything under them"},
		{"/", 15, true, "up to the root"},
		{"/h/a/", 5, true, "a trailing slash is the same place"},
	} {
		if got := c.Touched(x.path, x.since); got != x.want {
			t.Errorf("Touched(%q, %d) = %v: %s", x.path, x.since, got, x.why)
		}
	}
	if !Everything().Touched("/anything", ^uint64(0)) {
		t.Error("a journal that cannot tell: everything changed")
	}
	if !NewChanges([]ChangeEvent{{1, JournalTrim("/private/var/folders/x/T/a/")}}, nil, false, 1).Touched("/var/folders/x/T/a", 0) {
		t.Error("FSEvents says /private/var, the canonical path is /var")
	}
	if got := journalSelfAndAncestors("/a/b"); strings.Join(got, " ") != "/a/b /a /" {
		t.Errorf("ancestors: %v", got)
	}
	if JournalTrim("/") != "/" || JournalTrim("/private/tmp") != "/tmp" || JournalTrim("/private/tmpx") != "/private/tmpx" {
		t.Error("trim")
	}
}

func TestJournalCacheReplaysOncePerRound(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	calls := 0
	replay := func(c Changes) func() Changes { return func() Changes { calls++; return c } }
	j := NewJournalCache()
	got := j.Changes([]string{a, b}, 50, replay(NewChanges([]ChangeEvent{{60, a}}, nil, false, 70)))
	if calls != 1 || !got.Touched(a, 50) {
		t.Fatalf("first replay: %d calls", calls)
	}
	// Fewer folders, from later on: the replay made already answers.
	j.Changes([]string{b}, 60, replay(Everything()))
	if calls != 1 {
		t.Errorf("an earlier replay covering more folders answers a later question: %d calls", calls)
	}
	// From earlier on, or another folder: replayed.
	j.Changes([]string{a}, 40, replay(Everything()))
	j.Changes([]string{root}, 60, replay(Everything()))
	if calls != 3 {
		t.Errorf("replays: %d", calls)
	}
	// A replay that could not tell is not kept.
	j.Changes([]string{root}, 60, replay(Everything()))
	if calls != 4 {
		t.Errorf("an unknown answer is not reused: %d", calls)
	}
	var none *JournalCache
	none.Changes([]string{a}, 1, replay(Everything()))
	if calls != 5 {
		t.Error("no cache: replays")
	}
}

func TestBeginIncrement(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	j := newFakeJournal()
	ctx := NewContext(root)
	ctx.Store = store
	since := uint64(90)
	resets := 0
	begin := func() Increment {
		inc, err := BeginIncrement(&ctx, "fsevents.journal.test", []string{root}, &since, j.source(), func() error { resets++; return nil })
		if err != nil {
			t.Fatal(err)
		}
		return inc
	}
	if inc := begin(); resets != 1 || !inc.Changes.Unknown || inc.Start != 100 {
		t.Errorf("nothing kept of this journal yet: start over (%d resets, %+v)", resets, inc)
	}
	j.events = []ChangeEvent{{95, root}}
	inc := begin()
	if resets != 1 || inc.Changes.Unknown || !inc.Changes.Touched(root, 90) || inc.Verified() != 99 || j.calls != 1 {
		t.Errorf("same journal: replayed from since (%d resets, %d calls, verified %d)", resets, j.calls, inc.Verified())
	}
	j.uuid = "journal-2"
	if inc := begin(); resets != 2 || !inc.Changes.Unknown {
		t.Error("another journal: its old event ids mean nothing")
	}
	if v, _ := store.Get("fsevents.journal.test"); v != "journal-2" {
		t.Errorf("kept journal: %q", v)
	}
	j.uuid = ""
	if inc := begin(); resets != 2 || !inc.Changes.Unknown {
		t.Error("a journal that cannot be told: everything changed, without a reset")
	}
	if inc, err := BeginIncrement(&ctx, "fsevents.journal.test", nil, &since, j.source(), nil); err != nil || !inc.Changes.Unknown {
		t.Error("no roots: nothing to replay")
	}
	ctx.Cancelled = func() bool { return true }
	if _, err := BeginIncrement(&ctx, "fsevents.journal.test", []string{root}, &since, j.source(), nil); err == nil ||
		err.(*SkippedError).Reason != Interrupted {
		t.Errorf("cancelled: %v", err)
	}
}

// TestRealJournal replays the real FSEvents journal over a temp folder: a change shows up under its folder and
// nowhere else.
func TestRealJournal(t *testing.T) {
	if JournalCurrentID() == 0 {
		t.Skip("no FSEvents here (another system, or built without cgo)")
	}
	root := t.TempDir()
	for _, n := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(root, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1500 * time.Millisecond) // let the folders' own creation settle before the baseline
	since := JournalCurrentID()
	if err := os.WriteFile(filepath.Join(root, "a/new.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, b := Canonical(filepath.Join(root, "a")), Canonical(filepath.Join(root, "b"))
	seen := false
	for i := 0; i < 20 && !seen; i++ {
		time.Sleep(500 * time.Millisecond)
		c := JournalChanges([]string{root}, since, 10*time.Second, nil)
		if !c.Unknown && c.Touched(a, since) {
			seen = true
			if c.Touched(b, since) {
				t.Error("b did not change")
			}
			if c.Latest <= since {
				t.Errorf("latest %d, since %d", c.Latest, since)
			}
		}
	}
	if !seen {
		t.Error("within 10 seconds the journal should show the change in a")
	}
	if JournalUUID(root) == "" {
		t.Error("the journal of the temp folder's volume has an identity")
	}
	if c := JournalChanges([]string{filepath.Join(root, "missing")}, since, time.Second, nil); !c.Unknown {
		t.Error("no root there: nothing to go by")
	}
}

// TestRealJournalRightAway: a change made just before a replay is in that replay, not only in the next one (#100: the
// replay waits until fseventsd has written down what came before it). Ten times, since without the wait it is missed
// only some of the time.
func TestRealJournalRightAway(t *testing.T) {
	if JournalCurrentID() == 0 {
		t.Skip("no FSEvents here (another system, or built without cgo)")
	}
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		dir := filepath.Join(root, fmt.Sprintf("d%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		since := JournalCurrentID()
		if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if c := JournalChanges([]string{root}, since, 10*time.Second, nil); c.Unknown || !c.Touched(Canonical(dir), since) {
			t.Fatalf("try %d: the change just made is not in the replay (unknown %v)", i, c.Unknown)
		}
	}
}

// fakeJournal is a journal the test controls: the events in it, the current event id, its identity, and how often
// (and from where) it was replayed.
type fakeJournal struct {
	mu      sync.Mutex
	events  []ChangeEvent
	eventID uint64
	uuid    string
	calls   int
	from    []uint64
}

func newFakeJournal() *fakeJournal { return &fakeJournal{eventID: 100, uuid: "journal-1"} }

func (j *fakeJournal) source() JournalSource {
	return JournalSource{
		Replay: func(_ []string, since uint64, _ func() bool) Changes {
			j.mu.Lock()
			defer j.mu.Unlock()
			j.calls++
			j.from = append(j.from, since)
			var after []ChangeEvent
			for _, e := range j.events {
				if e.ID > since {
					after = append(after, e)
				}
			}
			return NewChanges(after, nil, false, max(since, j.eventID-1))
		},
		CurrentEventID: func() uint64 { j.mu.Lock(); defer j.mu.Unlock(); return j.eventID },
		JournalID:      func(string) string { j.mu.Lock(); defer j.mu.Unlock(); return j.uuid },
		MaxReuse:       7 * 24 * time.Hour,
	}
}

// event records a change in the folder at path, after the current event id.
func (j *fakeJournal) event(path string) {
	j.events = append(j.events, ChangeEvent{ID: j.eventID + 5, Path: Canonical(path)})
}

// writeBlob writes a file of n bytes (allocated: not sparse) dated at.
func writeBlob(t *testing.T, path string, n int, at time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), n), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func dateFolders(t *testing.T, at time.Time, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
}

// testNow is whole seconds: a time read back from a table compares equal to the one written.
var testNow = time.Unix(time.Now().Unix(), 0)

const testDay = 24 * time.Hour

func TestSpaceIncremental(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	writeBlob(t, filepath.Join(home, "a/blob"), 3<<20, testNow)
	writeBlob(t, filepath.Join(home, "b/blob"), 1<<20, testNow)
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	j := newFakeJournal()
	round := func(change func(*SpaceRule)) {
		t.Helper()
		r := NewSpaceRule(nil, nil).(*SpaceRule)
		r.Journal = j.source()
		if change != nil {
			change(r)
		}
		ctx := NewContext(home)
		ctx.Now, ctx.Store = testNow, store
		if _, err := r.Run(&ctx); err != nil {
			t.Fatal(err)
		}
		j.eventID += 10
	}
	recorded := func(name string) int64 {
		return spaceSizes(store).Load()[Canonical(filepath.Join(home, name))][ISODay(testNow)]
	}
	grow := func(name string, n int) {
		writeBlob(t, filepath.Join(home, name, "more-"+time.Now().Format("150405.000000000")), n, testNow)
	}

	round(nil)
	before := recorded("b")
	grow("b", 2<<20) // changed on disk, but the journal says nothing happened
	round(nil)
	if recorded("b") != before {
		t.Errorf("unchanged in the journal: not measured again (%d, then %d)", before, recorded("b"))
	}
	if j.calls != 1 {
		t.Errorf("the first round has nothing kept, no replay: %d", j.calls)
	}
	ids := map[uint64]bool{}
	for _, m := range SpaceMeasuredTable(store).Load() {
		ids[m.EventID] = true
	}
	if len(ids) != 1 || !ids[j.eventID-11] {
		t.Errorf("what was reused moves up to the newest event the replay saw: %v (now %d)", ids, j.eventID)
	}

	a := recorded("a")
	j.event(filepath.Join(home, "b/sub"))
	round(nil)
	if recorded("b") < 3<<20 || recorded("a") != a {
		t.Errorf("only what the journal saw change is measured again: a %d, b %d", recorded("a"), recorded("b"))
	}

	grow("a", 1<<20)
	j.uuid = "journal-2"
	round(nil)
	if recorded("a") < 4<<20 {
		t.Error("another journal: everything measured again")
	}

	grow("a", 1<<20)
	round(func(r *SpaceRule) { r.Journal.MaxReuse = 0 })
	if recorded("a") < 5<<20 {
		t.Error("the journal may have lost history: what was not really measured for too long is measured again")
	}

	// A folder deleted and made again under the same name: another inode, measured again.
	os.RemoveAll(filepath.Join(home, "a"))
	writeBlob(t, filepath.Join(home, "a/tiny"), 4096, testNow)
	round(nil)
	if recorded("a") >= 1<<20 {
		t.Error("another inode: measured again")
	}
}

func TestTempLeakIncremental(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	entry := func(i int) string { return filepath.Join(tmp, "wings-A"+strings.Repeat("0", 4)+string(rune('a'+i))) }
	for i := 0; i < 25; i++ {
		writeBlob(t, filepath.Join(entry(i), "index.html"), 5<<20, testNow.Add(-3*testDay))
		dateFolders(t, testNow.Add(-3*testDay), entry(i))
	}
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	j := newFakeJournal()
	round := func(at time.Time) *Finding {
		t.Helper()
		r := NewTempLeakRule(nil, nil).(*TempLeakRule)
		r.Journal = j.source()
		ctx := NewContext(root)
		ctx.Tmp, ctx.Now, ctx.Store = tmp, at, store
		f, err := r.Run(&ctx)
		if err != nil {
			t.Fatal(err)
		}
		j.eventID += 10
		if len(f) == 0 {
			return nil
		}
		return &f[0]
	}
	first := round(testNow)
	if first == nil || *first.Bytes < 125<<20 {
		t.Fatalf("25 leaked: %+v", first)
	}
	writeBlob(t, filepath.Join(entry(0), "more.bin"), 5<<20, testNow.Add(-3*testDay))
	dateFolders(t, testNow.Add(-3*testDay), entry(0))
	if f := round(testNow); f == nil || *f.Bytes != *first.Bytes {
		t.Error("nothing in the journal: what was walked is reused")
	}
	if v, _ := store.Get("temp.verified"); v != "109" {
		t.Errorf("found unchanged up to the newest event replayed: %q", v)
	}
	j.event(entry(0))
	if f := round(testNow); f == nil || *f.Bytes <= *first.Bytes {
		t.Error("the journal saw a change: walked again")
	}

	// A file dated in the future: once that time comes, the entry counts as changed then.
	writeBlob(t, filepath.Join(entry(1), "later.bin"), 5<<20, testNow.Add(testDay))
	dateFolders(t, testNow.Add(-3*testDay), entry(1))
	j.event(entry(1))
	before := round(testNow)
	if f := round(testNow.Add(2 * testDay)); f == nil || before == nil || f.Evidence["count"] != "24" {
		t.Errorf("the future came: walked again, now changed lately (%v)", f)
	}

	os.RemoveAll(entry(2))
	round(testNow)
	if _, ok := TempEntriesTable(store).Load()[Canonical(entry(2))]; ok {
		t.Error("gone: forgotten")
	}
}

func TestLeftoverIncremental(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	support := filepath.Join(home, "Library/Application Support")
	put := func(rel string, daysAgo float64) {
		u := filepath.Join(support, rel)
		writeBlob(t, u, 2<<20, testNow.Add(-time.Duration(daysAgo*float64(testDay))))
		dateFolders(t, testNow.Add(-200*testDay), filepath.Dir(u))
	}
	put("io.example.gone/data.bin", 90)
	put("io.example.busy/data.bin", 20)
	apps := filepath.Join(root, "Applications")
	os.MkdirAll(apps, 0o755)
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	j := newFakeJournal()
	round := func(daysLater float64) string {
		t.Helper()
		r := NewLeftoverRule(nil, nil).(*LeftoverRule)
		r.LaunchServices = false
		r.Journal = j.source()
		r.Journal.MaxReuse = 365 * testDay
		ctx := NewContext(home)
		ctx.Now, ctx.Store, ctx.AppDirs = testNow.Add(time.Duration(daysLater*float64(testDay))), store, []string{apps}
		f, err := r.Run(&ctx)
		if err != nil {
			t.Fatal(err)
		}
		j.eventID += 10
		var ids []string
		for _, x := range f {
			ids = append(ids, x.Evidence["bundle_id"])
		}
		sort.Strings(ids)
		return strings.Join(ids, " ")
	}
	if got := round(0); got != "io.example.gone" {
		t.Fatalf("written 20 days ago: in use (%q)", got)
	}
	put("io.example.gone/fresh.bin", 0) // written, but the journal does not say so
	if got := round(0); got != "io.example.gone" {
		t.Errorf("nothing in the journal: reused (%q)", got)
	}
	if got := round(15); got != "io.example.busy io.example.gone" {
		t.Errorf("busy's write is 30 days old now: looked at again (%q)", got)
	}
	j.event(filepath.Join(support, "io.example.gone"))
	if got := round(0); got != "" {
		t.Errorf("the journal saw a change: looked at again, in use; busy's row is from a later clock: looked at again (%q)", got)
	}

	// A row too old to reuse does not hold the replay back.
	table := LeftoverStateTable(store)
	busy := Canonical(filepath.Join(support, "io.example.busy"))
	row := table.Load()[busy]
	row.EventID, row.MeasuredAt = 1, testNow.Add(-400*testDay)
	table.Apply(map[string]LeftoverRow{busy: row}, nil, false)
	j.from = nil
	round(0)
	if len(j.from) != 1 || j.from[0] == 1 {
		t.Errorf("replayed from %v", j.from)
	}

	os.RemoveAll(filepath.Join(support, "io.example.gone"))
	round(0)
	if _, ok := table.Load()[Canonical(filepath.Join(support, "io.example.gone"))]; ok {
		t.Error("gone: forgotten")
	}
}

func TestStaleProjectIncremental(t *testing.T) {
	root := t.TempDir()
	projects := filepath.Join(root, "home/Projects")
	put := func(rel string, daysAgo float64) {
		u := filepath.Join(projects, rel)
		writeBlob(t, u, 4096, testNow.Add(-time.Duration(daysAgo*float64(testDay))))
		dateFolders(t, testNow.Add(-500*testDay), filepath.Dir(u), projects)
	}
	put("old/notes.txt", 400)
	put("busy/main.c", 150)
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	j := newFakeJournal()
	round := func(daysLater float64) string {
		t.Helper()
		r := NewStaleProjectRule(nil, nil).(*StaleProjectRule)
		r.MinFolderBytes = 0
		r.Journal = j.source()
		r.Journal.MaxReuse = 365 * testDay
		ctx := NewContext(filepath.Join(root, "home"))
		ctx.Now, ctx.Store, ctx.ProjectRoots = testNow.Add(time.Duration(daysLater*float64(testDay))), store, []string{projects}
		f, err := r.Run(&ctx)
		if err != nil {
			t.Fatal(err)
		}
		j.eventID += 10
		for _, x := range f {
			if x.Rule == "stale.folders" {
				return x.Evidence["folders"]
			}
		}
		return ""
	}
	if got := round(0); !strings.HasPrefix(got, "old（") || strings.Contains(got, "busy") {
		t.Fatalf("old is stale, busy changed 150 days ago: %q", got)
	}
	put("old/fresh.txt", 0) // written, but the journal does not say so
	if got := round(0); !strings.HasPrefix(got, "old（") {
		t.Errorf("nothing in the journal: reused (%q)", got)
	}
	if got := round(20); strings.Contains(got, "busy") {
		t.Errorf("busy still in use: reused (%q)", got)
	}
	if got := round(40); !strings.Contains(got, "busy") {
		t.Errorf("busy's change is half a year old now: looked at again (%q)", got)
	}
	j.event(filepath.Join(projects, "old"))
	if got := round(0); strings.Contains(got, "old") {
		t.Errorf("the journal saw a change: looked at again, in use (%q)", got)
	}

	// A linked worktree: its commits happen in another folder's .git, which the journal does not report here. Not kept.
	writeBlob(t, filepath.Join(projects, "linked/.git"), 40, testNow.Add(-500*testDay))
	dateFolders(t, testNow.Add(-500*testDay), filepath.Join(projects, "linked"), projects)
	round(0)
	rows := projectState(store).Load()
	if _, ok := rows[Canonical(filepath.Join(projects, "linked"))]; ok {
		t.Error("linked worktree kept")
	}
	if r, ok := rows[Canonical(filepath.Join(projects, "busy"))]; !ok || r.EventID == 0 {
		t.Errorf("busy kept with its event: %+v", r)
	}
}
