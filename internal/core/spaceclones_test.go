package core

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// cloneTestFile writes mb MiB of fill at path and says what it takes on disk.
func cloneTestFile(t *testing.T, path string, mb int, fill byte) int64 {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, mb<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	e, _ := Item(path)
	return e.Bytes
}

// cloneTestClone makes to a clone of from; the test is skipped where the volume makes none.
func cloneTestClone(t *testing.T, from, to string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(to), 0o755)
	if err := clonefile(from, to); err != nil {
		t.Skip("no clones here: " + err.Error())
	}
}

// cloneTestOverwrite writes mb MiB over the file from 1 MiB on, and waits for it to be on disk.
func cloneTestOverwrite(t *testing.T, path string, mb int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xEE}, mb<<20), 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// The space rule measures real clones (made here with clonefile): two in one folder, one each in two folders, a clone
// partly rewritten, a clone of a file outside what is measured, and a plain file. Each folder's size stays what its
// files add up to; what deleting it gives back and the sum with shared blocks counted once come out as the disk has it.
func TestSpaceCountsClonesOnce(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	const mb = int64(1 << 20)
	// Models: two whole clones, both inside
	model := cloneTestFile(t, filepath.Join(home, "Models/a/model.bin"), 8, 1)
	cloneTestClone(t, filepath.Join(home, "Models/a/model.bin"), filepath.Join(home, "Models/b/deep/er/model.bin"))
	// Cross1, Cross2: one of a pair each
	weights := cloneTestFile(t, filepath.Join(home, "Cross1/weights.bin"), 4, 2)
	cloneTestClone(t, filepath.Join(home, "Cross1/weights.bin"), filepath.Join(home, "Cross2/weights.bin"))
	// Edited: a file and its clone, 2 MiB of the clone rewritten
	base := cloneTestFile(t, filepath.Join(home, "Edited/base.bin"), 8, 3)
	cloneTestClone(t, filepath.Join(home, "Edited/base.bin"), filepath.Join(home, "Edited/changed.bin"))
	cloneTestOverwrite(t, filepath.Join(home, "Edited/changed.bin"), 2)
	// Grown: a file and its clone, 1 MiB added to the end of the clone
	grown := cloneTestFile(t, filepath.Join(home, "Grown/base.bin"), 4, 7)
	cloneTestClone(t, filepath.Join(home, "Grown/base.bin"), filepath.Join(home, "Grown/longer.bin"))
	if f, err := os.OpenFile(filepath.Join(home, "Grown/longer.bin"), os.O_WRONLY|os.O_APPEND, 0); err != nil {
		t.Fatal(err)
	} else {
		f.Write(bytes.Repeat([]byte{0xEE}, 1<<20))
		f.Sync()
		f.Close()
	}
	// Out: a clone of it is outside the home
	out := cloneTestFile(t, filepath.Join(home, "Out/o.bin"), 2, 4)
	cloneTestClone(t, filepath.Join(home, "Out/o.bin"), filepath.Join(root, "elsewhere/o.bin"))
	// Plain: shares nothing; Was: its only clone is gone
	plain := cloneTestFile(t, filepath.Join(home, "Plain/p.bin"), 3, 5)
	was := cloneTestFile(t, filepath.Join(home, "Was/w.bin"), 2, 6)
	cloneTestClone(t, filepath.Join(home, "Was/w.bin"), filepath.Join(home, "Was/w.tmp"))
	os.Remove(filepath.Join(home, "Was/w.tmp"))
	if model != 8*mb || weights != 4*mb || base != 8*mb || out != 2*mb || plain != 3*mb || was != 2*mb || grown != 4*mb {
		t.Fatalf("allocated sizes are not the files' sizes here: %d %d %d %d %d %d", model, weights, base, out, plain, was)
	}
	if volumeType(home) != "apfs" {
		t.Skip("clones, but not APFS: nothing says which files share")
	}

	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewContext(home)
	ctx.Store, ctx.Now, ctx.Tmp = store, time.Now(), ""
	rule := &SpaceRule{MinGrowthPerDay: 1 << 20, Window: 7, Budget: time.Minute, Journal: NewJournalSource(), SplitDepth: 2,
		RememberAbove: 1 << 20}
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	sizes, clones := SpaceSizes(store), SpaceClonesTable(store).Load()
	day := ISODay(ctx.Now)
	var all SpaceCloneSum
	var measured int64
	for _, name := range []string{"Models", "Cross1", "Cross2", "Edited", "Grown", "Out", "Plain", "Was"} {
		c, ok := clones[Canonical(filepath.Join(home, name))]
		if !ok {
			t.Fatalf("%s: nothing remembered of its clones: %v", name, clones)
		}
		all.Add(c)
		measured += sizes[Canonical(filepath.Join(home, name))][day]
	}
	type row struct{ bytes, exclusive, shared int64 }
	want := map[string]row{
		"Models": {16 * mb, 8 * mb, 0},       // both of the pair: one of them is given back
		"Cross1": {4 * mb, 0, 4 * mb},        // the other of the pair is in Cross2
		"Cross2": {4 * mb, 0, 4 * mb},        //
		"Edited": {16 * mb, 4 * mb, 12 * mb}, // 2 MiB rewritten: 2 MiB each of their own, 6 MiB shared, counted in both
		"Out":    {2 * mb, 0, 2 * mb},        // the other of the pair is not measured: the volume says there are two
		"Plain":  {3 * mb, 3 * mb, 0},
		"Was":    {2 * mb, 2 * mb, 0},      // "may share" stays on the file; all of it is its own
		"Grown":  {9 * mb, 1 * mb, 8 * mb}, // the megabyte added is its own; the 4 MiB both have, counted in both
	}
	got := map[string]row{}
	for name := range want {
		key := Canonical(filepath.Join(home, name))
		var one SpaceCloneSum
		one.Add(clones[key])
		repeated, shared := one.Split(&all)
		got[name] = row{sizes[key][day], sizes[key][day] - repeated - shared, shared}
		if clones[key].Unchecked != 0 || clones[key].Volume == "" {
			t.Errorf("%s: unchecked %d, volume %q", name, clones[key].Unchecked, clones[key].Volume)
		}
	}
	if !reflect.DeepEqual(got, want) {
		var names []string
		for n := range want {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if got[n] != want[n] {
				t.Errorf("%s: bytes, exclusive, shared %v, want %v (%+v)", n, got[n], want[n], clones[Canonical(filepath.Join(home, n))])
			}
		}
	}
	// On disk: Models 8, the Cross pair 4, Edited 6 shared + 2 + 2, Grown 4 shared + 1, Out 2, Plain 3, Was 2.
	if measured != 56*mb || measured-all.Repeated() != 34*mb {
		t.Errorf("measured %d MiB, counted once %d MiB; want 56 and 34", measured/mb, (measured-all.Repeated())/mb)
	}
	// a remembered subfolder has its own: one of the pair, the other elsewhere in Models
	sub, ok := clones[Canonical(filepath.Join(home, "Models"))+"/b"]
	if !ok || len(sub.Groups) != 1 {
		t.Fatalf("Models/b: %+v %v", sub, ok)
	}
	var one SpaceCloneSum
	one.Add(sub)
	if repeated, shared := one.Split(&all); repeated != 0 || shared != 8*mb {
		t.Errorf("Models/b alone: repeated %d, shared %d", repeated, shared)
	}

	// the other of Cross1's pair goes: what Cross1 holds is its own again; a folder that is gone is forgotten
	os.RemoveAll(filepath.Join(home, "Cross2"))
	os.RemoveAll(filepath.Join(home, "Plain"))
	if err := SpaceMeasuredTable(store).Apply(nil, nil, true); err != nil {
		t.Fatal(err)
	}
	ctx.Now = ctx.Now.Add(time.Hour)
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	clones = SpaceClonesTable(store).Load()
	if _, ok := clones[Canonical(filepath.Join(home, "Plain"))]; ok {
		t.Error("a folder that is gone still has its clones remembered")
	}
	var after, cross SpaceCloneSum
	for _, name := range []string{"Models", "Cross1", "Edited", "Grown", "Out", "Was"} {
		after.Add(clones[Canonical(filepath.Join(home, name))])
	}
	cross.Add(clones[Canonical(filepath.Join(home, "Cross1"))])
	if repeated, shared := cross.Split(&after); repeated != 0 || shared != 0 {
		t.Errorf("Cross1 after its clone went: repeated %d, shared %d (%+v)", repeated, shared, clones[Canonical(filepath.Join(home, "Cross1"))])
	}
}

// linkTestLink gives the file at from a second name; the test is skipped where the volume makes no hard links.
func linkTestLink(t *testing.T, from, to string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(to), 0o755)
	if err := os.Link(from, to); err != nil {
		t.Skip("no hard links here: " + err.Error())
	}
}

// The space rule measures real hard links: a file with a second name in another subfolder of the same folder, one
// with its second name in another measured folder, one with its second name outside what is measured, and small ones.
// Each folder's size stays what its names add up to; deleting a folder gives a file back only when all its names are
// in it, and the sum counts a file once.
func TestSpaceCountsHardLinksOnce(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	const mb = int64(1 << 20)
	// Linked: both names inside, in two subfolders
	lib := cloneTestFile(t, filepath.Join(home, "Linked/a/lib.bin"), 4, 1)
	linkTestLink(t, filepath.Join(home, "Linked/a/lib.bin"), filepath.Join(home, "Linked/b/lib.bin"))
	// Pair1, Pair2: one name each, the second below the levels listed one by one
	pair := cloneTestFile(t, filepath.Join(home, "Pair1/p.bin"), 4, 2)
	linkTestLink(t, filepath.Join(home, "Pair1/p.bin"), filepath.Join(home, "Pair2/deep/er/still/p.bin"))
	// Outside: the second name is outside the home
	out := cloneTestFile(t, filepath.Join(home, "Outside/o.bin"), 2, 3)
	linkTestLink(t, filepath.Join(home, "Outside/o.bin"), filepath.Join(root, "elsewhere/o.bin"))
	// Small: two names of a file too small to follow, and a plain file
	os.MkdirAll(filepath.Join(home, "Small"), 0o755)
	if err := os.WriteFile(filepath.Join(home, "Small/s1"), bytes.Repeat([]byte{4}, 512<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	linkTestLink(t, filepath.Join(home, "Small/s1"), filepath.Join(home, "Small/s2"))
	plain := cloneTestFile(t, filepath.Join(home, "Small/plain.bin"), 1, 5)
	small, _ := Item(filepath.Join(home, "Small/s1"))
	if lib != 4*mb || pair != 4*mb || out != 2*mb || plain != mb || small.Bytes != mb/2 {
		t.Fatalf("allocated sizes are not the files' sizes here: %d %d %d %d %d", lib, pair, out, plain, small.Bytes)
	}
	// every read says how many names a file has: lstat, and the bulk reads with and without the sharing
	if e, _ := Item(filepath.Join(home, "Linked/a/lib.bin")); e.Links != 2 {
		t.Errorf("lstat: %d names", e.Links)
	}
	if e, _ := Item(filepath.Join(home, "Small/plain.bin")); e.Links != 1 || small.Links != 2 {
		t.Errorf("lstat: a plain file %d names, the small one %d", e.Links, small.Links)
	}
	for name, walk := range map[string]walker{"lstat": treeStat, "bulk": Tree, "clones": treeClones} {
		names := map[string]uint32{}
		walk(filepath.Join(home, "Small"), nil, func(e Entry) bool { names[e.Name] = e.Links; return true })
		if !reflect.DeepEqual(names, map[string]uint32{"s1": 2, "s2": 2, "plain.bin": 1}) {
			t.Errorf("%s walk: names %v", name, names)
		}
	}
	if d, _ := Item(filepath.Join(home, "Linked/a")); d.Links != 0 {
		t.Errorf("a folder has %d names", d.Links)
	}

	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewContext(home)
	ctx.Store, ctx.Now, ctx.Tmp = store, time.Now(), ""
	rule := &SpaceRule{MinGrowthPerDay: 1 << 20, Window: 7, Budget: time.Minute, Journal: NewJournalSource(), SplitDepth: 2,
		RememberAbove: 1 << 20}
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	sizes, clones := SpaceSizes(store), SpaceClonesTable(store).Load()
	day := ISODay(ctx.Now)
	var all SpaceCloneSum
	var measured int64
	for _, name := range []string{"Linked", "Pair1", "Pair2", "Outside", "Small"} {
		c, ok := clones[Canonical(filepath.Join(home, name))]
		if !ok {
			t.Fatalf("%s: nothing remembered: %v", name, clones)
		}
		all.Add(c)
		measured += sizes[Canonical(filepath.Join(home, name))][day]
	}
	type row struct{ bytes, exclusive, shared int64 }
	split := func(key string) row {
		var one SpaceCloneSum
		one.Add(clones[key])
		repeated, shared := one.Split(&all)
		b := sizes[key][day]
		if b == 0 {
			b = SpaceMeasuredTable(store).Load()[key].Bytes
		}
		return row{b, b - repeated - shared, shared}
	}
	for name, want := range map[string]row{
		"Linked":   {8 * mb, 4 * mb, 0},  // both names: the file is given back, once
		"Linked/a": {4 * mb, 0, 4 * mb},  // a subfolder alone: the other name stays
		"Linked/b": {4 * mb, 0, 4 * mb},  //
		"Pair1":    {4 * mb, 0, 4 * mb},  // the other name is in Pair2
		"Pair2":    {4 * mb, 0, 4 * mb},  //
		"Outside":  {2 * mb, 0, 2 * mb},  // the other name is not measured: the file says it has two
		"Small":    {2 * mb, mb, mb / 2}, // the plain megabyte; of the two small names, half each is shared, half repeated
	} {
		top, sub, _ := strings.Cut(name, "/")
		key := Canonical(filepath.Join(home, top))
		if sub != "" {
			key += "/" + sub
		}
		if _, ok := clones[key]; !ok {
			t.Errorf("%s: nothing remembered", name)
			continue
		}
		if got := split(key); got != want {
			t.Errorf("%s: bytes, exclusive, shared %v, want %v (%+v)", name, got, want, clones[key])
		}
	}
	// On disk: Linked 4, the pair 4, Outside 2, Small 1.5.
	if measured != 20*mb || measured-all.Repeated() != 11*mb+mb/2 {
		t.Errorf("measured %d KiB, counted once %d KiB; want 20 MiB and 11.5 MiB", measured>>10, (measured-all.Repeated())>>10)
	}

	// the other name of Pair1's file goes: what Pair1 holds is its own again
	os.RemoveAll(filepath.Join(home, "Pair2"))
	if err := SpaceMeasuredTable(store).Apply(nil, nil, true); err != nil {
		t.Fatal(err)
	}
	ctx.Now = ctx.Now.Add(time.Hour)
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	clones = SpaceClonesTable(store).Load()
	if c := clones[Canonical(filepath.Join(home, "Pair1"))]; len(c.Groups) != 0 || c.LinkBytes != 0 {
		t.Errorf("Pair1 after the other name went: %+v", c)
	}
}

// A file with two names that is a clone as well is counted as hard links, not twice: its names once between them,
// and never as given back.
func TestSpaceHardLinkThatIsAlsoAClone(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	const mb = int64(1 << 20)
	cloneTestFile(t, filepath.Join(home, "Both/x.bin"), 4, 1)
	linkTestLink(t, filepath.Join(home, "Both/x.bin"), filepath.Join(home, "Both/x.link"))
	cloneTestClone(t, filepath.Join(home, "Both/x.bin"), filepath.Join(home, "Both/x.clone"))
	if volumeType(home) != "apfs" {
		t.Skip("clones, but not APFS: nothing says which files share")
	}
	b, _, c, ok := WalkClones(filepath.Join(home, "Both"), time.Now(), nil)
	if !ok || b != 12*mb {
		t.Fatalf("walked: %d %v", b, ok)
	}
	if c.LinkBytes != 8*mb || c.LinkOnce != 4*mb {
		t.Errorf("the two names: %+v", c)
	}
	for id := range c.Groups {
		if strings.HasPrefix(id, spaceLinkGroup) {
			t.Errorf("the names are a group of their own: %+v", c)
		}
	}
	var sum SpaceCloneSum
	sum.Add(c)
	// 4 MiB of the names repeated; the names' 4 MiB and the clone's 4 MiB shared: nothing counts as given back
	if repeated, shared := sum.Split(&sum); repeated != 4*mb || shared != 8*mb {
		t.Errorf("repeated %d, shared %d (%+v)", repeated, shared, c)
	}
}

// What is kept of hard links adds up through subfolders; small ones, and the groups past the limit, count by each
// name's share of its file.
func TestSpaceLinksAddAndSplit(t *testing.T) {
	oldFacts, oldInode := shareFacts, linkInode
	defer func() { shareFacts, linkInode = oldFacts, oldInode }()
	shareFacts = func(path string) (int64, int64, bool) {
		switch path {
		case "/was-cloned": // "may share" left on a file that shares nothing
			return 2 << 20, 1, true
		case "/changed-clone":
			return 1 << 20, 1, true
		}
		return 0, 0, false
	}
	inodes := map[string]uint64{"/x1": 7, "/x2": 7, "/x3": 7, "/was-cloned": 8}
	linkInode = func(path string) uint64 { return inodes[path] }
	var a, b SpaceClones
	a.file(Entry{Path: "/x1", Bytes: 3 << 20, Links: 3})
	a.file(Entry{Path: "/small", Bytes: 3000, Links: 3})
	a.file(Entry{Path: "/was-cloned", Bytes: 2 << 20, Links: 2, Shares: sharesSome, CloneID: 5})
	a.file(Entry{Path: "/changed-clone", Bytes: 2 << 20, Links: 2, Shares: sharesSome, CloneID: 6})
	a.file(Entry{Path: "/whole-clone", Bytes: 4 << 20, Links: 4, Shares: sharesAll, CloneID: 9})
	a.file(Entry{Path: "/gone", Bytes: 2 << 20, Links: 2}) // its inode cannot be read: by its share
	a.file(Entry{Path: "/plain", Bytes: 8 << 20, Links: 1})
	b.file(Entry{Path: "/x2", Bytes: 3 << 20, Links: 3})
	want := SpaceClones{Groups: map[string]SpaceCloneGroup{"i7": {Count: 1, Bytes: 3 << 20, Size: 3 << 20, Refs: 3},
		"i8": {Count: 1, Bytes: 2 << 20, Size: 2 << 20, Refs: 2}},
		LinkBytes: 3000 + 2<<20 + 4<<20 + 2<<20, LinkOnce: 1000 + 1<<20 + 1<<20 + 1<<20}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("%+v, want %+v", a, want)
	}
	a.Volume, b.Volume = "V", "V"
	var sa, all SpaceCloneSum
	sa.Add(a)
	all.Add(a)
	all.Add(b)
	once := int64(1000 + 3<<20)
	// a: both groups have a name elsewhere (5 MiB shared); of the names not followed, each one's share is shared
	if r, s := sa.Split(&all); r != a.LinkBytes-once || s != 5<<20+once {
		t.Errorf("a: repeated %d shared %d", r, s)
	}
	// a and b: two of the three names of inode 7 (one repeated, and still shared: the third is elsewhere)
	if r, s := all.Split(&all); r != 3<<20+a.LinkBytes-once || s != 5<<20+once || all.Repeated() != 3<<20+a.LinkBytes-once {
		t.Errorf("both: repeated %d shared %d, Repeated %d", r, s, all.Repeated())
	}
	var c SpaceClones
	c.file(Entry{Path: "/x3", Bytes: 3 << 20, Links: 3})
	c.Volume = "V"
	all.Add(c)
	var three SpaceCloneSum
	for _, x := range []SpaceClones{a, b, c} {
		var only SpaceClones
		only.Volume, only.Groups = "V", map[string]SpaceCloneGroup{"i7": x.Groups["i7"]}
		three.Add(only)
	}
	// all three names: the file is given back, once
	if r, s := three.Split(&all); r != 6<<20 || s != 0 {
		t.Errorf("all the names: repeated %d shared %d", r, s)
	}
	// a subfolder's adds up into its folder's
	var sum SpaceClones
	sum.add(a)
	sum.add(b)
	if g := sum.Groups["i7"]; g.Count != 2 || g.Bytes != 6<<20 || g.Size != 3<<20 || g.Refs != 3 || sum.LinkBytes != a.LinkBytes ||
		sum.LinkOnce != a.LinkOnce {
		t.Errorf("added: %+v", sum)
	}
	// past the limit the smallest groups stop being followed: clones become loose, a file's names count by their share
	var many SpaceClones
	for i := 0; i < spaceCloneGroups; i++ {
		many.file(Entry{Bytes: 2 * spaceCloneMin, Shares: sharesAll, CloneID: uint64(100 + i)})
	}
	inodes["/l1"], inodes["/l2"] = 50, 50
	many.file(Entry{Path: "/l1", Bytes: spaceCloneMin, Links: 4})
	many.file(Entry{Path: "/l2", Bytes: spaceCloneMin, Links: 4})
	many.trim()
	if _, ok := many.Groups["i50"]; ok || len(many.Groups) != spaceCloneGroups || many.LooseBytes != 0 ||
		many.LinkBytes != 2*spaceCloneMin || many.LinkOnce != spaceCloneMin/2 {
		t.Errorf("trimmed: %d groups, loose %d, names %d, their share %d", len(many.Groups), many.LooseBytes, many.LinkBytes, many.LinkOnce)
	}
}

// A clone-aware read says the same as a plain one of everything else, and tells whole clones, changed clones and
// plain files apart.
func TestCloneWalkSeesWhatSharesBlocks(t *testing.T) {
	root := t.TempDir()
	cloneTestFile(t, root+"/d/orig", 2, 1)
	cloneTestClone(t, root+"/d/orig", root+"/d/clone")
	cloneTestClone(t, root+"/d/orig", root+"/d/changed")
	cloneTestOverwrite(t, root+"/d/changed", 1)
	cloneTestFile(t, root+"/d/plain", 1, 2)
	os.Symlink("orig", root+"/d/link")
	os.Mkdir(root+"/d/sub", 0o755)
	if volumeType(root) != "apfs" {
		t.Skip("not APFS")
	}
	seen := map[string]Entry{}
	var plainWalk []Entry
	treeClones(root, nil, func(e Entry) bool { seen[e.Name] = e; return true })
	Tree(root, nil, func(e Entry) bool { plainWalk = append(plainWalk, e); return true })
	if len(seen) != len(plainWalk) {
		t.Fatalf("%d entries, the plain walk %d", len(seen), len(plainWalk))
	}
	for _, p := range plainWalk {
		c := seen[p.Name]
		c.Shares, c.CloneID = 0, 0
		if c != p {
			t.Errorf("%s: %+v, the plain walk %+v", p.Name, c, p)
		}
		if p.Shares != 0 || p.CloneID != 0 {
			t.Errorf("%s: a plain walk says it shares", p.Name)
		}
	}
	o, c, ch, pl := seen["orig"], seen["clone"], seen["changed"], seen["plain"]
	if o.Shares != sharesAll || c.Shares != sharesAll || o.CloneID == 0 || o.CloneID != c.CloneID {
		t.Errorf("the pair: %+v %+v", o, c)
	}
	if ch.Shares != sharesSome || ch.CloneID == o.CloneID {
		t.Errorf("the changed clone: %+v", ch)
	}
	if own, refs, ok := shareFacts(ch.Path); !ok || own != 1<<20 || refs != 1 {
		t.Errorf("the changed clone's own bytes: %d, clones %d, %v", own, refs, ok)
	}
	if own, refs, ok := shareFacts(o.Path); !ok || own != 0 || refs != 2 {
		t.Errorf("the pair: %d of its own, %d clones, %v", own, refs, ok)
	}
	if pl.Shares != 0 || seen["link"].Shares != 0 || seen["sub"].Shares != 0 {
		t.Errorf("plain file, link, folder: %+v %+v %+v", pl, seen["link"], seen["sub"])
	}
	// the listing the space rule uses for the first levels says the same
	list, ok := spaceListEntries(root+"/d", nil)
	if !ok || len(list) != 6 {
		t.Fatalf("listing: %d %v", len(list), ok)
	}
	for _, e := range list {
		if e != seen[e.Name] {
			t.Errorf("listing %s: %+v, the walk %+v", e.Name, e, seen[e.Name])
		}
	}
	if id := VolumeID(root); len(id) != 32 || id != VolumeID(root+"/d/orig") {
		t.Errorf("volume id %q, of a file in it %q", id, VolumeID(root+"/d/orig"))
	}
}

// What is kept of clones adds up through subfolders, small whole clones and the groups past the limit count as loose,
// and what was not looked at stays unchecked.
func TestSpaceClonesAddAndSplit(t *testing.T) {
	old := shareFacts
	defer func() { shareFacts = old }()
	shareFacts = func(path string) (int64, int64, bool) {
		switch path {
		case "/changed":
			return 3 << 20, 1, true
		case "/alone": // "may share" left on a file that shares nothing
			return 8 << 20, 1, true
		case "/x", "/y", "/z":
			return 0, 3, true
		}
		return 0, 0, false
	}
	var a, b SpaceClones
	a.file(Entry{Path: "/x", Bytes: 8 << 20, Shares: sharesAll, CloneID: 7})
	a.file(Entry{Path: "/small", Bytes: 4096, Shares: sharesAll, CloneID: 9})
	a.file(Entry{Path: "/changed", Bytes: 8 << 20, Shares: sharesSome, CloneID: 10})
	a.file(Entry{Path: "/alone", Bytes: 8 << 20, Shares: sharesSome, CloneID: 11})
	a.file(Entry{Path: "/unknown", Bytes: 8 << 20, Shares: sharesSome, CloneID: 12})
	a.file(Entry{Path: "/plain", Bytes: 8 << 20})
	b.file(Entry{Path: "/y", Bytes: 8 << 20, Shares: sharesAll, CloneID: 7})
	b.file(Entry{Path: "/z", Bytes: 8 << 20, Shares: sharesAll, CloneID: 7})
	b.Unchecked = 5
	want := SpaceClones{Groups: map[string]SpaceCloneGroup{"7": {Count: 1, Bytes: 8 << 20, Size: 8 << 20, Refs: 3}},
		LooseBytes: 8<<20 + 4096, LoosePrivate: 3 << 20}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("%+v, want %+v", a, want)
	}
	a.Volume, b.Volume = "V", "V"
	var sa, sb, all, other SpaceCloneSum
	sa.Add(a)
	sb.Add(b)
	all.Add(a)
	all.Add(b)
	loose := int64(5<<20 + 4096)
	if r, s := sa.Split(&all); r != 0 || s != 8<<20+loose {
		t.Errorf("a: repeated %d shared %d", r, s)
	}
	if r, s := sb.Split(&all); r != 8<<20 || s != 8<<20 {
		t.Errorf("b: repeated %d shared %d", r, s)
	}
	if r, s := all.Split(&all); r != 16<<20 || s != loose || all.Repeated() != 16<<20+loose/2 || all.Unchecked != 5 {
		t.Errorf("both: repeated %d shared %d, Repeated %d, unchecked %d", r, s, all.Repeated(), all.Unchecked)
	}
	// the same id on another volume is another group
	c := b
	c.Volume = "W"
	other.Add(a)
	other.Add(c)
	if got := other.Repeated(); got != 8<<20+loose/2 {
		t.Errorf("two volumes: %d", got)
	}
	// the volume did not say how many (refs 0): whole when the measured folders hold no more of it
	var d SpaceClones
	d.file(Entry{Path: "/p", Bytes: 2 << 20, Shares: sharesAll, CloneID: 20})
	d.file(Entry{Path: "/q", Bytes: 2 << 20, Shares: sharesAll, CloneID: 20})
	var sd SpaceCloneSum
	sd.Add(d)
	if r, s := sd.Split(&sd); r != 2<<20 || s != 0 {
		t.Errorf("no count from the volume: repeated %d shared %d", r, s)
	}
	// past the limit the smallest groups become loose
	var many SpaceClones
	for i := 0; i < spaceCloneGroups+10; i++ {
		many.file(Entry{Bytes: int64(spaceCloneMin + i*4096), Shares: sharesAll, CloneID: uint64(100 + i)})
	}
	many.trim()
	var smallest int64
	for i := 0; i < 10; i++ {
		smallest += int64(spaceCloneMin + i*4096)
	}
	if _, ok := many.Groups["100"]; ok || len(many.Groups) != spaceCloneGroups || many.LooseBytes != smallest {
		t.Errorf("trimmed: %d groups, loose %d, want %d", len(many.Groups), many.LooseBytes, smallest)
	}
	var sum SpaceClones
	sum.add(a)
	sum.add(b)
	if g := sum.Groups["7"]; g.Count != 3 || g.Bytes != 24<<20 || g.Size != 8<<20 || sum.Unchecked != 5 || sum.LooseBytes != a.LooseBytes {
		t.Errorf("added: %+v", sum)
	}
}
