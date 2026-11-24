package core

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// treeStat is the walk as it was before the bulk read, kept word for word: the names, then one lstat each.
func treeStat(root string, enter func(Entry) bool, visit func(Entry) bool) bool {
	var st syscall.Stat_t
	if syscall.Lstat(root, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return true
	}
	return walkFolderStat(root, st.Dev, false, enter, visit)
}

func walkFolderStat(dir string, device int32, inGit bool, enter func(Entry) bool, visit func(Entry) bool) bool {
	f, err := os.Open(dir)
	if err != nil {
		return true
	}
	names, _ := f.Readdirnames(-1)
	f.Close()
	type sub struct {
		path  string
		inGit bool
		dev   int32
	}
	var subs []sub
	for _, n := range names {
		p := dir + "/" + n
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil {
			continue
		}
		e := entryOf(p, &st)
		e.InGit = inGit || n == ".git"
		if !visit(e) {
			return false
		}
		if e.IsDir && (enter == nil || enter(e)) {
			subs = append(subs, sub{p, e.InGit, st.Dev})
		}
	}
	for _, s := range subs {
		if s.dev != device {
			continue
		}
		if !walkFolderStat(s.path, device, s.inGit, enter, visit) {
			return false
		}
	}
	return true
}

type walker func(string, func(Entry) bool, func(Entry) bool) bool

func walkAll(w walker, root string) []Entry {
	var out []Entry
	w(root, nil, func(e Entry) bool { out = append(out, e); return true })
	return out
}

// sameWalk says the bulk walk sees exactly what the lstat walk sees, in the same order, field for field.
func sameWalk(t *testing.T, root string) int {
	t.Helper()
	old, bulk := walkAll(treeStat, root), walkAll(Tree, root)
	if reflect.DeepEqual(old, bulk) {
		return len(old)
	}
	byPath := map[string]Entry{}
	for _, e := range old {
		byPath[e.Path] = e
	}
	shown := 0
	for i, e := range bulk {
		o, ok := byPath[e.Path]
		switch {
		case !ok:
			t.Errorf("%s: only the bulk walk has it: %+v", root, e)
		case o != e:
			t.Errorf("%s: differs\n  lstat %+v\n  bulk  %+v", root, o, e)
		case i < len(old) && old[i].Path != e.Path:
			t.Errorf("%s: order differs at %d: lstat %s, bulk %s", root, i, old[i].Path, e.Path)
		default:
			continue
		}
		if shown++; shown > 20 {
			break
		}
	}
	if len(old) != len(bulk) {
		t.Errorf("%s: lstat walk saw %d, bulk walk %d", root, len(old), len(bulk))
	}
	return len(old)
}

// sameFolder says one folder read in bulk equals it read with lstat, and that the bulk read itself worked.
func sameFolder(t *testing.T, dir string, mustBulk bool) {
	t.Helper()
	if mustBulk {
		fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		plain, ok := readBulk(fd, dir, false, nil)
		syscall.Close(fd)
		if !ok {
			t.Errorf("%s: getattrlistbulk did not read it", dir)
		}
		// asked also for what shares blocks (APFS), it says the same of everything else
		if volumeType(dir) == "apfs" {
			fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
			if err != nil {
				t.Fatalf("%s: %v", dir, err)
			}
			clones, ok := readBulk(fd, dir, true, nil)
			syscall.Close(fd)
			if !ok || len(clones) != len(plain) {
				t.Errorf("%s: the clone-aware read: %d entries, ok %v; the plain one %d", dir, len(clones), ok, len(plain))
			} else {
				for i, e := range clones {
					e.Shares, e.CloneID = 0, 0
					if e != plain[i] {
						t.Errorf("%s: the clone-aware read %+v, the plain one %+v", dir, e, plain[i])
					}
				}
			}
		}
	}
	for _, d := range folderDiff(dir) {
		t.Error(d)
	}
}

// sameLiveFolder is sameFolder for a folder others may be changing (/dev's terminals, /Volumes while a disk is
// attached): a difference counts only when it is there three times in a row.
func sameLiveFolder(t *testing.T, dir string) {
	t.Helper()
	var diff []string
	for try := 0; try < 3; try++ {
		if diff = folderDiff(dir); len(diff) == 0 {
			return
		}
	}
	for _, d := range diff {
		t.Error(d)
	}
}

// folderDiff is how dir read in bulk differs from it read with lstat.
func folderDiff(dir string) []string {
	old, ok1 := readFolderStat(dir)
	bulk, ok2 := readFolder(dir)
	if ok1 != ok2 || len(old) != len(bulk) {
		return []string{fmt.Sprintf("%s: lstat %v %d entries, bulk %v %d", dir, ok1, len(old), ok2, len(bulk))}
	}
	var out []string
	for i := range old {
		if old[i] != bulk[i] {
			out = append(out, fmt.Sprintf("%s: entry %d\n  lstat %+v\n  bulk  %+v", dir, i, old[i], bulk[i]))
		}
	}
	return out
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, out)
	}
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeOddTree builds every kind of entry the walk can meet.
func makeOddTree(t *testing.T, root string) {
	mk := func(p string) string {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	files := mk("files")
	write(t, files+"/empty", nil)
	write(t, files+"/small", []byte("hello"))
	write(t, files+"/page", make([]byte, 4096))
	big := make([]byte, 3<<20+17)
	for i := range big {
		big[i] = byte(i * 7)
	}
	write(t, files+"/big", big)
	// sparse: a hole of 1 GB, then a little data
	f, err := os.Create(files + "/sparse")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte("tail"), 1<<30)
	f.Close()
	// compressed (decmpfs: the data lives in the resource fork), small and large
	text := []byte(strings.Repeat("compress me, compress me well. ", 40000))
	write(t, files+"/plain-large.txt", text)
	write(t, files+"/plain-small.txt", text[:3000])
	run(t, "ditto", "--hfsCompression", files+"/plain-large.txt", files+"/compressed-large.txt")
	run(t, "ditto", "--hfsCompression", files+"/plain-small.txt", files+"/compressed-small.txt")
	// hard links and clones
	write(t, files+"/linked", big[:100000])
	for i := 0; i < 3; i++ {
		if err := os.Link(files+"/linked", fmt.Sprintf("%s/hardlink%d", files, i)); err != nil {
			t.Fatal(err)
		}
	}
	run(t, "cp", "-c", files+"/big", files+"/clone-of-big")
	run(t, "cp", "-c", files+"/compressed-large.txt", files+"/clone-of-compressed")
	// extended attributes and resource forks
	write(t, files+"/xattr", []byte("x"))
	if err := SetXattrNoFollow(files+"/xattr", "com.example.big", make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	write(t, files+"/rsrc", []byte("data fork"))
	write(t, files+"/rsrc/..namedfork/rsrc", make([]byte, 200000))
	write(t, files+"/rsrc-only", nil)
	write(t, files+"/rsrc-only/..namedfork/rsrc", []byte("only a resource fork"))
	// links: to a file, to a folder, dangling, relative, a long target
	links := mk("links")
	os.Symlink(files+"/big", links+"/to-file")
	os.Symlink(files, links+"/to-dir")
	os.Symlink(root+"/nowhere", links+"/dangling")
	os.Symlink("../files/small", links+"/relative")
	os.Symlink(strings.Repeat("a/", 500), links+"/long-target")
	// pipes and sockets
	special := mk("special")
	if err := syscall.Mkfifo(special+"/fifo", 0o644); err != nil {
		t.Fatal(err)
	}
	if l, err := net.Listen("unix", special+"/sock"); err == nil {
		l.(*net.UnixListener).SetUnlinkOnClose(false)
		l.Close()
	}
	// folders: unreadable, unenterable, empty, .git with things in it, deep
	locked := mk("locked/inside")
	write(t, locked+"/secret", []byte("s"))
	os.Chmod(filepath.Dir(locked), 0o000)
	t.Cleanup(func() { os.Chmod(filepath.Dir(locked), 0o755) })
	noexec := mk("noexec")
	write(t, noexec+"/file", []byte("f"))
	os.Chmod(noexec, 0o644) // can list the names, cannot lstat them
	t.Cleanup(func() { os.Chmod(noexec, 0o755) })
	mk("empty")
	git := mk("project/.git/objects/ab")
	write(t, git+"/cdef", []byte("blob"))
	write(t, root+"/project/main.go", []byte("package main"))
	mk(strings.Repeat("deep/", 40))
	// more entries than one getattrlistbulk call returns
	many := mk("many")
	for i := 0; i < 3000; i++ {
		name := fmt.Sprintf("%s/entry-%04d-%s", many, i, strings.Repeat("x", i%200))
		if i%10 == 0 {
			os.Mkdir(name, 0o755)
		} else {
			write(t, name, make([]byte, i%5*1000))
		}
	}
	// odd names
	odd := mk("odd")
	for _, n := range []string{" space ", "new\nline", "tab\there", "-dash", ".hidden", "..dots", "~tilde", "#hash",
		"café", "café", "日本語のファイル", "😀 emoji", "a:colon", "back\\slash", "quote\"'", "\x01ctrl",
		strings.Repeat("長", 85), strings.Repeat("n", 255)} {
		write(t, odd+"/"+n, []byte(n))
	}
	if err := os.WriteFile(odd+"/bad-\xff\xfe-utf8", []byte("x"), 0o644); err != nil {
		t.Logf("a name that is not UTF-8: %v (the volume refuses it)", err)
	}
	// dates: future, before 1970, with nanoseconds
	dates := mk("dates")
	for i, d := range []string{"203801191200.07", "196912311200", "200001010000.59", "210601010000"} {
		p := fmt.Sprintf("%s/d%d", dates, i)
		write(t, p, []byte("d"))
		run(t, "touch", "-h", "-t", d, p)
		os.Symlink(p, p+"-link")
		run(t, "touch", "-h", "-t", d, p+"-link")
	}
	ns := dates + "/nanoseconds"
	write(t, ns, nil)
	ts := []syscall.Timespec{{Sec: 1700000000, Nsec: 123456789}, {Sec: 1700000000, Nsec: 987654321}}
	if err := syscall.UtimesNano(ns, ts); err != nil {
		t.Fatal(err)
	}
}

func TestBulkWalkMatchesLstat(t *testing.T) {
	root := t.TempDir()
	makeOddTree(t, root)
	// the tree really has what it is meant to have
	problems, notes := oddTreeLacks(root)
	for _, n := range notes {
		t.Log(n)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if n := sameWalk(t, root); n < 3100 {
		t.Errorf("walked %d entries; the tree has more", n)
	}
	// each folder on its own, and that getattrlistbulk really read it (not the fallback)
	Tree(root, nil, func(e Entry) bool {
		if e.IsDir {
			// a folder that cannot be opened, or whose items cannot be looked at, is read the plain way
			sameFolder(t, e.Path, e.Name != "locked" && e.Name != "noexec")
		}
		return true
	})
	sameFolder(t, root, true)
	// the walk's callers see the same too
	if a, b := walkFactsWith(treeStat, root), walkFactsWith(Tree, root); a != b {
		t.Errorf("facts: lstat %+v, bulk %+v", a, b)
	}
}

// oddTreeLacks: what the tree makeOddTree built lacks of what it is meant to have (problems), and what this Mac could
// not make, for the log (notes). A compressed file is a note, not a problem: on some Macs `ditto --hfsCompression`
// exits 0 and leaves the copy uncompressed, and the walk is then compared without one.
func oddTreeLacks(root string) (problems, notes []string) {
	lstat := func(rel string) syscall.Stat_t {
		var st syscall.Stat_t
		syscall.Lstat(filepath.Join(root, rel), &st)
		return st
	}
	if st := lstat("files/compressed-large.txt"); st.Flags&0x20 == 0 { // UF_COMPRESSED
		notes = append(notes, "ditto --hfsCompression did not compress here: the walk is compared without a compressed file")
	}
	if st := lstat("files/sparse"); st.Blocks*512 >= st.Size {
		problems = append(problems, fmt.Sprintf("sparse file has %d blocks for %d bytes", st.Blocks, st.Size))
	}
	if st := lstat("files/linked"); st.Nlink != 4 {
		problems = append(problems, fmt.Sprintf("hard links: %d", st.Nlink))
	}
	return problems, notes
}

// A Mac where ditto --hfsCompression leaves the copy as it was (it exits 0 either way): logged, not failed; what else
// the tree lacks still fails.
func TestOddTreeLacksWithoutCompression(t *testing.T) {
	root := t.TempDir()
	files := filepath.Join(root, "files")
	if err := os.Mkdir(files, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, files+"/compressed-large.txt", []byte(strings.Repeat("compress me, compress me well. ", 40000))) // as ditto left it
	f, err := os.Create(files + "/sparse")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte("tail"), 1<<30)
	f.Close()
	write(t, files+"/linked", []byte("linked"))
	for i := 0; i < 3; i++ {
		if err := os.Link(files+"/linked", fmt.Sprintf("%s/hardlink%d", files, i)); err != nil {
			t.Fatal(err)
		}
	}
	problems, notes := oddTreeLacks(root)
	if len(problems) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "did not compress") {
		t.Errorf("uncompressed copy: problems %q, notes %q", problems, notes)
	}
	os.Remove(files + "/hardlink0")
	if problems, _ := oddTreeLacks(root); !reflect.DeepEqual(problems, []string{"hard links: 3"}) {
		t.Errorf("a hard link short: problems %q", problems)
	}
}

// walkFactsWith adds up what WalkFacts adds up, with the given walk.
func walkFactsWith(w walker, root string) [3]int64 {
	var out [3]int64
	w(root, func(e Entry) bool { return !e.InGit }, func(e Entry) bool {
		out[0] += e.Bytes
		out[1] += e.Modified.UnixNano() % 1000003
		if e.IsLink {
			out[2]++
		}
		return true
	})
	return out
}

// Stopping and not going in work as they did: the same entries seen, up to the same point.
func TestBulkWalkStopsAndSkipsAsBefore(t *testing.T) {
	root := t.TempDir()
	makeOddTree(t, root)
	for _, stopAt := range []int{1, 7, 50, 1500, 3050} {
		take := func(w walker) []string {
			var seen []string
			w(root, func(e Entry) bool { return e.Name != "many" && !e.InGit }, func(e Entry) bool {
				seen = append(seen, e.Path)
				return len(seen) < stopAt
			})
			return seen
		}
		if a, b := take(treeStat), take(Tree); !reflect.DeepEqual(a, b) {
			t.Errorf("stop at %d: lstat saw %d, bulk %d", stopAt, len(a), len(b))
		}
	}
}

// Read-only trees every Mac has: system files owned by root, compressed, hard-linked, with folders that cannot be
// read, and the folder where the other volumes are mounted.
func TestBulkWalkMatchesLstatOnSystemTrees(t *testing.T) {
	for _, root := range []string{"/System/Library/CoreServices", "/usr/share", "/usr/bin", "/System/Library/Fonts"} {
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		n := sameWalk(t, root)
		t.Logf("%s: %d entries", root, n)
	}
	for _, dir := range []string{"/", "/System", "/System/Volumes", "/System/Library",
		"/System/Library/CoreServices/CoreTypes.bundle/Contents", "/Applications", "/Library", "/usr", "/private",
		"/dev", "/Volumes"} {
		if _, err := os.Lstat(dir); err == nil {
			sameLiveFolder(t, dir)
		}
	}
}

// Volumes other than APFS: the same tree on disk images of each kind (attached without a Finder window, detached
// after). Opt-in: LUOKE_TEST_DISKIMAGES=1. A user-attached image ignores ownership, which tests the owner mapping too.
func TestBulkWalkMatchesLstatOnDiskImages(t *testing.T) {
	if os.Getenv("LUOKE_TEST_DISKIMAGES") == "" {
		t.Skip("LUOKE_TEST_DISKIMAGES=1 to attach disk images")
	}
	for _, fs := range []string{"APFS", "HFS+", "Case-sensitive APFS", "ExFAT", "MS-DOS FAT32"} {
		t.Run(fs, func(t *testing.T) {
			tmp := t.TempDir()
			img, mnt := tmp+"/image.dmg", tmp+"/mnt"
			run(t, "hdiutil", "create", "-quiet", "-size", "1500m", "-fs", fs, "-volname", "BULK", "-layout", "GPTSPUD", img)
			os.Mkdir(mnt, 0o755)
			run(t, "hdiutil", "attach", "-quiet", "-nobrowse", "-noverify", "-noautoopen", "-mountpoint", mnt, img)
			t.Cleanup(func() { exec.Command("hdiutil", "detach", "-force", mnt).Run() })
			// the image as a folder inside a walked tree: the walk must not go in, as before
			if n := sameWalk(t, tmp); n == 0 {
				t.Error("nothing walked")
			}
			sameFolder(t, tmp, true)
			if want := !strings.Contains(fs, "FAT"); bulkVolume(mnt) != want {
				t.Errorf("bulkVolume on %s: %v", fs, !want)
			}
			makeOddTreeLoose(t, mnt+"/tree")
			n := sameWalk(t, mnt)
			t.Logf("%s: %d entries", fs, n)
		})
	}
}

// makeOddTreeLoose is makeOddTree where a volume cannot make everything (links, forks, odd names on FAT).
func makeOddTreeLoose(t *testing.T, root string) {
	os.MkdirAll(root, 0o755)
	write(t, root+"/plain", []byte("plain"))
	write(t, root+"/big", make([]byte, 1<<20+3))
	os.Symlink(root+"/plain", root+"/link")
	os.Link(root+"/plain", root+"/hard")
	os.Mkdir(root+"/sub", 0o755)
	write(t, root+"/sub/x", []byte("x"))
	exec.Command("ditto", "--hfsCompression", root+"/big", root+"/compressed").Run()
	exec.Command("cp", "-c", root+"/big", root+"/clone").Run()
	os.WriteFile(root+"/plain/..namedfork/rsrc", []byte("fork"), 0o644)
	for i := 0; i < 1200; i++ {
		write(t, fmt.Sprintf("%s/sub/n%04d", root, i), make([]byte, i%3*700))
	}
	for _, n := range []string{"café", "日本語", " space", "😀"} {
		os.WriteFile(root+"/"+n, []byte(n), 0o644)
	}
}
