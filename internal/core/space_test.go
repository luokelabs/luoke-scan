package core

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestTempLeakPrefix(t *testing.T) {
	for name, want := range map[string]string{"wings-AbC123": "wings", "puppeteer_dev_chrome_profile-XyZ987": "puppeteer_dev_chrome_profile",
		"a-b_cdefgh": "a-b", "upload_Q000001": "upload"} {
		if got, ok := TempLeakPrefix(name); !ok || got != want {
			t.Errorf("%s: %q %v", name, got, ok)
		}
	}
	for _, name := range []string{"notes", "-AbC123", "com.apple.MetalPerformanceShadersGraph", "log-12345", "cache-abc12-"} {
		if got, ok := TempLeakPrefix(name); ok {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestDeviceVersion(t *testing.T) {
	for name, want := range map[string]string{"iPhone16,2 18.1 (22B83)": "18.1", "16.4.1 (20E252) arm64e": "16.4.1",
		"Watch7,1 10.1 (21S71)": "10.1", "something": "", "17.2 (21C62)": "17.2"} {
		if got := DeviceVersion(name); got != want {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestSpaceExt(t *testing.T) {
	for name, want := range map[string]string{".env": "", "a.": "", "foo.egg-info": "egg-info", "a.b c": "", "x.photoslibrary": "photoslibrary",
		".a.b": "b", "a.b/": "b", "Foo.IPSW": "IPSW", "x.tar.gz": "gz", "...": "", "17.2 (21C62)": "", "/x/y.app": "app"} {
		if got := spaceExt(name); got != want {
			t.Errorf("%q: %q", name, got)
		}
	}
}

func TestSpaceCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{{"17.2", "18.1", -1, true}, {"16.4.1", "16.4", 1, true}, {"10.0", "10", 0, true}, {"x", "1", 0, false}} {
		if got, ok := spaceCompareVersions(c.a, c.b); got != c.want || ok != c.ok {
			t.Errorf("%s %s: %d %v", c.a, c.b, got, ok)
		}
	}
}

func TestSnapshotDates(t *testing.T) {
	d := SnapshotDates("Snapshots for volume group containing disk /:\ncom.apple.TimeMachine.2026-10-20-101500.local\n" +
		"com.apple.os.update-MSUPrepareUpdate\ncom.apple.TimeMachine.2026-10-26-093000.local\n")
	if len(d) != 2 || !d[0].Equal(time.Date(2026, 10, 20, 10, 15, 0, 0, time.Local)) {
		t.Fatalf("%v", d)
	}
}

func TestPrivateBytesOfClone(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.bin"), filepath.Join(dir, "b.bin")
	if err := os.WriteFile(a, bytes.Repeat([]byte{7}, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if exec.Command("/bin/cp", "-c", a, b).Run() != nil {
		t.Skip("no clones here")
	}
	n, ok := PrivateBytes(a)
	if !ok {
		t.Skip("the volume does not say")
	}
	if n != 0 {
		t.Errorf("a clone's original holds %d of its own", n)
	}
	if !SameContents(a, b) {
		t.Error("a clone is not the same")
	}
	os.WriteFile(b, []byte("other"), 0o600)
	if SameContents(a, b) {
		t.Error("different files are the same")
	}
	if n, ok := PrivateBytes(a); !ok || n < 1<<20 {
		t.Errorf("after the clone changed: %d %v", n, ok)
	}
}

// The biggest files directly in a measured folder are remembered when it is walked (data/usage), the biggest first,
// from RememberAbove up, not a subfolder's files; replaced when it is walked again; forgotten with the folder.
func TestSpaceRemembersTheBiggestFilesOfAFolder(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	write := func(rel string, n int) {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, bytes.Repeat([]byte("x"), n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, n := range []int{300, 700, 100, 500, 900, 200, 800} {
		write(fmt.Sprintf("Downloads/f%d.bin", i), n<<10)
	}
	write("Downloads/small.txt", 10)
	write("Downloads/sub/deep.bin", 2000<<10)
	write("Projects/one.bin", 400<<10)
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewContext(home)
	ctx.Store = store
	ctx.Now = time.Now()
	ctx.Tmp = ""
	rule := &SpaceRule{MinGrowthPerDay: 1 << 20, Window: 7, Budget: time.Minute, Journal: NewJournalSource(), SplitDepth: 2,
		RememberAbove: 150 << 10}
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	top := SpaceTopFilesTable(store).Load()
	dl := top[Canonical(filepath.Join(home, "Downloads"))]
	var names []string
	for _, f := range dl {
		names = append(names, f.Name)
		if f.Bytes < 150<<10 {
			t.Errorf("%s: %d bytes, under RememberAbove", f.Name, f.Bytes)
		}
	}
	if want := []string{"f4.bin", "f6.bin", "f1.bin", "f3.bin", "f0.bin"}; !reflect.DeepEqual(names, want) {
		t.Errorf("Downloads' biggest files: %v, want %v", names, want)
	}
	if p := top[Canonical(filepath.Join(home, "Projects"))]; len(p) != 1 || p[0].Name != "one.bin" {
		t.Errorf("Projects: %v", p)
	}
	if _, ok := top[Canonical(filepath.Join(home, "Downloads/sub"))]; ok {
		t.Errorf("a subfolder has files of its own remembered: %v", top)
	}

	// walked again after a change: replaced; a folder that is gone: forgotten
	os.Remove(filepath.Join(home, "Downloads/f4.bin"))
	os.RemoveAll(filepath.Join(home, "Projects"))
	if err := SpaceMeasuredTable(store).Apply(nil, nil, true); err != nil { // nothing counts as unchanged: all walked again
		t.Fatal(err)
	}
	ctx.Now = ctx.Now.Add(time.Hour)
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	top = SpaceTopFilesTable(store).Load()
	dl = top[Canonical(filepath.Join(home, "Downloads"))]
	if len(dl) != 5 || dl[0].Name != "f6.bin" || dl[4].Name != "f5.bin" {
		t.Errorf("after the change: %v", dl)
	}
	if _, ok := top[Canonical(filepath.Join(home, "Projects"))]; ok {
		t.Errorf("a folder that is gone is still remembered: %v", top)
	}
}

// Listing a folder's entries stops when asked (luoke-scan#213: a huge folder was stat'ed to the end after SIGTERM).
func TestSpaceListEntriesStopsWhenAsked(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3*spaceListStopEvery; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if all, ok := spaceListEntries(dir, nil); !ok || len(all) != 3*spaceListStopEvery {
		t.Fatalf("whole listing: %d %v", len(all), ok)
	}
	// how often it asks depends on how the folder is read: every spaceListStopEvery entries one by one, between the
	// system calls in bulk
	asked := 0
	if got, ok := spaceListEntries(dir, func() bool { asked++; return false }); !ok || len(got) != 3*spaceListStopEvery || asked < 2 {
		t.Errorf("not stopped: %d entries, ok %v, asked %d times", len(got), ok, asked)
	}
	asked = 0
	if got, ok := spaceListEntries(dir, func() bool { asked++; return asked == 2 }); ok || got != nil || asked != 2 {
		t.Errorf("stopped at the second ask: %d entries, ok %v, asked %d times", len(got), ok, asked)
	}
}

// What a measured folder is made of is remembered when it is walked (data/usage's mix): every file under it, however
// deep, by kind and by the year it was last changed, and the biggest of them by their path under the folder; a
// remembered subfolder has its own; forgotten with the folder.
func TestSpaceRemembersWhatAFolderIsMadeOf(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	now := time.Now()
	write := func(rel string, mb int, year int) int64 {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, bytes.Repeat([]byte("x"), mb<<20), 0o644); err != nil {
			t.Fatal(err)
		}
		when := time.Date(year, 6, 1, 12, 0, 0, 0, time.Local)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
		e, _ := Item(p)
		return e.Bytes
	}
	this, last := now.Year(), now.Year()-1
	photo := write("Library/Messages/Attachments/0a/10/IMG_1.HEIC", 3, last)
	video := write("Library/Messages/Attachments/0b/11/x/y/clip.mov", 5, last)
	db := write("Library/Messages/chat.db", 2, this)
	plain := write("Library/Messages/Attachments/0a/noext", 1, this)
	future := write("Library/Messages/Attachments/0a/later.pdf", 1, this+2)
	write("Projects/a.zip", 1, this)
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := NewContext(home)
	ctx.Store, ctx.Now, ctx.Tmp = store, now, ""
	rule := &SpaceRule{MinGrowthPerDay: 1 << 20, Window: 7, Budget: time.Minute, Journal: NewJournalSource(), SplitDepth: 2,
		RememberAbove: 1 << 20}
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	mixes := SpaceMixTable(store).Load()
	key := Canonical(filepath.Join(home, "Library/Messages"))
	m, ok := mixes[key]
	if !ok {
		t.Fatalf("no mix for Library/Messages: %v", mixes)
	}
	wantKinds := map[string]SpaceTally{"photo": {photo, 1}, "video": {video, 1}, "database": {db, 1}, "document": {future, 1},
		KindOther: {plain, 1}}
	if !reflect.DeepEqual(m.Kinds, wantKinds) {
		t.Errorf("kinds: %v, want %v", m.Kinds, wantKinds)
	}
	wantYears := map[string]int64{strconv.Itoa(last): photo + video, strconv.Itoa(this): db + plain, "": future}
	if !reflect.DeepEqual(m.Years, wantYears) {
		t.Errorf("years: %v, want %v", m.Years, wantYears)
	}
	var paths []string
	for _, f := range m.Top {
		paths = append(paths, f.Path)
	}
	if want := []string{"Attachments/0b/11/x/y/clip.mov", "Attachments/0a/10/IMG_1.HEIC", "chat.db", "Attachments/0a/later.pdf",
		"Attachments/0a/noext"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("the biggest files: %v, want %v", paths, want)
	}
	if m.Top[0].Modified != fmt.Sprintf("%d-06-01", last) || m.Unknown != 0 {
		t.Errorf("the biggest file's day %s, unknown %d", m.Top[0].Modified, m.Unknown)
	}
	// a remembered subfolder has its own, by its own paths
	sub, ok := mixes[key+"/Attachments/0b"]
	if !ok || len(sub.Top) != 1 || sub.Top[0].Path != "11/x/y/clip.mov" || sub.Kinds["video"].Bytes != video {
		t.Errorf("Attachments/0b: %v %v", sub, ok)
	}
	if _, ok := mixes[Canonical(filepath.Join(home, "Projects"))]; !ok {
		t.Error("no mix for Projects")
	}

	// a folder that is gone: forgotten, with its subfolders; the others walked again and kept
	os.RemoveAll(filepath.Join(home, "Projects"))
	os.RemoveAll(filepath.Join(home, "Library/Messages/Attachments/0b"))
	if err := SpaceMeasuredTable(store).Apply(nil, nil, true); err != nil {
		t.Fatal(err)
	}
	ctx.Now = ctx.Now.Add(time.Hour)
	if _, err := rule.Run(&ctx); err != nil {
		t.Fatal(err)
	}
	mixes = SpaceMixTable(store).Load()
	if _, ok := mixes[Canonical(filepath.Join(home, "Projects"))]; ok {
		t.Error("a folder that is gone still has a mix")
	}
	if _, ok := mixes[key+"/Attachments/0b"]; ok {
		t.Error("a subfolder that is gone still has a mix")
	}
	if m := mixes[key]; m.Kinds["video"].Count != 0 || m.Kinds["photo"].Bytes != photo {
		t.Errorf("after the change: %v", m.Kinds)
	}
}

// A mix takes in a subfolder's: the kinds and years added, the files by their path through the subfolder, the
// biggest kept; what the subfolder did not know stays unknown.
func TestSpaceMixAdd(t *testing.T) {
	now := time.Now()
	var m SpaceMix
	m.file("a.mp4", 5<<20, now, now)
	sub := SpaceMix{Kinds: map[string]SpaceTally{"video": {8 << 20, 2}, "photo": {1 << 20, 4}}, Years: map[string]int64{"2020": 9 << 20},
		Top: []SpaceBigFile{{"x/b.mov", 6 << 20, "2020-01-02"}}, Unknown: 7}
	m.add(sub, "sub")
	if m.Kinds["video"] != (SpaceTally{13 << 20, 3}) || m.Kinds["photo"].Count != 4 || m.Years["2020"] != 9<<20 || m.Unknown != 7 {
		t.Errorf("%+v", m)
	}
	if len(m.Top) != 2 || m.Top[0] != (SpaceBigFile{"sub/x/b.mov", 6 << 20, "2020-01-02"}) || m.Top[1].Path != "a.mp4" {
		t.Errorf("top: %v", m.Top)
	}
	for i := 0; i < 200; i++ {
		m.file(fmt.Sprintf("f%03d.bin", i), int64(i+1)<<20, now, now)
	}
	m.file("tiny.bin", 100, now, now)
	m.trim()
	if len(m.Top) != spaceMixTop || m.Top[0].Path != "f199.bin" {
		t.Errorf("top after many: %v", m.Top)
	}
	for name, want := range map[string]string{"a.JPG": "photo", "Docker.raw": "disk-image", "x.tar.gz": "archive", "noext": KindOther,
		".hidden": KindOther, "a.": KindOther, "m.gguf": "model", "weird.zzz": KindOther} {
		if got := FileKind(name); got != want {
			t.Errorf("FileKind(%s) = %s, want %s", name, got, want)
		}
	}
}
