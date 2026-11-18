package core

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
