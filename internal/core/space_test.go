package core

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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
