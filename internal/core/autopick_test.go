package core

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestMountInside(t *testing.T) {
	if _, ok := MountInside(t.TempDir()); ok {
		t.Fatal("a temp folder has no disk mounted in it")
	}
	if on, ok := MountInside("/System/Volumes"); !ok {
		t.Fatal("the data volume is mounted under /System/Volumes")
	} else if on == "" {
		t.Fatal("empty mount point")
	}
}

func TestBrowserRunning(t *testing.T) {
	d := t.TempDir()
	if BrowserRunning(d) {
		t.Fatal("no lock: not running")
	}
	os.Symlink("host-"+strconv.Itoa(os.Getpid()), filepath.Join(d, "SingletonLock"))
	if !BrowserRunning(d) {
		t.Fatal("a lock naming a live pid: running")
	}
	e := t.TempDir()
	os.Symlink("host-nopid", filepath.Join(e, "lock"))
	if !BrowserRunning(e) {
		t.Fatal("a lock without a pid counts as running")
	}
}

func TestRegeneratedAndProject(t *testing.T) {
	if !Regenerated("~/Projects/app/build/out.bin") || Regenerated("~/Documents/build") {
		t.Fatal("only the folders on the way count")
	}
	top := t.TempDir()
	os.MkdirAll(filepath.Join(top, "proj/sub"), 0o755)
	os.WriteFile(filepath.Join(top, "proj/go.mod"), nil, 0o644)
	top = Canonical(top)
	if !InProject(filepath.Join(top, "proj/sub/x.bin"), top) || InProject(filepath.Join(top, "x.bin"), top) {
		t.Fatal("project marker between top and file")
	}
}
