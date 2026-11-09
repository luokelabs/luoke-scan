package core

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReplaceWithClone(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a.bin"), filepath.Join(d, "b.bin")
	data := bytes.Repeat([]byte("luoke"), 100000)
	os.WriteFile(a, data, 0o644)
	os.WriteFile(b, data, 0o600)
	if putXattr(b, "com.example.tag", []byte("kept")) != nil {
		t.Fatal("setxattr")
	}
	// An access control list on the copy goes with it (an allow entry: a "deny delete" would also stop the swap).
	if err := exec.Command("/bin/chmod", "+a", "everyone allow read", b).Run(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exec.Command("/bin/chmod", "-N", b).Run() })
	var before syscall.Stat_t
	syscall.Lstat(b, &before)
	if err := ReplaceWithClone(a, b); err != nil {
		t.Fatal(err)
	}
	var after syscall.Stat_t
	syscall.Lstat(b, &after)
	if after.Ino == before.Ino {
		t.Fatal("not swapped")
	}
	if after.Mode&0o777 != 0o600 || after.Mtimespec != before.Mtimespec || after.Birthtimespec != before.Birthtimespec {
		t.Fatalf("metadata not kept: %o %v %v", after.Mode&0o777, after.Mtimespec, before.Mtimespec)
	}
	if v, ok := getXattr(b, "com.example.tag"); !ok || string(v) != "kept" {
		t.Fatal("extended attribute not kept")
	}
	if acl, ok := extendedSecurity(b); !ok || acl == nil {
		t.Fatal("access control list not kept")
	}
	if acl, ok := extendedSecurity(a); !ok || acl != nil {
		t.Fatal("the original has no access control list")
	}
	got, _ := os.ReadFile(b)
	if !bytes.Equal(got, data) {
		t.Fatal("contents changed")
	}
	if err := ReplaceWithClone(a, a); err == nil {
		t.Fatal("same file refused")
	}
}

func TestOpenBy(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "open")
	defer f.Close()
	names := OpenBy(f.Name())
	if len(names) == 0 {
		t.Fatal("this test has it open")
	}
	g := filepath.Join(t.TempDir(), "closed")
	os.WriteFile(g, []byte("x"), 0o644)
	if n := OpenBy(g); len(n) != 0 {
		t.Fatalf("nobody has it open: %v", n)
	}
	if p, err := FDPath(int(f.Fd())); err != nil || filepath.Base(p) != filepath.Base(f.Name()) {
		t.Fatalf("F_GETPATH: %q %v", p, err)
	}
}
