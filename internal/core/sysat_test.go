package core

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRemoveNoFollowAndRenameExcl(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir()) // the caller passes the real path (no link anywhere on the way)
	keep := filepath.Join(dir, "keep")
	os.MkdirAll(keep, 0o755)
	os.WriteFile(filepath.Join(keep, "precious"), []byte("x"), 0o644)
	cache := filepath.Join(dir, "cache")
	os.MkdirAll(filepath.Join(cache, "a/b"), 0o755)
	os.WriteFile(filepath.Join(cache, "a/b/f"), []byte("y"), 0o644)
	os.Symlink(keep, filepath.Join(cache, "link")) // a link inside goes as a link; what it points to stays
	if err := RemoveNoFollow(cache); err != nil {
		t.Fatal(err)
	}
	if Exists(cache) || !Exists(filepath.Join(keep, "precious")) {
		t.Fatal("removed the wrong things")
	}
	// A link on the way: refused.
	os.Symlink(keep, filepath.Join(dir, "via"))
	if err := RemoveNoFollow(filepath.Join(dir, "via")); err == nil || !Exists(keep) {
		t.Fatal("followed a link")
	}
	// Never over something there.
	src := OpenNoFollow(dir)
	defer syscall.Close(src)
	os.WriteFile(filepath.Join(dir, "x"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(dir, "y"), []byte("2"), 0o644)
	if err := RenameatxNp(src, "x", src, "y", RenameExcl); err != syscall.EEXIST {
		t.Fatalf("%v", err)
	}
	if err := RenameatxNp(src, "x", src, "z", RenameExcl); err != nil || !Exists(filepath.Join(dir, "z")) {
		t.Fatalf("%v", err)
	}
	if err := Mkdirat(src, "made", 0o700); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "made")); st.Mode().Perm() != 0o700 {
		t.Fatal(st.Mode())
	}
}

func TestDateAdded(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a")
	os.WriteFile(f, []byte("x"), 0o644)
	when, ok := DateAdded(f)
	if !ok || time.Since(when) > time.Minute || time.Since(when) < -time.Minute {
		t.Fatalf("%v %v", when, ok)
	}
	if _, ok := DateAdded(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing")
	}
}
