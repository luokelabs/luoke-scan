package service

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Moving into the Trash never replaces what is there: a file of the same name, nor a link of that name pointing
// nowhere (a check by stat would have taken that name as free).
func TestTrashIntoNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	trash := filepath.Join(dir, "Trash")
	os.MkdirAll(trash, 0o700)
	os.WriteFile(filepath.Join(trash, "report.pdf"), []byte("there before"), 0o644)
	os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(trash, "report 2.pdf"))
	src := filepath.Join(dir, "Downloads", "report.pdf")
	os.MkdirAll(filepath.Dir(src), 0o755)
	os.WriteFile(src, []byte("moved"), 0o644)

	to, err := trashInto(trash, src)
	if err != nil || to != filepath.Join(trash, "report 3.pdf") {
		t.Fatalf("%q %v", to, err)
	}
	if b, _ := os.ReadFile(to); string(b) != "moved" {
		t.Fatalf("moved: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(trash, "report.pdf")); string(b) != "there before" {
		t.Fatalf("replaced: %q", b)
	}
	if l, err := os.Readlink(filepath.Join(trash, "report 2.pdf")); err != nil || l != filepath.Join(dir, "nowhere") {
		t.Fatalf("the link: %q %v", l, err)
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatal("still where it was")
	}

	// A folder without an extension, and one already there under that name.
	for _, want := range []string{"cache", "cache 2"} {
		d := filepath.Join(dir, "cache")
		os.MkdirAll(filepath.Join(d, "x"), 0o755)
		if to, err := trashInto(trash, d); err != nil || to != filepath.Join(trash, want) {
			t.Fatalf("%q %v", to, err)
		}
	}

	// Gone meanwhile: the error says so, and nothing in the Trash changed.
	if _, err := trashInto(trash, src); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("%v", err)
	}
	if names, _ := os.ReadDir(trash); len(names) != 5 {
		t.Fatalf("%d in the Trash", len(names))
	}
}
