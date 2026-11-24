package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// DigestOf reads only the file it was told of (luoke-scan#234: a copy checked again before the others go): that device
// and inode, a plain file, no link followed; a FIFO in its place is refused, not waited on.
func TestDigestOf(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(p, bytes.Repeat([]byte("ab"), 1<<20), 0o644); err != nil { // 2 MiB: more than one read
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	dev, ino := int64(st.Dev), st.Ino
	want, _ := fileDigest(p, nil)
	if h, ok := DigestOf(p, dev, ino, nil); !ok || h != want || len(h) != 64 {
		t.Fatalf("%q %v, want %q", h, ok, want)
	}
	if _, ok := DigestOf(p, dev, ino+1, nil); ok {
		t.Error("another inode read")
	}
	if _, ok := DigestOf(p, dev+1, ino, nil); ok {
		t.Error("another device read")
	}
	if _, ok := DigestOf(p, dev, ino, func() bool { return true }); ok {
		t.Error("read once told to stop")
	}
	// A link to it, even with the file's own device and inode: not followed
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, ok := DigestOf(link, dev, ino, nil); ok {
		t.Error("followed a link")
	}
	// A folder
	var ds syscall.Stat_t
	syscall.Lstat(dir, &ds)
	if _, ok := DigestOf(dir, int64(ds.Dev), ds.Ino, nil); ok {
		t.Error("read a folder")
	}
	// A FIFO with nobody writing to it: refused at once
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	var fs syscall.Stat_t
	syscall.Lstat(fifo, &fs)
	done := make(chan bool, 1)
	go func() {
		_, ok := DigestOf(fifo, int64(fs.Dev), fs.Ino, nil)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("read a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waited on a FIFO")
	}
}

func TestDuplicatesHash(t *testing.T) {
	h := strings.Repeat("0123456789abcdef", 4)
	if got, ok := DuplicatesHash(Finding{Rule: "space.duplicates", Key: duplicatesKey + h}); !ok || got != h {
		t.Errorf("%q %v", got, ok)
	}
	for _, key := range []string{"", h, duplicatesKey + h[:63], duplicatesKey + strings.ToUpper(h), duplicatesKey + h + "0",
		"space.other:" + h, duplicatesKey + h[:63] + "g"} {
		if got, ok := DuplicatesHash(Finding{Key: key}); ok {
			t.Errorf("%q: %q", key, got)
		}
	}
}
