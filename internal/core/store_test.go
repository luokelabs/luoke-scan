package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestTableAppendCompactReplace(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	tb := NewTable[int](s, "nums", 1)
	tb.Apply(map[string]int{"a": 1, "b": 2}, nil, false)
	tb.Apply(map[string]int{"a": 3}, []string{"b"}, false)
	if got := tb.Load(); len(got) != 1 || got["a"] != 3 {
		t.Fatalf("%v", got)
	}
	tb.Compact()
	if _, err := os.Stat(filepath.Join(s.Dir, "nums.log")); !os.IsNotExist(err) {
		t.Fatal("log kept after compact")
	}
	if got := tb.Load(); got["a"] != 3 {
		t.Fatalf("%v", got)
	}
	tb.Replace(map[string]int{"z": 9})
	if got := tb.Load(); len(got) != 1 || got["z"] != 9 {
		t.Fatalf("%v", got)
	}
	tb.Apply(nil, nil, true)
	if got := tb.Load(); len(got) != 0 {
		t.Fatalf("reset: %v", got)
	}
}

// Several processes' worth of writers at once: every row arrives (appends under a shared lock, one write each).
func TestTableConcurrentWriters(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "data"))
	tb := NewTable[string](s, "seen", 1)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				tb.Apply(map[string]string{fmt.Sprintf("%d-%d", w, i): "x"}, nil, false)
			}
		}(w)
	}
	wg.Wait()
	if got := tb.Load(); len(got) != 400 {
		t.Fatalf("%d rows", len(got))
	}
}

// A line cut short (a writer killed mid-write) or with a wrong CRC: what came before it stays.
func TestTableBrokenLine(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "data"))
	tb := NewTable[int](s, "nums", 1)
	tb.Apply(map[string]int{"a": 1}, nil, false)
	f, _ := os.OpenFile(filepath.Join(s.Dir, "nums.log"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`deadbeef {"version":1,"set":{"b":2}}` + "\n" + `{"version":1,"se`)
	f.Close()
	if got := tb.Load(); len(got) != 1 || got["a"] != 1 {
		t.Fatalf("%v", got)
	}
	// Another version of the rows' shape: dropped (a cache, rebuilt).
	if got := NewTable[int](s, "nums", 2).Load(); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestMetaAndSwiftDatabaseRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "scan.db"), []byte("old"), 0o600)
	s, _ := OpenStore(dir)
	if _, err := os.Stat(filepath.Join(dir, "scan.db")); !os.IsNotExist(err) {
		t.Fatal("scan.db kept")
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("%v", st.Mode())
	}
	s.Set("clamav.version", "27000")
	if v, ok := s.Get("clamav.version"); !ok || v != "27000" {
		t.Fatal(v)
	}
}

func TestFilterWindows(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.ndb")
	long := "Osx.Long-1:0:*:" + string(make([]byte, 0)) + fmt.Sprintf("%0200000d", 0) + "\n"
	os.WriteFile(in, []byte("Win.Trojan.Fake-1:0:*:aa\nOsx.Trojan.Fake-1:0:*:bb\nPUA.Win.Tool-1:0:*:cc\n"+long+"Unix.X-1:0:*:dd"), 0o600)
	out := filepath.Join(dir, "b.ndb")
	if !filterWindows(in, out, 0) {
		t.Fatal("failed")
	}
	got, _ := os.ReadFile(out)
	want := "Osx.Trojan.Fake-1:0:*:bb\n" + long + "Unix.X-1:0:*:dd"
	if string(got) != want {
		t.Fatalf("%d bytes, want %d", len(got), len(want))
	}
	h := filepath.Join(dir, "a.hsb")
	os.WriteFile(h, []byte("aa:1:Win.Trojan.Hash-1:73\nbb:2:Unix.Trojan.Hash-1:73\n"), 0o600)
	filterWindows(h, out, 2)
	if got, _ := os.ReadFile(out); string(got) != "bb:2:Unix.Trojan.Hash-1:73\n" {
		t.Fatalf("%q", got)
	}
}

func TestSignatureOf(t *testing.T) {
	dir := t.TempDir()
	un := filepath.Join(dir, "un")
	os.WriteFile(un, []byte("x"), 0o755)
	sh := filepath.Join(dir, "s.sh")
	os.WriteFile(sh, []byte("#!/bin/sh\n"), 0o755)
	ad := filepath.Join(dir, "ad")
	data, _ := os.ReadFile("/usr/bin/true")
	os.WriteFile(ad, data, 0o755)
	Run("/usr/bin/codesign", []string{"-s", "-", "-f", ad}, RunOpts{})
	for path, want := range map[string]SigKind{"/usr/bin/true": SigApple, un: SigUnsigned, sh: SigScript, ad: SigAdhoc,
		filepath.Join(dir, "gone"): SigMissing} {
		if got := SignatureOf(path); got.Kind != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
}

func TestReplaceWithoutLog(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tab := NewTable[int](s, "fresh", 1)
	if err := tab.Replace(map[string]int{"a": 1}); err != nil {
		t.Fatalf("a table with no log yet: %v", err)
	}
	if got := tab.Load(); got["a"] != 1 {
		t.Fatalf("got %v", got)
	}
}
