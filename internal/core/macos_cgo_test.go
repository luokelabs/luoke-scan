//go:build darwin && cgo

package core

import (
	"fmt"
	"os"
	"testing"
)

func TestImportantCapacity(t *testing.T) {
	// The system answers 0 free to a process without a graphical session (over ssh, in CI): known, just not useful.
	free, total, ok := importantCapacity(t.TempDir())
	if !ok || total <= 0 || free < 0 || free > total {
		t.Fatalf("free %d total %d ok %v", free, total, ok)
	}
	// What the rules read is never less than what statfs says is available.
	got, all, ok := volumeCapacity(t.TempDir())
	avail, _, plainOK := statfsCapacity(t.TempDir())
	if !ok || !plainOK || got <= 0 || got > all || got < avail-(1<<30) {
		t.Fatalf("volume free %d total %d ok %v, statfs %d ok %v", got, all, ok, avail, plainOK)
	}
	if p := os.Getenv("LUOKE_PRINT_CAPACITY"); p != "" {
		f, tot, _ := importantCapacity(p)
		fmt.Println("go", f, tot)
	}
}

// Asking the window server is read-only and shows no dialog; without a graphical session it is not known.
func TestKeyboardTapsAnswers(t *testing.T) {
	taps, ok := KeyboardTaps()
	if ok && taps == nil {
		t.Fatal("known but nil")
	}
}
