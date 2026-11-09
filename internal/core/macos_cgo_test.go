//go:build darwin && cgo

package core

import (
	"fmt"
	"os"
	"testing"
)

func TestImportantCapacity(t *testing.T) {
	free, total, ok := importantCapacity(t.TempDir())
	if !ok || total <= 0 || free <= 0 || free > total {
		t.Fatalf("free %d total %d ok %v", free, total, ok)
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
