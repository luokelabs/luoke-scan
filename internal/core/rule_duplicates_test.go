package core

import (
	"strings"
	"testing"
)

// The places a skip reason names are read back as the rule wrote them, also inside the reason an interrupted round
// carried over.
func TestDuplicatesNotLooked(t *testing.T) {
	reason := NotLooked("Downloads、Desktop" + duplicatesLeftOut)
	want := []string{"Downloads", "Desktop"}
	for _, r := range []string{reason, "这一轮被打断了，沿用 2026-10-20 那一轮的结果（" + reason + "）"} {
		if got := DuplicatesNotLooked(r); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: %v", r, got)
		}
	}
	for _, r := range []string{"", Interrupted, NotLooked("Documents 里的项目")} {
		if got := DuplicatesNotLooked(r); got != nil {
			t.Errorf("%q: %v", r, got)
		}
	}
}
