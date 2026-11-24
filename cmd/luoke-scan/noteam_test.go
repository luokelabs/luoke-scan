package main

import (
	"strings"
	"testing"
)

// Only a packed copy without a release team names itself; a release (packed, with a team) and a build from source
// (not packed) say nothing more than their version.
func TestNoTeamNote(t *testing.T) {
	if got := noTeamNote(true, ""); !strings.Contains(got, noTeamWord) {
		t.Errorf("packed, no team: %q", got)
	}
	if got := noTeamNote(true, "ABCDE12345"); got != "" {
		t.Errorf("packed, with a team: %q", got)
	}
	if got := noTeamNote(false, ""); got != "" {
		t.Errorf("not packed: %q", got)
	}
	if r := luokeScan(t, false, "version"); r.code != 0 || strings.Contains(r.stdout, noTeamWord) {
		t.Errorf("the plain build's version: %d %q", r.code, r.stdout)
	}
}
