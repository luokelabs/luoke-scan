package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

func TestPermissionOff(t *testing.T) {
	for value, want := range map[string]bool{"": false, "fda": true, "auto,fda": true, "auto, fda ": true, "auto": false, "fda2": false, "xfda,auto": false} {
		t.Setenv(PermissionsOffEnv, value)
		if PermissionOff("fda") != want {
			t.Errorf("%q: want %v", value, want)
		}
	}
}

// The probe finds a fake TCC database in a fake home, so it says yes without asking of this Mac; switched off it is no.
func TestFullDiskAccessNowSwitchedOff(t *testing.T) {
	home := t.TempDir()
	db := filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for value, want := range map[string]bool{"": true, "auto": true, "fda": false, "auto,fda": false} {
		t.Setenv(PermissionsOffEnv, value)
		if v := FullDiskAccessNow(home); v == nil || *v != want {
			t.Errorf("%q: want %v, got %v", value, want, v)
		}
	}
}

func accessReport() core.Report {
	return core.Report{FinishedAt: core.Time{Time: core.FixtureNow},
		Skipped: []core.Skipped{{Rule: "permission.stale-grant", Reason: "读不了 TCC.db（需要完全磁盘访问）"}}}
}

func kinds(o O) map[string]bool {
	out := map[string]bool{}
	for _, it := range o["items"].(A) {
		out[it.(O)["kind"].(string)] = true
	}
	return out
}

// Denied by macOS or not allowed for this app: asked for, and the permissions resource says denied either way.
func TestNeedsAccessRaisedWhenSwitchedOff(t *testing.T) {
	no := false
	r := accessReport()
	denied := &Service{Config: Config{FullDiskAccess: func() *bool { return &no }}}
	if !kinds(denied.outboxOf(State{}, &r))["needs-access"] {
		t.Fatal("denied by macOS: no needs-access")
	}
	want := denied.permissionStates(State{})["fda"]

	t.Setenv(PermissionsOffEnv, "fda")
	s := &Service{Config: FixtureConfig(core.Layout{Root: t.TempDir()}, nil)}
	if !kinds(s.outboxOf(State{}, &r))["needs-access"] {
		t.Fatal("not allowed here yet: no needs-access to ask with")
	}
	if got := s.permissionStates(State{})["fda"]; got != want || got != "denied" {
		t.Fatalf("switched off: %v, denied: %v", got, want)
	}
	if !s.Config.Context.AccessOff || s.Config.Context.MayLook(filepath.Join(s.Config.Context.Home, "Documents")) {
		t.Fatal("switched off: the round would look")
	}

	t.Setenv(PermissionsOffEnv, "auto")
	if !kinds(denied.outboxOf(State{}, &r))["needs-access"] {
		t.Fatal("another permission off: no needs-access")
	}
}
