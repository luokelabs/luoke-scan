package service

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The password step's judgement and move, as this user (not root: asUser runs the body as it is). The fake system
// Library is this user's, so the rule's owner is set to this user.
func TestAdminApplyMovesOnlyWhatTheRuleStillTakes(t *testing.T) {
	root := core.Canonical(t.TempDir())
	home, lib := filepath.Join(root, "home"), filepath.Join(root, "Library")
	gone := filepath.Join(lib, "Caches/com.example.gone")
	other := filepath.Join(lib, "Caches/com.example.other")
	for _, d := range []string{filepath.Join(home, ".Trash"), filepath.Join(root, "Applications"), gone, other} {
		os.MkdirAll(d, 0o755)
	}
	old := time.Now().Add(-90 * 24 * time.Hour)
	for _, d := range []string{gone, other} {
		f := filepath.Join(d, "data.bin")
		os.WriteFile(f, make([]byte, 2<<20), 0o644)
		os.Chtimes(f, old, old)
		os.Chtimes(d, old, old)
	}
	ident := func(p string) Target {
		var st syscall.Stat_t
		syscall.Lstat(p, &st)
		return Target{Path: p, Device: int64(st.Dev), Inode: st.Ino}
	}
	rule := core.NewLeftoverRule(nil, nil).(*core.LeftoverRule)
	rule.SystemOwner = uint32(os.Getuid())
	rule.LaunchServices = false
	step := AdminApply{Home: home, UID: uint32(os.Getuid()), Apps: map[string]bool{"com.example.gone": true}, Library: lib,
		AppDirs: []string{filepath.Join(root, "Applications")}, Trash: filepath.Join(home, ".Trash"), Now: time.Now(), Rule: rule}
	plan := Plan{ID: "p-0123456789ab", Admin: true, Items: []PlanItem{
		{Key: "a0", Rule: "leftover.app-data", BundleID: "com.example.gone", Targets: []Target{ident(gone)}},
		// Not among the apps the user's process judged again: not looked at.
		{Key: "a1", Rule: "leftover.app-data", BundleID: "com.example.other", Targets: []Target{ident(other)}},
	}}
	lines := step.Run(plan, map[string]bool{"a0": true, "a1": true})
	if len(lines) != 2 {
		t.Fatalf("lines: %+v", lines)
	}
	if lines[0].Trashed == nil || !strings.HasPrefix(*lines[0].Trashed, adminReal(filepath.Join(home, ".Trash"))+"/") || core.Exists(gone) {
		t.Fatalf("a0 should be in the Trash: %+v", lines[0])
	}
	if lines[1].Error == nil || *lines[1].Error != "现在不算卸载残留了" || !core.Exists(other) {
		t.Fatalf("a1 must stay: %+v", lines[1])
	}
	// Swapped for something else since the plan: not moved.
	os.RemoveAll(other)
	os.MkdirAll(other, 0o755)
	step.Apps["com.example.other"] = true
	lines = step.Run(Plan{Admin: true, Items: []PlanItem{plan.Items[1]}}, map[string]bool{"a1": true})
	if len(lines) != 1 || lines[0].Trashed != nil || lines[0].Error == nil {
		t.Fatalf("a swapped folder must stay: %+v", lines)
	}
}

func TestNumberedAndRootCheck(t *testing.T) {
	if numbered("report.pdf", 2) != "report 2.pdf" || numbered("Cellar", 3) != "Cellar 3" {
		t.Fatal("Finder's naming")
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "x"), nil, 0o644)
	now := time.Now()
	if why := rootCheck(d, uint32(os.Getuid()), now.Add(-time.Hour), now, 10); why != "最近还在用" {
		t.Fatalf("written just now: %q", why)
	}
	old := now.Add(-48 * time.Hour)
	os.Chtimes(filepath.Join(d, "x"), old, old)
	os.Chtimes(d, old, old)
	if why := rootCheck(d, uint32(os.Getuid()), now.Add(-time.Hour), now, 10); why != "" {
		t.Fatalf("quiet and mine: %q", why)
	}
	if why := rootCheck(d, 12345, now.Add(-time.Hour), now, 10); why != "里面有别的账户的东西" {
		t.Fatalf("another account's: %q", why)
	}
}
