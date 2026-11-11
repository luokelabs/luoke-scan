package service

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// luoke-scan#101: after 「现在查一下」 the overview page shows that a round runs and how far it is, the summary says so
// (so the agent has the window draw the page again), and both go back to the results once the round is over.
func TestOverviewWhileScanning(t *testing.T) {
	root := t.TempDir()
	store, err := core.OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := core.NewContext(filepath.Join(root, "home"))
	s := New(store, NewConfig(ctx))
	page := func() string {
		b, _ := json.Marshal(s.page("overview", s.state()))
		return string(b)
	}
	summary := func() string { return s.summaryNow(s.state())["text"].(string) }

	// No round yet, one running: no button, the row instead.
	lock := core.TakeLock(store.Dir, "round.lock", 0)
	if lock == nil {
		t.Fatal("lock")
	}
	if p := page(); !strings.Contains(p, "正在查这台 Mac") || strings.Contains(p, "现在查一下") {
		t.Errorf("first round running: %s", p)
	}
	if got := summary(); got != "正在查这台 Mac，刚开始" {
		t.Errorf("summary: %q", got)
	}
	lock.Release()
	if p := page(); strings.Contains(p, "正在查这台 Mac") || !strings.Contains(p, "现在查一下") {
		t.Errorf("nothing running: %s", p)
	}
	if got := summary(); got != "还没查过这台 Mac" {
		t.Errorf("summary: %q", got)
	}

	// A last round whose checks took 10 s and 30 s; the first is done.
	now := core.Time{Time: time.Now()}
	if err := store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: []core.Finding{},
		RuleSeconds: map[string]float64{"space": 10, "malware": 30}}); err != nil {
		t.Fatal(err)
	}
	lock = core.TakeLock(store.Dir, "round.lock", 0)
	store.SaveProgress(core.RoundProgress{Started: time.Now(), Done: []string{"space"}, Total: 2, Current: "malware"})
	p := page()
	if !strings.Contains(p, "正在查这台 Mac") || !strings.Contains(p, "查了 25%，快好了") || !strings.Contains(p, `"ProgressBar","id":`) ||
		strings.Contains(p, "现在查一下") {
		t.Errorf("round running: %s", p)
	}
	if got := summary(); got != "正在查这台 Mac，查了 25%，快好了" {
		t.Errorf("summary while running: %q", got)
	}
	store.SaveProgress(core.RoundProgress{Started: time.Now(), Done: []string{"space", "malware"}, Total: 2, Current: "model"})
	if got := summary(); got != "正在查这台 Mac，都查完了，在写说明" {
		t.Errorf("summary while the model writes: %q", got)
	}
	lock.Release()
	store.ClearProgress()
	if p := page(); strings.Contains(p, "正在查这台 Mac") || !strings.Contains(p, "现在查一下") {
		t.Errorf("round over: %s", p)
	}
	if got := summary(); got != "没有要你处理的" {
		t.Errorf("summary after: %q", got)
	}
}

func TestScanProgressMinutesLeft(t *testing.T) {
	root := t.TempDir()
	store, _ := core.OpenStore(filepath.Join(root, "data"))
	s := New(store, NewConfig(core.NewContext(filepath.Join(root, "home"))))
	last := &core.Report{RuleSeconds: map[string]float64{"a": 60, "b": 240, "c": 0}}
	store.SaveProgress(core.RoundProgress{Done: []string{"a"}, Total: 3, Current: "b"})
	if what, frac := s.scanProgress(last); what != "查了 20%，大约还要 4 分钟" || frac != 0.2 {
		t.Errorf("weighed by last time: %q %v", what, frac)
	}
	if what, frac := s.scanProgress(nil); what != "查了 33%" || frac < 0.33 || frac > 0.34 {
		t.Errorf("no last round: checks done of all: %q %v", what, frac)
	}
}

// luoke-scan#122: the main body ends a request after 300 s. With too little left for the password dialog, scan_apply
// shows none and says to click again; nothing moves, the card stays.
func TestAdminApplyLeavesTimeForTheDialog(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	asked := false
	s.Config.Elevate = func([]string, string, time.Duration) Elevated { asked = true; return Elevated{Kind: "cancelled"} }
	plan := Plan{ID: "p-000000000001", Admin: true, Items: []PlanItem{{Key: "a0", Rule: "leftover.app-data.system", Title: "x",
		BundleID: "com.example.gone", Options: []string{ChoiceTrash, ChoiceKeep}, Suggested: ChoiceKeep}}}
	out, err := s.applyAdmin(plan, map[string]string{"a0": ChoiceTrash}, O{}, false, time.Now().Add(dialogLeast-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if asked || !strings.Contains(out.Text, "再点一次") || out.Done == nil || *out.Done {
		t.Errorf("asked %v, answer %+v", asked, out)
	}
}

// luoke-scan#101: once Full Disk Access is allowed, the card asking for it goes at once, not after the next round.
func TestNeedsAccessGoesOnceAllowed(t *testing.T) {
	root := t.TempDir()
	store, _ := core.OpenStore(filepath.Join(root, "data"))
	cfg := NewConfig(core.NewContext(filepath.Join(root, "home")))
	allowed := false
	cfg.FullDiskAccess = func() *bool { v := allowed; return &v }
	s := New(store, cfg)
	now := core.Time{Time: time.Now()}
	r := core.Report{StartedAt: now, FinishedAt: now, Findings: []core.Finding{},
		Skipped: []core.Skipped{{Rule: "space", Reason: core.NotLooked("下载、文稿、桌面")}}}
	kinds := func() []string {
		var out []string
		for _, it := range s.outboxOf(s.state(), &r)["items"].(A) {
			out = append(out, it.(O)["kind"].(string))
		}
		return out
	}
	if got := kinds(); len(got) != 1 || got[0] != "needs-access" {
		t.Fatalf("not allowed: %v", got)
	}
	allowed = true
	if got := kinds(); len(got) != 0 {
		t.Fatalf("allowed now: %v", got)
	}
}
