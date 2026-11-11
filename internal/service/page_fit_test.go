package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

var allFeatures = map[string]bool{"lucide": true, "itemIcons": true, "badge": true, "collapsed": true, "optionIcons": true,
	"strong": true, "maxLines": true, "tooltip": true, "placement": true}

// A long round (a full plan to choose in, many kinds to look at): the page stays within the card's 200 components
// and still has every item's choice and every kind, with item rows or without.
func TestALongRoundFitsOnThePage(t *testing.T) {
	m := newModelSetup(t)
	home := m.ctx.Home
	file := func(rel string) string {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	opened := time.Now().AddDate(-2, 0, 0).Format("2006-01-02")
	var fs []core.Finding
	for i := 0; i < 30; i++ {
		fs = append(fs, core.Finding{Rule: "stale.large-file", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm,
			Path: file(fmt.Sprintf("Movies/clip-%02d.mov", i)), Bytes: core.Size(int64(i+1) * 1_000_000_000),
			Evidence: map[string]string{"last_opened": opened}})
	}
	var kinds []string
	for i := 0; i < 40; i++ {
		prog := fmt.Sprintf("~/Library/Application Support/x/prog-%02d", i)
		fs = append(fs, core.Finding{Rule: fmt.Sprintf("startup.kind-%02d", i), Category: core.CatPersistence, Severity: core.Medium,
			Verdict: core.Confirm, Path: file(fmt.Sprintf("Library/LaunchAgents/io.example.prog-%02d.plist", i)),
			Evidence: map[string]string{"scope": "user-agent", "label": fmt.Sprintf("io.example.prog-%02d", i), "program": prog}})
		kinds = append(kinds, fmt.Sprintf("prog-%02d", i))
	}
	now := core.Time{Time: time.Now()}
	s := m.service(nil, nil)
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	if v.plan == nil || len(v.plan.Items) != 30 {
		t.Fatalf("plan %+v", v.plan)
	}
	for _, features := range []map[string]bool{nil, allFeatures} {
		msgs := s.page("overview", s.state(), features)
		comps, _ := cardParts(t, msgs)
		if len(comps) > CardMaxComponents {
			t.Errorf("features %v: %d components", features != nil, len(comps))
		}
		ids := map[string]bool{}
		for _, c := range comps {
			ids[c["id"].(string)] = true
		}
		// Each item has its choice, or its kind's one (the 30 big files are one kind: one row, planGroups)
		kind := map[string]string{}
		for _, g := range planGroups(v.plan.Items) {
			for _, it := range g.items {
				kind[it.Key] = g.key
			}
		}
		for _, it := range v.plan.Items {
			if !ids["c-"+it.Key] && !ids["c-"+kind[it.Key]] {
				t.Errorf("features %v: no choice for %s", features != nil, it.Key)
			}
		}
		all := strings.Join(texts(comps), "\n")
		for _, k := range kinds {
			if !strings.Contains(all, "「"+k+"」") {
				t.Errorf("features %v: kind %s is not on the page", features != nil, k)
			}
		}
		if strings.Contains(all, "没列出") {
			t.Errorf("features %v: a kind left out", features != nil)
		}
	}
}

// 自动清理 is a switch: off with what turning it on cleans, on with what it cleans; a click sends the other state.
func TestAutocleanIsASwitch(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	sw := func() (map[string]any, []string) {
		comps, _ := cardParts(t, s.page("overview", s.state()))
		for _, c := range comps {
			if c["component"] == "Button" && c["variant"] == "switch" {
				return c, texts(comps)
			}
		}
		t.Fatal("no switch")
		return nil, nil
	}
	ctx := func(b map[string]any) any {
		return b["action"].(map[string]any)["event"].(map[string]any)["context"].(map[string]any)["on"]
	}
	b, ts := sw()
	if b["on"] != false || ctx(b) != true || indexOf(ts, "打开后，每天那一轮") < 0 || indexOf(ts, "自动清理") < 0 {
		t.Errorf("off: %v %q", b, ts)
	}
	if _, err := s.setAutoclean(O{"on": true}, nil); err != nil {
		t.Fatal(err)
	}
	if b, ts = sw(); b["on"] != true || ctx(b) != false || indexOf(ts, "每天那一轮不用你点就清：") < 0 {
		t.Errorf("on: %v %q", b, ts)
	}
	// Every kind turned off one by one draws as off; switching it on turns them all on
	s.mutate(func(st *State) {
		st.AutoOff = map[string]core.Time{}
		for _, k := range AutoKinds {
			st.AutoOff[string(k)] = core.Time{Time: time.Now()}
		}
	})
	if b, _ = sw(); b["on"] != false {
		t.Errorf("every kind off: %v", b)
	}
	if _, err := s.setAutoclean(O{"on": true}, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ = sw(); b["on"] != true || len(s.state().AutoOff) != 0 {
		t.Errorf("after switching on: %v %v", b, s.state().AutoOff)
	}
}

// 「要你看看」 leaves just what follows it (what was not checked, the side column) and no more: a page with a full
// 「可以清掉」 still draws each of six kinds as its own line where the core draws item rows, with room to spare for
// nothing more than one line; none of them is pushed into the one line that only names the kinds.
func TestLookUsesTheRoomLeft(t *testing.T) {
	m := newModelSetup(t)
	home := m.ctx.Home
	file := func(rel string) string {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	opened := time.Now().AddDate(-2, 0, 0).Format("2006-01-02")
	var fs []core.Finding
	for i := 0; i < pageDecideFirst+1; i++ {
		fs = append(fs, core.Finding{Rule: "stale.large-file", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm,
			Path: file(fmt.Sprintf("Movies/clip-%02d.mov", i)), Bytes: core.Size(int64(i+1) * 1_000_000_000),
			Evidence: map[string]string{"last_opened": opened}})
	}
	var kinds []string
	for i := 0; i < pageLookFirst+1; i++ {
		fs = append(fs, core.Finding{Rule: fmt.Sprintf("startup.kind-%02d", i), Category: core.CatPersistence, Severity: core.Medium,
			Verdict: core.Confirm, Path: file(fmt.Sprintf("Library/LaunchAgents/io.example.prog-%02d.plist", i)),
			Evidence: map[string]string{"scope": "user-agent", "label": fmt.Sprintf("io.example.prog-%02d", i),
				"program": fmt.Sprintf("~/Library/Application Support/x/prog-%02d", i)}})
		kinds = append(kinds, fmt.Sprintf("prog-%02d", i))
	}
	now := core.Time{Time: time.Now()}
	s := m.service(nil, nil)
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	features := map[string]bool{"countLabel": true, "openPage": true}
	for k := range allFeatures {
		features[k] = true
	}
	comps, _ := cardParts(t, s.page("overview", s.state(), features))
	t.Logf("%d components", len(comps))
	if len(comps) > CardMaxComponents {
		t.Fatalf("%d components", len(comps))
	}
	all := texts(comps)
	for _, x := range all {
		if strings.Contains(x, "这几类怎么处理写在报告里") {
			t.Errorf("kinds only named (%d components): %q", len(comps), x)
		}
	}
	for _, k := range kinds {
		found := false
		for _, x := range all {
			found = found || (strings.Contains(x, "「"+k+"」") && !strings.Contains(x, "\n"))
		}
		if !found {
			t.Errorf("kind %s is not a line of its own", k)
		}
	}
}
