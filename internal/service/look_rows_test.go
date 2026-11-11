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

// lookCrowd: a round like the one on internal-1110-5: 「可以清掉」 with some thirty rows (kinds of three, each a row of
// its own, the 41 installers as one, AI plugins with their 「在访达里显示」), and seven kinds to look at (four apps from
// nowhere as one, the disk not encrypted, five programs that start with the computer). extra: kinds of three more to
// clean.
func lookCrowd(t *testing.T, extra int) *Service {
	m := newModelSetup(t)
	home := m.ctx.Home
	file := func(rel string) string {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().AddDate(0, 0, -30)
		os.Chtimes(p, old, old)
		return p
	}
	opened := time.Now().AddDate(-2, 0, 0).Format("2006-01-02")
	var fs []core.Finding
	for i := 0; i < 41; i++ {
		app, v := fmt.Sprintf("App%02d", i), fmt.Sprintf("1.%d.2", i)
		fs = append(fs, core.Finding{Rule: "leftover.installer", Category: core.CatLeftover, Severity: core.Low, Verdict: core.Confirm,
			Path: file(fmt.Sprintf("Downloads/%s-%s.dmg", app, v)), Bytes: core.Size(int64(i+1) * 1_000_000),
			Evidence: map[string]string{"days": "30", "installed": app, "exact": app, "downloaded": "1", "signed": "1",
				"installer_version": v, "app_version": v}})
	}
	for i := 0; i < 3; i++ {
		fs = append(fs, core.Finding{Rule: "stale.large-file", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm,
			Path: file(fmt.Sprintf("Movies/clip-%02d.mov", i)), Bytes: core.Size(int64(i+1) * 900_000_000),
			Evidence: map[string]string{"last_opened": opened}})
		dir := filepath.Join(home, fmt.Sprintf(".claude/skills/helper-%d", i))
		file(filepath.Join(fmt.Sprintf(".claude/skills/helper-%d", i), "SKILL.md"))
		fs = append(fs, core.Finding{Rule: "skill.exec", Category: core.CatSkill, Severity: core.High, Verdict: core.Info, Path: dir,
			Title: "skill", Evidence: map[string]string{"skill": fmt.Sprintf("helper-%d", i), "agent": "Claude Code",
				"scope": string(core.ScopePersonal)}})
	}
	for k := 0; k < 7+extra; k++ {
		for i := 0; i < 3; i++ {
			id := fmt.Sprintf("com.example.Old%02d%d", k, i)
			file("Library/Application Support/" + id + "/data")
			fs = append(fs, core.Finding{Rule: fmt.Sprintf("leftover.kind-%02d", k), Category: core.CatLeftover, Severity: core.Low,
				Verdict: core.Confirm, Path: filepath.Join(home, "Library/Application Support", id),
				Bytes: core.Size(int64(200-k)*1_000_000 + int64(i)), Evidence: map[string]string{"bundle_id": id}})
		}
	}
	for i := 0; i < 4; i++ {
		file(fmt.Sprintf("Applications/Tool.%d.Beta.app/Contents/Info.plist", i))
		fs = append(fs, core.Finding{Rule: "apps.unsigned", Category: core.CatMalware, Severity: core.Medium, Verdict: core.Confirm,
			Path: filepath.Join(home, fmt.Sprintf("Applications/Tool.%d.Beta.app", i)), Title: "unsigned"})
	}
	fs = append(fs, core.Finding{Rule: "posture.filevault", Category: core.CatPosture, Severity: core.Medium, Verdict: core.Confirm, Title: "FileVault"})
	for i := 0; i < 5; i++ {
		fs = append(fs, core.Finding{Rule: fmt.Sprintf("startup.kind-%02d", i), Category: core.CatPersistence, Severity: core.Medium,
			Verdict: core.Confirm, Path: file(fmt.Sprintf("Library/LaunchAgents/io.example.prog-%02d.plist", i)),
			Evidence: map[string]string{"scope": "user-agent", "label": fmt.Sprintf("io.example.prog-%02d", i),
				"program": fmt.Sprintf("~/Library/Application Support/x/prog-%02d", i)}})
	}
	now := core.Time{Time: time.Now()}
	s := m.service(nil, nil)
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	return s
}

func withEveryFeature() map[string]bool {
	f := map[string]bool{"countWeights": true}
	for k := range allFeatures {
		f[k] = true
	}
	for k := range everyFeature {
		f[k] = true
	}
	return f
}

// Seven kinds to look at under some thirty rows to clean: every kind a line of its own with its button (an item row
// where the core draws them), the sixth and seventh folded in 「还有 2 类」; every item to clean its choice; within 200.
// Not 「这几类怎么处理写在报告里」: there is no report to open.
func TestSevenKindsToLookAtEachKeepALine(t *testing.T) {
	s := lookCrowd(t, 0)
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	groups := groupLook(v.look)
	if len(groups) != 7 {
		var keys []string
		for _, g := range groups {
			keys = append(keys, g.key)
		}
		t.Fatalf("%d kinds to look at: %v", len(groups), keys)
	}
	// rows to clean: a kind of many is one (planGroups), any other item one each; not the caches' line
	inGroup := map[string]bool{}
	gs := planGroups(v.plan.Items)
	for _, g := range gs {
		for _, it := range g.items {
			inGroup[it.Key] = true
		}
	}
	entries := len(gs)
	for _, it := range v.plan.Items {
		if it.Suggested != ChoiceRemove && !inGroup[it.Key] {
			entries++
		}
	}
	for _, features := range []map[string]bool{nil, withEveryFeature()} {
		label := fmt.Sprintf("features %v", features != nil)
		comps, choices := cardParts(t, s.page("overview", s.state(), features))
		t.Logf("%s: %d components, %d plan items", label, len(comps), len(v.plan.Items))
		if len(comps) > CardMaxComponents {
			t.Errorf("%s: %d components", label, len(comps))
		}
		byID := map[string]map[string]any{}
		parent := map[string]string{}
		for _, c := range comps {
			byID[c["id"].(string)] = c
			if kids, ok := c["children"].([]any); ok {
				for _, k := range kids {
					parent[k.(string)] = c["id"].(string)
				}
			}
		}
		all := texts(comps)
		for _, x := range all {
			if strings.Contains(x, "写在报告里") || strings.Contains(x, "这一页放不下") {
				t.Errorf("%s: %q", label, x)
			}
		}
		for _, g := range groups {
			title, _, _ := s.plainGroup(g)
			var at string
			for _, c := range comps {
				if c["component"] == "Text" && c["text"] == title {
					at = c["id"].(string)
				}
			}
			if at == "" {
				t.Errorf("%s: kind %q is not a line of its own", label, title)
				continue
			}
			if features == nil {
				continue
			}
			// an item row: the title's row (spaceBetween) holds a button, or the fold right under it does (each app
			// in the Finder: 「在访达里逐个看」)
			row := at
			for row != "" && byID[row]["justify"] != "spaceBetween" {
				row = parent[row]
			}
			next := ""
			if kids, _ := byID[parent[row]]["children"].([]any); row != "" {
				for i, k := range kids {
					if k == row && i+1 < len(kids) {
						next = kids[i+1].(string)
					}
				}
			}
			if row == "" || !(hasButton(byID, row) || (byID[next]["collapsed"] != nil && hasButton(byID, next))) {
				t.Errorf("%s: kind %q has no item row with a button", label, title)
			}
		}
		if features != nil {
			folded := false
			for _, c := range comps {
				if sum, _ := c["collapsed"].(string); strings.HasPrefix(sum, "还有 2 类") {
					folded = true
				}
			}
			if !folded {
				t.Errorf("%s: the sixth and seventh kinds are not folded", label)
			}
		}
		ids := map[string]bool{}
		for _, c := range comps {
			ids[c["id"].(string)] = true
		}
		kind := map[string]string{}
		for _, g := range planGroups(v.plan.Items) {
			for _, it := range g.items {
				kind[it.Key] = g.key
			}
		}
		for _, it := range v.plan.Items {
			if it.Suggested == ChoiceRemove {
				continue // the caches' line
			}
			if !ids["c-"+it.Key] && !ids["c-"+kind[it.Key]] {
				t.Errorf("%s: no choice for %s (%s)", label, it.Key, it.Rule)
			}
		}
		_ = choices
	}
	if entries < 25 {
		t.Errorf("only %d rows to clean", entries)
	}
	t.Logf("%d rows to clean", entries)
}

func hasButton(byID map[string]map[string]any, id string) bool {
	c := byID[id]
	if c == nil {
		return false
	}
	if c["component"] == "Button" {
		return true
	}
	kids, _ := c["children"].([]any)
	for _, k := range kids {
		if hasButton(byID, k.(string)) {
			return true
		}
	}
	return false
}

// Far more rows than a page holds even as choices alone: the page stays within 200, the rows past the room are not
// drawn and stay 先不动 (the button does nothing to what the page does not show), and a line says how many.
func TestRowsPastThePageStayAsTheyAre(t *testing.T) {
	s := lookCrowd(t, 70)
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	for _, features := range []map[string]bool{nil, withEveryFeature()} {
		label := fmt.Sprintf("features %v", features != nil)
		comps, choices := cardParts(t, s.page("overview", s.state(), features))
		if len(comps) > CardMaxComponents {
			t.Errorf("%s: %d components", label, len(comps))
		}
		ids := map[string]bool{}
		for _, c := range comps {
			ids[c["id"].(string)] = true
		}
		kind := map[string]string{}
		for _, g := range planGroups(v.plan.Items) {
			for _, it := range g.items {
				kind[it.Key] = g.key
			}
		}
		left := 0
		for _, it := range v.plan.Items {
			k := it.Key
			if kind[k] != "" {
				k = kind[k]
			}
			if it.Suggested == ChoiceRemove || ids["c-"+k] {
				continue
			}
			left++
			if got, _ := choices[k].([]any); len(got) != 1 || got[0] != ChoiceKeep {
				t.Errorf("%s: %s is off the page but chosen %v", label, k, choices[k])
			}
		}
		if left == 0 {
			t.Fatalf("%s: every row fit (%d components); make the round bigger", label, len(comps))
		}
		note := fmt.Sprintf("还有 %d 项这一页放不下，这次先不动。", left)
		if !strings.Contains(strings.Join(texts(comps), "\n"), note) {
			t.Errorf("%s: no %q", label, note)
		}
	}
}
