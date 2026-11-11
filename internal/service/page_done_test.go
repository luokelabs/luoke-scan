package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// ownTrash: the service moves to a Trash folder of the test's own, never the Mac's.
func ownTrash(t *testing.T, s *Service) {
	trash := filepath.Join(t.TempDir(), "Trash")
	os.MkdirAll(trash, 0o755)
	s.Config.Trash = func(p string) (string, error) { return trashInto(trash, p) }
	s.Config.TrashFolders = []string{trash}
}

// backdate: as a round finds files, not changed since it looked.
func backdate(paths ...string) {
	old := time.Now().AddDate(0, 0, -30)
	for _, p := range paths {
		os.Chtimes(p, old, old)
	}
}

// clickOn: the user clicks a scan_apply button (its context), on a card or on the scan page (surface).
func clickOn(t *testing.T, s *Service, surface string, ctx map[string]any) ToolOutput {
	t.Helper()
	meta := O{metaCapabilities: O{"experimental": O{"ai.luoke/a2ui": O{"features": A{"openPage", "countLabel", "countAlso", "countWeights"}}}},
		UserAction: map[string]any{"surfaceId": surface, "componentId": "b", "at": time.Now().Format(time.RFC3339)}}
	out, err := s.apply(O{"plan_id": ctx["plan_id"], "choices": ctx["choices"]}, meta)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// urgentItem: the urgent card in 「今天」 for the finding with this name in its title, as a core with every feature reads
// the outbox, and its card's components; nil when the outbox has none.
func urgentItem(t *testing.T, s *Service, name string) (map[string]any, []map[string]any) {
	t.Helper()
	r := s.Store.LastReport()
	b, _ := json.Marshal(s.outboxOf(s.state(), r, everyFeature))
	var box struct {
		Items []map[string]any `json:"items"`
	}
	json.Unmarshal(b, &box)
	for _, it := range box.Items {
		if it["kind"] == "security" && strings.Contains(fmt.Sprint(it["title"]), name) {
			card, _ := json.Marshal(it["card"])
			var msgs []any
			json.Unmarshal(card, &msgs)
			comps, _ := cardParts(t, msgs)
			return it, comps
		}
	}
	return nil, nil
}

// withVirus: the model setup's round with a file the virus database recognised in Downloads.
func withVirus(t *testing.T) (*Service, core.Finding) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	ownTrash(t, s)
	virus := filepath.Join(m.ctx.Home, "Downloads/invoice.com")
	os.MkdirAll(filepath.Dir(virus), 0o755)
	if err := os.WriteFile(virus, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	backdate(virus)
	f := core.Finding{Rule: "malware.clamav", Category: core.CatMalware, Severity: core.High, Verdict: core.Confirm, Path: virus,
		Bytes: core.Size(1), Title: "病毒库认出 invoice.com 是 Eicar-Test-Signature",
		Evidence: map[string]string{"signature": "Eicar-Test-Signature", "how": "移到废纸篓；如果是你刚下载的，别打开它"}}
	r := m.report
	r.Findings = append(r.Findings, f)
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	return s, f
}

// A virus taken care of from its urgent card in 「今天」, then the scan page opened (internal-1110-5: it was still under
// 「要尽快处理」, and 「移到废纸篓」 there only said 「1 项找不到，已跳过」): gone from the page, from the counts, from 「今天」.
// Moved to the Trash by the card; or deleted in the Finder first, the card's click finding it gone (「找不到，已跳过」).
// The same when that click is on the scan page.
func TestScanPageLeavesOutTheVirusTakenCareOfFromToday(t *testing.T) {
	for _, c := range []struct {
		name               string
		deletedInFinder    bool
		clickOnTheScanPage bool
		said               string
	}{
		{"moved by the urgent card", false, false, "移到废纸篓"},
		{"deleted in the Finder, then the urgent card", true, false, "1 项找不到，已跳过"},
		{"deleted in the Finder, then the scan page", true, true, "1 项找不到，已跳过"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, f := withVirus(t)
			before := s.summary(s.state())
			page, _ := cardParts(t, s.page("overview", s.state(), everyFeature))
			card, cardComps := urgentItem(t, s, "invoice.com")
			if indexOf(texts(page), "要尽快处理 1") < 0 || card == nil {
				t.Fatalf("before: page %q, card %v", texts(page), card)
			}
			if c.deletedInFinder {
				os.Remove(f.Path)
			}
			comps, surface := cardComps, fmt.Sprint(card["id"])
			if c.clickOnTheScanPage {
				comps, surface = page, "luoke-scan/page/overview"
			}
			b := buttonsOf(comps)["移到废纸篓"]
			if b == nil {
				t.Fatalf("no 移到废纸篓: %v", buttonsOf(comps))
			}
			_, ctx := eventOf(b)
			if out := clickOn(t, s, surface, ctx); core.Exists(f.Path) || !strings.HasPrefix(out.Text, c.said) {
				t.Fatalf("answer %q, there %v", out.Text, core.Exists(f.Path))
			}

			page, choices := cardParts(t, s.page("overview", s.state(), everyFeature))
			if all := strings.Join(texts(page), "\n"); strings.Contains(all, "要尽快处理") || strings.Contains(all, "invoice.com") {
				t.Errorf("the virus is still on the page: %q", all)
			}
			r := *s.Store.LastReport()
			v := s.roundView(s.visible(r, s.state()), r, roundID(r))
			for _, it := range v.plan.Items {
				if it.FindingID == s.fid(f) && !reflect.DeepEqual(choices[it.Key], []any{ChoiceKeep}) {
					t.Errorf("its choice %v: the page's button would try it again", choices[it.Key])
				}
			}
			after := s.summary(s.state())
			if after["count"].(int) != before["count"].(int)-1 || strings.Contains(after["text"].(string), "要尽快") {
				t.Errorf("summary %v, before %v", after, before)
			}
			if card, _ := urgentItem(t, s, "invoice.com"); card != nil {
				t.Errorf("still in 「今天」: %v", card)
			}
		})
	}
}

// Something deleted outside 螺壳 (in the Finder) and then clicked on the scan page: 「找不到，已跳过」, and it is gone from
// the page, the counts and the round's card right away (State.Gone), not a round later. A later round that finds it
// again lists it again.
func TestScanPageLeavesOutWhatAClickFoundGone(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	ownTrash(t, s)
	backdate(pc.installer.Path, pc.big.Path)
	r := *s.Store.LastReport()
	comps, choices := cardParts(t, s.page("overview", s.state(), everyFeature))
	toLook := s.roundView(s.visible(r, s.state()), r, roundID(r)).toLook
	count := s.summary(s.state())["count"].(int)
	all := button(comps, "移到废纸篓 {n} 项")
	if all == nil {
		t.Fatalf("no bottom button: %v", buttonsOf(comps))
	}
	os.Remove(pc.installer.Path) // in the Finder, before the click
	if out := clickOn(t, s, "luoke-scan/page/overview", map[string]any{"plan_id": all["plan_id"], "choices": choices}); !strings.HasPrefix(out.Text, "1 项找不到，已跳过") {
		t.Fatalf("answer %q", out.Text)
	}
	if _, ok := s.state().Gone[s.fid(pc.installer)]; !ok {
		t.Errorf("not written down: %v", s.state().Gone)
	}
	comps, choices = cardParts(t, s.page("overview", s.state(), everyFeature))
	ts := texts(comps)
	if indexOf(ts, "ModelBox 的安装包") >= 0 || indexOf(ts, "可以清掉 2") < 0 || indexOf(ts, "家庭录像_01.avi") < 0 {
		t.Errorf("page after %q", ts)
	}
	v := s.roundView(s.visible(r, s.state()), r, roundID(r))
	if v.toLook != toLook-1 || s.summary(s.state())["count"].(int) != count-1 {
		t.Errorf("toLook %d (before %d), count %v (before %d)", v.toLook, toLook, s.summary(s.state())["count"], count)
	}
	if title, _ := s.decisionsBody(NewCard("round"), r, s.state(), s.visible(r, s.state()), roundID(r)); strings.Contains(title, "830.9 MB") {
		t.Errorf("the round's card still offers it: %q", title)
	}
	// Nothing at all chosen for the Trash now: the bottom button counts 0 (the core does not draw it)
	if b := button(comps, "移到废纸篓 {n} 项"); b == nil || countChosen(choices, ChoiceTrash) != 0 {
		t.Errorf("bottom button %v", b)
	}

	// The next round finds it again (put there again): listed again
	if err := os.WriteFile(pc.installer.Path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	next := pc.report
	next.StartedAt = core.Time{Time: time.Now().Add(time.Second)}
	next.FinishedAt = next.StartedAt
	if err := s.Store.SaveReport(next); err != nil {
		t.Fatal(err)
	}
	comps, _ = cardParts(t, s.page("overview", s.state(), everyFeature))
	if ts = texts(comps); indexOf(ts, "ModelBox 的安装包") < 0 {
		t.Errorf("the next round's page %q", ts)
	}
}

// The scan page's bottom button: what it moved is gone from the page when the page is read again (internal-1110-5: the
// rows stayed, and the button still counted them); what the user left 「先不动」 stays. Put back, it is offered again.
func TestScanPageLeavesOutWhatItsButtonMoved(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	ownTrash(t, s)
	r := *s.Store.LastReport() // as stored: the clean-up record's times are to the second too
	backdate(pc.installer.Path, pc.big.Path)
	comps, choices := cardParts(t, s.page("overview", s.state(), everyFeature))
	ts := texts(comps)
	if indexOf(ts, "可以清掉 3") < 0 || indexOf(ts, "ModelBox 的安装包") < 0 {
		t.Fatalf("page before %q", ts)
	}
	all := button(comps, "按上面的选择清理")
	if all == nil {
		all = button(comps, "移到废纸篓 {n} 项")
	}
	if all == nil {
		t.Fatalf("no bottom button: %v", buttonsOf(comps))
	}
	toLook := s.roundView(s.visible(r, s.state()), r, roundID(r)).toLook
	// what the page's data model holds is what the core sends for {"path": "/choices"}
	out := clickOn(t, s, "luoke-scan/page/overview", map[string]any{"plan_id": all["plan_id"], "choices": choices})
	if core.Exists(pc.installer.Path) || !core.Exists(pc.big.Path) {
		t.Fatalf("installer there %v, big file there %v: %q", core.Exists(pc.installer.Path), core.Exists(pc.big.Path), out.Text)
	}

	comps, choices = cardParts(t, s.page("overview", s.state(), everyFeature))
	ts = texts(comps)
	if indexOf(ts, "ModelBox 的安装包") >= 0 || indexOf(ts, "可以清掉 2") < 0 || indexOf(ts, "家庭录像_01.avi") < 0 {
		t.Errorf("page after %q", ts)
	}
	v := s.roundView(s.visible(r, s.state()), r, roundID(r))
	ik := ""
	for _, it := range v.plan.Items {
		if it.FindingID == s.fid(pc.installer) {
			ik = it.Key
		}
	}
	if !reflect.DeepEqual(choices[ik], []any{ChoiceKeep}) {
		t.Errorf("installer's choice %v", choices[ik])
	}
	if v.toLook != toLook-1 || v.bytes != *pc.cache.Bytes || len(v.trash) != 1 || v.trash[0].FindingID != s.fid(pc.cache) {
		t.Errorf("toLook %d (before %d), bytes %d, trash %v: what is left to free is the cache", v.toLook, toLook, v.bytes, v.trash)
	}
	if title, _ := s.decisionsBody(NewCard("round"), r, s.state(), s.visible(r, s.state()), roundID(r)); strings.Contains(title, "830.9 MB") {
		t.Errorf("the round's card still offers it: %q", title)
	}

	// 放回: there again, and offered again
	if _, err := s.restoreTool(O{"id": all["plan_id"]}, O{}); err != nil || !core.Exists(pc.installer.Path) {
		t.Fatalf("restore: %v, there %v", err, core.Exists(pc.installer.Path))
	}
	comps, _ = cardParts(t, s.page("overview", s.state(), everyFeature))
	if ts = texts(comps); indexOf(ts, "ModelBox 的安装包") < 0 || indexOf(ts, "可以清掉 3") < 0 {
		t.Errorf("page after 放回 %q", ts)
	}
}

// A record from before the round started is not this round's: the round found it again (put back by hand, or back).
func TestItemsCleanedOnlySinceTheRoundStarted(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := *s.Store.LastReport()
	v := s.roundView(s.visible(r, s.state()), r, roundID(r))
	var it PlanItem
	for _, x := range v.plan.Items {
		if x.FindingID == s.fid(pc.installer) {
			it = x
		}
	}
	old := Cleaned{ID: "c-old", Batch: "p-old", At: core.Time{Time: r.StartedAt.Add(-time.Hour)}, Rule: it.Rule,
		Original: it.Targets[0].Path, Trashed: strPtr(filepath.Join(s.Config.Context.Home, ".Trash/x"))}
	if err := s.cleanLog().append([]cleanLine{{Op: "trashed", Entry: &old}}, s.now()); err != nil {
		t.Fatal(err)
	}
	if got := s.itemsCleaned(*v.plan, r); got[it.Key] {
		t.Errorf("a record from before the round counts: %v", got)
	}
	// the same an hour later is this round's; by another rule it is not this item
	other := old
	other.ID, other.At, other.Rule = "c-other", core.Time{Time: r.StartedAt.Add(time.Hour)}, "stale.large-file"
	now := old
	now.ID, now.At = "c-now", core.Time{Time: r.StartedAt.Add(time.Hour)}
	if err := s.cleanLog().append([]cleanLine{{Op: "trashed", Entry: &other}}, s.now()); err != nil {
		t.Fatal(err)
	}
	if got := s.itemsCleaned(*v.plan, r); got[it.Key] {
		t.Errorf("another rule's record counts: %v", got)
	}
	if err := s.cleanLog().append([]cleanLine{{Op: "trashed", Entry: &now}}, s.now()); err != nil {
		t.Fatal(err)
	}
	if got := s.itemsCleaned(*v.plan, r); !got[it.Key] || len(got) != 1 {
		t.Errorf("this round's record: %v", got)
	}
}

// Everything the round found went with a click: the sidebar says there is nothing to do, not 「0 项等你处理」.
func TestSummaryWhenEverythingWent(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	ownTrash(t, s)
	backdate(pc.installer.Path)
	r := pc.report
	r.Findings = []core.Finding{pc.installer}
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	if sm := s.summary(s.state()); sm["count"].(int) != 1 || !strings.HasPrefix(sm["text"].(string), "能清出 830.9 MB") {
		t.Fatalf("before: %v", sm)
	}
	comps, choices := cardParts(t, s.page("overview", s.state(), everyFeature))
	all := button(comps, "移到废纸篓 {n} 项")
	if all == nil {
		t.Fatalf("no bottom button: %v", buttonsOf(comps))
	}
	clickOn(t, s, "luoke-scan/page/overview", map[string]any{"plan_id": all["plan_id"], "choices": choices})
	if sm := s.summary(s.state()); sm["count"].(int) != 0 || sm["text"] != "没有要你处理的" {
		t.Errorf("after: %v", sm)
	}
}
