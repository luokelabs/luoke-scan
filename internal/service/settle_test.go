package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// bunCache: Bun's rebuildable cache in the case's home, with Bun running.
func bunCache(t *testing.T, s *Service, home string) core.Finding {
	dir := filepath.Join(home, ".bun/install/cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "left-pad.tgz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Config.Running = func() map[string]bool { return map[string]bool{"bun": true} }
	return core.Finding{Rule: "cache.rebuildable.bun", Category: core.CatCache, Severity: core.Low, Verdict: core.Safe, Path: dir,
		Bytes: core.Size(601_800_000), Title: "Bun 的缓存，删了会自动重建"}
}

// outboxItem: the item of this kind in the outbox, and its card's components and choices; nil when there is none.
func outboxItem(t *testing.T, s *Service, kind string) (map[string]any, []map[string]any, map[string]any) {
	b, _ := json.Marshal(s.outboxOf(s.state(), s.Store.LastReport(), map[string]bool{"openPage": true}))
	var box struct {
		Items []map[string]any `json:"items"`
	}
	json.Unmarshal(b, &box)
	for _, it := range box.Items {
		if it["kind"] == kind {
			card, _ := json.Marshal(it["card"])
			var msgs []any
			json.Unmarshal(card, &msgs)
			comps, choices := cardParts(t, msgs)
			return it, comps, choices
		}
	}
	return nil, nil, nil
}

// The low-space card in 「今天」: 「腾出 …」 deletes the rebuildable caches, and the one whose tool is running stays.
// Nothing is left to click on the answer, so the card is done with (it leaves 「要你决定」 and the outbox) instead of
// staying there with nothing to decide; the cache that stayed is still on the round's card.
func TestLowSpaceCardIsDoneWhenACacheToolRuns(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	bun := bunCache(t, s, s.Config.Context.Home)
	low := core.Finding{Rule: "space.low", Category: core.CatSpace, Severity: core.Medium, Verdict: core.Info,
		Title: "磁盘只剩 15 GB", Evidence: map[string]string{"total": "460 GB"}}
	r := pc.report
	r.Findings = append([]core.Finding{low, bun}, r.Findings...) // pip's cache is in it already
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	item, comps, choices := outboxItem(t, s, "space")
	if item == nil {
		t.Fatal("no low-space card")
	}
	var free map[string]any
	for words, b := range buttonsOf(comps) {
		if strings.HasPrefix(words, "腾出 ") {
			free = b
		}
	}
	if free == nil {
		t.Fatalf("no 腾出 on the card: %q", texts(comps))
	}
	_, ctx := eventOf(free)
	meta := O{UserAction: map[string]any{"surfaceId": "space-" + core.ShortHash(item["id"].(string)), "componentId": free["id"],
		"at": time.Now().Format(time.RFC3339)}}
	out, err := s.apply(O{"plan_id": ctx["plan_id"], "choices": choices}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if core.Exists(pc.cache.Path) || !core.Exists(bun.Path) {
		t.Fatalf("pip's cache there %v, Bun's there %v", core.Exists(pc.cache.Path), core.Exists(bun.Path))
	}
	if out.Done == nil || !*out.Done {
		t.Errorf("done %v: %q", out.Done, out.Text)
	}
	if !strings.HasPrefix(out.Text, "删掉会重建的缓存 1 项") || !strings.Contains(out.Text, "，1 项未能清理。") ||
		strings.Contains(out.Text, "找不到") || !strings.Contains(out.Text, "Bun 正在跑") {
		t.Errorf("answer %q", out.Text)
	}
	answer, _ := cardParts(t, out.Card)
	if !strings.Contains(strings.Join(texts(answer), "\n"), "Bun 的缓存：未能清理，Bun 正在跑") {
		t.Errorf("answer card %q", texts(answer))
	}
	if again, _, _ := outboxItem(t, s, "space"); again != nil {
		t.Errorf("the low-space card is still in the outbox: %v", again["title"])
	}
	// What stayed is still offered: the round's card cleans it, now that pip's is gone
	_, round, _ := outboxItem(t, s, "findings")
	if buttonsOf(round)["清理 1 项缓存"] == nil {
		t.Errorf("round's card: %q %v", texts(round), buttonsOf(round))
	}
}

// 「清理 N 项缓存」 on the round's card with nothing else waiting, and one cache's tool running: the card is done with,
// as when every cache went.
func TestRoundCardIsDoneWhenOnlyARunningToolsCacheIsLeft(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := pc.report
	r.Findings = []core.Finding{pc.cache, bunCache(t, s, s.Config.Context.Home)}
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	out, _ := clickRoundCaches(t, s, "openPage")
	if out.Done == nil || !*out.Done || !strings.Contains(out.Text, "Bun 正在跑") {
		t.Errorf("done %v: %q", out.Done, out.Text)
	}
	if item, _ := roundItem(t, s, "openPage"); item != nil {
		t.Errorf("the round's card is still there: %v", item["title"])
	}
}

// The same while other things wait on the scan page: the card stays as the round is now (as after every cache went),
// with something to click, not a dead end of result lines.
func TestRoundCardStaysClickableWhenACacheIsLeft(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := pc.report
	r.Findings = append(r.Findings, bunCache(t, s, s.Config.Context.Home))
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	out, answer := clickRoundCaches(t, s, "openPage")
	if out.Done == nil || *out.Done || !strings.Contains(out.Text, "Bun 正在跑") {
		t.Fatalf("done %v: %q", out.Done, out.Text)
	}
	bs := buttonsOf(answer)
	open := false
	for words := range bs {
		open = open || strings.HasPrefix(words, "去扫描页看 ")
	}
	if !open || bs["清理 1 项缓存"] == nil {
		t.Errorf("answer %q %v", texts(answer), bs)
	}
	if item, _ := roundItem(t, s, "openPage"); item == nil {
		t.Error("the round's card left the outbox")
	}
}

// Clicked on the scan page, what was left keeps the plan open as before: the page draws itself again.
func TestPageClickWithACacheLeftIsNotDone(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := pc.report
	r.Findings = []core.Finding{pc.cache, bunCache(t, s, s.Config.Context.Home)}
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	v := s.roundView(s.visible(r, s.state()), r, roundID(r))
	choices := map[string]any{}
	for _, it := range v.plan.Items {
		choices[it.Key] = []any{it.Suggested}
	}
	out, err := s.apply(O{"plan_id": v.plan.ID, "choices": choices},
		O{UserAction: map[string]any{"surfaceId": "overview", "componentId": "b1", "at": time.Now().Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Done == nil || *out.Done {
		t.Errorf("done %v: %q", out.Done, out.Text)
	}
	if item, _ := roundItem(t, s, "openPage"); item == nil {
		t.Error("the round's card left the outbox")
	}
}

// An urgent card whose 「移到废纸篓」 could not move the file (in use): the card stays (not done), the answer with
// 「再试一次」, which sends the same plan and choices; clicked once the file can move, it goes to the Trash and the card
// is done with. Clicked on the scan page, no 「再试一次」: the page draws its buttons again.
func TestUrgentCardOffersRetryWhenTheMoveFails(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	virus := filepath.Join(m.ctx.Home, "Downloads/invoice.com")
	os.MkdirAll(filepath.Dir(virus), 0o755)
	if err := os.WriteFile(virus, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	hourAgo := time.Now().Add(-time.Hour) // there before the round looked
	os.Chtimes(virus, hourAgo, hourAgo)
	f := core.Finding{Rule: "malware.clamav", Category: core.CatMalware, Severity: core.High, Verdict: core.Confirm, Path: virus,
		Bytes: core.Size(1), Title: "病毒库认出 invoice.com 是 Eicar-Test-Signature",
		Evidence: map[string]string{"signature": "Eicar-Test-Signature"}}
	now := core.Time{Time: time.Now()}
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: []core.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	trash := filepath.Join(t.TempDir(), "Trash") // never the real Trash
	busy := true
	s.Config.Trash = func(p string) (string, error) {
		if busy {
			return "", &os.PathError{Op: "rename", Path: p, Err: syscall.EBUSY}
		}
		os.MkdirAll(trash, 0o755)
		to := filepath.Join(trash, filepath.Base(p))
		return to, os.Rename(p, to)
	}
	s.Config.TrashFolders = []string{trash}
	_, comps, _ := outboxItem(t, s, "security")
	move := buttonsOf(comps)["移到废纸篓"]
	if move == nil {
		t.Fatalf("no 移到废纸篓 on the urgent card: %v", buttonsOf(comps))
	}
	_, ctx := eventOf(move)
	click := func(surface string, ctx map[string]any) (ToolOutput, []map[string]any) {
		out, err := s.apply(O{"plan_id": ctx["plan_id"], "choices": ctx["choices"]},
			O{UserAction: map[string]any{"surfaceId": surface, "componentId": "b1", "at": time.Now().Format(time.RFC3339)}})
		if err != nil {
			t.Fatal(err)
		}
		answer, _ := cardParts(t, out.Card)
		return out, answer
	}
	// On the scan page: as before
	if out, answer := click("overview", ctx); out.Done == nil || *out.Done || buttonsOf(answer)["再试一次"] != nil {
		t.Errorf("page: done %v, %v", out.Done, buttonsOf(answer))
	}
	card := "security-" + core.ShortHash(s.fid(f))
	out, answer := click(card, ctx)
	if out.Done == nil || *out.Done || !core.Exists(virus) || !strings.Contains(out.Text, "正在使用") {
		t.Fatalf("done %v, there %v: %q", out.Done, core.Exists(virus), out.Text)
	}
	retry := buttonsOf(answer)["再试一次"]
	if retry == nil {
		t.Fatalf("no 再试一次: %q %v", texts(answer), buttonsOf(answer))
	}
	name, again := eventOf(retry)
	if name != "scan_apply" || again["plan_id"] != ctx["plan_id"] || !reflect.DeepEqual(again["choices"], ctx["choices"]) ||
		retry["variant"] != "primary" {
		t.Errorf("再试一次: %v", retry)
	}
	if item, _, _ := outboxItem(t, s, "security"); item == nil {
		t.Error("the urgent card left the outbox")
	}
	busy = false
	out, answer = click(card, again)
	if out.Done == nil || !*out.Done || core.Exists(virus) || !core.Exists(filepath.Join(trash, "invoice.com")) {
		t.Fatalf("again: done %v, there %v: %q", out.Done, core.Exists(virus), out.Text)
	}
	if buttonsOf(answer)["再试一次"] != nil || buttonsOf(answer)["放回"] == nil {
		t.Errorf("again: %v", buttonsOf(answer))
	}
	if item, _, _ := outboxItem(t, s, "security"); item != nil {
		t.Errorf("the urgent card is still there: %v", item["title"])
	}
}
