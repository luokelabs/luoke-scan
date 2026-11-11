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

// buttonsOf: the buttons of a card, with the words of each (its Text child, or the Text in its Row child).
func buttonsOf(comps []map[string]any) map[string]map[string]any {
	byID := map[string]map[string]any{}
	for _, c := range comps {
		byID[c["id"].(string)] = c
	}
	out := map[string]map[string]any{}
	for _, c := range comps {
		if c["component"] != "Button" {
			continue
		}
		if t := byID[c["id"].(string)+"-text"]; t != nil {
			out[t["text"].(string)] = c
		}
	}
	return out
}

func eventOf(b map[string]any) (string, map[string]any) {
	e := b["action"].(map[string]any)["event"].(map[string]any)
	ctx, _ := e["context"].(map[string]any)
	return e["name"].(string), ctx
}

// countChosen: what the window puts for {n} (luoke-agent a2ui.count_chosen): the items of the group with that choice.
func countChosen(choices map[string]any, value string) int {
	n := 0
	for _, v := range choices {
		for _, x := range v.([]any) {
			if x == value {
				n++
				break
			}
		}
	}
	return n
}

// 「可以清掉」's button: where the core draws counted labels and keeps them clickable for the other choices (countLabel
// and countAlso) it says how many go to the Trash as chosen, any other choice that does something (以后别提 here) turning
// it into 「按上面的选择处理」; the same plan and choices as before. A core with countLabel alone, or neither, gets
// 「按上面的选择清理」 with no count: there the other choices alone would leave it grey.
func TestCleanButtonCountsTheChoices(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	both := map[string]bool{"countLabel": true, "countAlso": true}
	for _, features := range []map[string]bool{nil, {"lucide": true}, {"countLabel": true}, {"countAlso": true},
		withFeature(allFeatures, "countLabel"), both, withFeature(allFeatures, "countLabel", "countAlso"), withFeature(both, "countWeights")} { // the last: no rows of a kind here, so no weights
		comps, choices := cardParts(t, s.page("overview", s.state(), features))
		bs := buttonsOf(comps)
		old, counted := bs["按上面的选择清理"], bs["移到废纸篓 {n} 项"]
		if !features["countLabel"] || !features["countAlso"] {
			if old == nil || counted != nil || old["count"] != nil {
				t.Errorf("features %v: %v / %v", features, old, counted)
			}
			continue
		}
		if old != nil || counted == nil {
			t.Fatalf("features %v: buttons %v", features, bs)
		}
		want := map[string]any{"path": "/choices", "value": ChoiceTrash, "also": []any{ChoiceIgnore}, "alsoLabel": "按上面的选择处理"}
		if !reflect.DeepEqual(counted["count"], want) {
			t.Errorf("count %v, want %v", counted["count"], want)
		}
		name, ctx := eventOf(counted)
		if name != "scan_apply" || !reflect.DeepEqual(ctx["choices"], map[string]any{"path": "/choices"}) || ctx["plan_id"] == nil ||
			counted["variant"] != "primary" {
			t.Errorf("button %v", counted)
		}
		// As drawn at first: the installer automatic cleaning would take (the cache has its own button, its choice 先不动)
		if n := countChosen(choices, ChoiceTrash); n != 1 {
			t.Errorf("{n} = %d at first: %v", n, choices)
		}
	}
}

// also names every choice besides 移到废纸篓 and 先不动 that the items offer (here 删掉 of a cache the rule is not sure
// of, and 以后别提), so choosing only those still goes. With no item that can go to the Trash, the button keeps its
// words: 「移到废纸篓 0 项」 would name what none of them does.
func TestCleanButtonAlsoGoesForTheOtherChoices(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	npm := filepath.Join(s.Config.Context.Home, ".npm/_cacache")
	os.MkdirAll(npm, 0o755)
	os.WriteFile(filepath.Join(npm, "x"), []byte("x"), 0o644)
	unsure := core.Finding{Rule: "cache.rebuildable.npm", Category: core.CatCache, Severity: core.Low, Verdict: core.Confirm, Path: npm,
		Bytes: core.Size(70_000_000), Title: "npm 的缓存，删了会自动重建"}
	both := map[string]bool{"countLabel": true, "countAlso": true}
	r := pc.report
	r.Findings = append(append([]core.Finding(nil), r.Findings...), unsure)
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	comps, choices := cardParts(t, s.page("overview", s.state(), both))
	counted := buttonsOf(comps)["移到废纸篓 {n} 项"]
	want := map[string]any{"path": "/choices", "value": ChoiceTrash, "also": []any{ChoiceIgnore, ChoiceRemove}, "alsoLabel": "按上面的选择处理"}
	if counted == nil || !reflect.DeepEqual(counted["count"], want) {
		t.Errorf("button %v, want count %v", counted, want)
	}
	if len(choices) != 4 {
		t.Errorf("the unsure cache is not one of the choices: %v", choices)
	}

	// Only the unsure cache to decide on (and the pip cache, which has its own button)
	r.Findings = []core.Finding{pc.cache, unsure}
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	// It keeps its words, and counts the other choices: the core does not draw it while every item is 「先不动」 (§4
	// countLabel since 11-11), and draws it once one is 以后别提 or 删掉
	comps, _ = cardParts(t, s.page("overview", s.state(), both))
	bs := buttonsOf(comps)
	want = map[string]any{"path": "/choices", "value": ChoiceIgnore, "also": []any{ChoiceRemove}, "alsoLabel": "按上面的选择清理"}
	if bs["按上面的选择清理"] == nil || bs["移到废纸篓 {n} 项"] != nil || !reflect.DeepEqual(bs["按上面的选择清理"]["count"], want) {
		t.Errorf("nothing can go to the Trash: %v, want count %v", bs, want)
	}
}

func withFeature(base map[string]bool, more ...string) map[string]bool {
	out := map[string]bool{}
	for k, v := range base {
		out[k] = v
	}
	for _, k := range more {
		out[k] = true
	}
	return out
}

// The round's card in 「今天」: where the core opens a tool's own page (openPage), what waits on the scan page is a button
// that goes there (「去扫描页看 N 项」, agent.open_page with only the page id) and not a line; the summary says it either
// way. An older core gets the line and no such button.
func TestRoundCardGoesToTheScanPage(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := s.Store.LastReport()
	f := s.visible(*r, s.state())

	plain := NewCard("round")
	_, summary := s.decisionsBody(plain, *r, s.state(), f, roundID(*r))
	comps, _ := cardParts(t, plain.Messages())
	all := strings.Join(texts(comps), "\n")
	if !strings.Contains(all, "项在「螺壳扫描」里等你看") {
		t.Errorf("older core: %q", all)
	}
	for _, b := range buttonsOf(comps) {
		if name, _ := eventOf(b); name == "agent.open_page" {
			t.Errorf("older core got %v", b)
		}
	}

	c := NewCard("round").Use(map[string]bool{"openPage": true})
	_, summary2 := s.decisionsBody(c, *r, s.state(), f, roundID(*r))
	if summary2 != summary {
		t.Errorf("summary %q, was %q", summary2, summary)
	}
	comps, _ = cardParts(t, c.Messages())
	all = strings.Join(texts(comps), "\n")
	if strings.Contains(all, "等你看") || !strings.Contains(all, "会重建的缓存 1 项，不用你选。") {
		t.Errorf("with openPage: %q", all)
	}
	v := s.roundView(f, *r, roundID(*r))
	rest := v.toLook
	for _, x := range f {
		if isUrgent(x) {
			rest--
		}
	}
	bs := buttonsOf(comps)
	open := bs[fmt.Sprintf("去扫描页看 %d 项", rest)]
	if open == nil {
		t.Fatalf("no 去扫描页看 %d 项: %v", rest, bs)
	}
	if name, ctx := eventOf(open); name != "agent.open_page" || !reflect.DeepEqual(ctx, map[string]any{"page": "overview"}) ||
		open["variant"] != nil {
		t.Errorf("open %v", open)
	}
	if bs["清理 1 项缓存"] == nil || bs["清理 1 项缓存"]["variant"] != "primary" {
		t.Errorf("清理 1 项缓存 %v", bs)
	}
	// The page it opens is one of this tool's own (the manifest's service.pages)
	if !hasBasePage("overview") {
		t.Error("overview is not a base page")
	}
}

func hasBasePage(id string) bool {
	for _, p := range basePages {
		if p.id == id {
			return true
		}
	}
	return false
}

// Through MCP: the outbox read with the features in the request's _meta draws the round's card in them, and so does
// the round's card redrawn under the answer to a click on it; a request without them gets the cards as before.
func TestOutboxDrawsTheRoundInTheCoresForms(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	caps := func(features ...string) O {
		list := A{}
		for _, f := range features {
			list = append(list, f)
		}
		return O{metaCapabilities: O{"experimental": O{"ai.luoke/a2ui": O{"features": list}}}}
	}
	roundCard := func(meta O) []map[string]any {
		reply := s.Server.Handle(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "resources/read",
			"params": map[string]any{"uri": "outbox", "_meta": meta}})
		b, _ := json.Marshal(reply)
		var out struct {
			Result struct {
				Contents []struct{ Text string } `json:"contents"`
			} `json:"result"`
		}
		if err := json.Unmarshal(b, &out); err != nil || len(out.Result.Contents) != 1 {
			t.Fatalf("reply %s", b)
		}
		var box struct {
			Items []struct {
				Kind string `json:"kind"`
				Card []any  `json:"card"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(out.Result.Contents[0].Text), &box); err != nil {
			t.Fatal(err)
		}
		for _, it := range box.Items {
			if it.Kind == "findings" {
				comps, _ := cardParts(t, it.Card)
				return comps
			}
		}
		t.Fatalf("no round in %s", out.Result.Contents[0].Text)
		return nil
	}
	hasOpen := func(comps []map[string]any) bool {
		for _, b := range buttonsOf(comps) {
			if name, _ := eventOf(b); name == "agent.open_page" {
				return true
			}
		}
		return false
	}
	if hasOpen(roundCard(O{})) || hasOpen(roundCard(caps("lucide", "countLabel"))) {
		t.Error("open_page without openPage")
	}
	if !hasOpen(roundCard(caps("openPage"))) {
		t.Error("no open_page with openPage")
	}

	// A click on the round's card (打开自动清理): the card under the answer is drawn in the same forms
	r := s.Store.LastReport()
	click := func(meta O) []map[string]any {
		meta[UserAction] = map[string]any{"surfaceId": roundSurface(roundID(*r)), "componentId": "b1", "at": time.Now().Format(time.RFC3339)}
		out, err := s.setAutoclean(O{"on": true}, meta)
		if err != nil {
			t.Fatal(err)
		}
		comps, _ := cardParts(t, out.Card)
		return comps
	}
	if comps := click(caps("openPage")); !hasOpen(comps) {
		t.Errorf("redrawn without the button: %q", texts(comps))
	}
	if comps := click(O{}); hasOpen(comps) {
		t.Errorf("older core's redraw: %q", texts(comps))
	}
}

// roundItem: the round's item in the outbox as a core with these features reads it, and its card's components; nil
// when the outbox has none.
func roundItem(t *testing.T, s *Service, features ...string) (map[string]any, []map[string]any) {
	fs := map[string]bool{}
	for _, f := range features {
		fs[f] = true
	}
	r := s.Store.LastReport()
	b, _ := json.Marshal(s.outboxOf(s.state(), r, fs))
	var box struct {
		Items []map[string]any `json:"items"`
	}
	json.Unmarshal(b, &box)
	for _, it := range box.Items {
		if it["kind"] == "findings" {
			card, _ := json.Marshal(it["card"])
			var msgs []any
			json.Unmarshal(card, &msgs)
			comps, _ := cardParts(t, msgs)
			return it, comps
		}
	}
	return nil, nil
}

// clickRoundCaches: the user clicks 「清理 N 项缓存」 on the round's card, the agent core listing features.
func clickRoundCaches(t *testing.T, s *Service, features ...string) (ToolOutput, []map[string]any) {
	_, comps := roundItem(t, s, features...)
	var b map[string]any
	for words, x := range buttonsOf(comps) {
		if strings.HasPrefix(words, "清理 ") && strings.HasSuffix(words, " 项缓存") {
			b = x
		}
	}
	if b == nil {
		t.Fatalf("no 清理 N 项缓存 on the round's card: %q", texts(comps))
	}
	_, ctx := eventOf(b)
	list := A{}
	for _, f := range features {
		list = append(list, f)
	}
	r := s.Store.LastReport()
	meta := O{metaCapabilities: O{"experimental": O{"ai.luoke/a2ui": O{"features": list}}},
		UserAction: map[string]any{"surfaceId": roundSurface(roundID(*r)), "componentId": b["id"], "at": time.Now().Format(time.RFC3339)}}
	out, err := s.apply(O{"plan_id": ctx["plan_id"], "choices": ctx["choices"]}, meta)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := cardParts(t, out.Card)
	return out, answer
}

// After 「清理 N 项缓存」 on the round's card, while other things wait on the scan page: the card stays (done false),
// says the caches went, and still sends the user to the page (the button where the core has openPage, the line where it
// does not); the outbox draws it so from then on, and the scan page no longer offers the caches.
func TestRoundCardStaysAfterTheCaches(t *testing.T) {
	for _, features := range [][]string{{"openPage"}, nil} {
		pc := newPageCase(t)
		s := pc.s
		before, _ := roundItem(t, s, features...)
		out, answer := clickRoundCaches(t, s, features...)
		if out.Done == nil || *out.Done || !strings.HasPrefix(out.Text, "删掉会重建的缓存 1 项") {
			t.Fatalf("features %v: answer %q done %v", features, out.Text, out.Done)
		}
		if core.Exists(pc.cache.Path) {
			t.Fatal("the cache is still there")
		}
		item, comps := roundItem(t, s, features...)
		if item == nil {
			t.Fatalf("features %v: the round is gone from the outbox", features)
		}
		for name, cs := range map[string][]map[string]any{"answer": answer, "outbox": comps} {
			all := strings.Join(texts(cs), "\n")
			bs := buttonsOf(cs)
			if !strings.Contains(all, "已删掉会重建的缓存 1 项（腾出 ") || strings.Contains(all, "不用你选") {
				t.Errorf("features %v, %s: %q", features, name, all)
			}
			for words := range bs {
				if strings.HasPrefix(words, "清理 ") {
					t.Errorf("features %v, %s: %s again", features, name, words)
				}
			}
			open := false
			for words, b := range bs {
				if n, _ := eventOf(b); n == "agent.open_page" {
					open = strings.HasPrefix(words, "去扫描页看 ") && b["variant"] == "primary"
				}
			}
			if len(features) > 0 && (!open || strings.Contains(all, "等你看")) {
				t.Errorf("features %v, %s: no 去扫描页看 N 项 (%v): %q", features, name, bs, all)
			}
			if len(features) == 0 && (open || !strings.Contains(all, "项在「螺壳扫描」里等你看")) {
				t.Errorf("features %v, %s: %q", features, name, all)
			}
		}
		// The title and the summary leave the caches out now: what is left to free is the installer
		if title := item["title"].(string); title == before["title"] || !strings.HasPrefix(title, "能清出 830.9 MB，另外 ") {
			t.Errorf("title %q (before %q)", title, before["title"])
		}
		if sm := item["summary"].(string); !strings.HasPrefix(sm, "已删掉会重建的缓存 1 项") || !strings.Contains(sm, "里等你看") {
			t.Errorf("summary %q", sm)
		}
		page, _ := cardParts(t, s.page("overview", s.state()))
		ts := texts(page)
		if indexOf(ts, "会自动重建的缓存") >= 0 || indexOf(ts, "可以清掉 2") < 0 {
			t.Errorf("page %q", ts)
		}
	}
}

// With nothing else to look at, 「清理 N 项缓存」 is the end of the round's card, as before.
func TestRoundCardGoesWhenOnlyTheCachesWaited(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := pc.report
	r.Findings = []core.Finding{pc.cache}
	if err := s.Store.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	out, _ := clickRoundCaches(t, s, "openPage")
	if out.Done == nil || !*out.Done {
		t.Errorf("done %v: %q", out.Done, out.Text)
	}
	if item, _ := roundItem(t, s, "openPage"); item != nil {
		t.Errorf("the round's card is still there: %v", item)
	}
}
