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

// luoke-scan#129: the scan page and the round's card, redone. A fake home with a rebuildable cache, an installer of an
// app installed at that version (what automatic cleaning would take), a big file not opened for years, and the model
// setup's skill (what waits for the user's look).
type pageCase struct {
	s                     *Service
	report                core.Report
	cache, installer, big core.Finding
}

func newPageCase(t *testing.T) pageCase { return newPageCaseWith(t, true) }

// newPageCaseWith: plugin says whether the AI plugin came with a Claude Code plugin (it stays under 「要你看看」) or was
// put in the user's own skills folder (it goes to the Trash from 「可以清掉」).
func newPageCaseWith(t *testing.T, plugin bool) pageCase {
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
	pip := filepath.Dir(file("Library/Caches/pip/http/x"))
	pip = filepath.Dir(pip)
	opened := time.Now().AddDate(-3, -1, 0).Format("2006-01-02")
	pc := pageCase{
		cache: core.Finding{Rule: "cache.rebuildable.pip", Category: core.CatCache, Severity: core.Low, Verdict: core.Safe, Path: pip,
			Bytes: core.Size(62_900_000), Title: "pip 的缓存，删了会自动重建"},
		installer: core.Finding{Rule: "leftover.installer", Category: core.CatLeftover, Severity: core.Low, Verdict: core.Confirm,
			Path: file("Downloads/ModelBox-0.7.0.dmg"), Bytes: core.Size(830_900_000),
			Title: "下载文件夹里 24 天前的安装包 ModelBox-0.7.0.dmg（ModelBox 已经装好了）",
			Evidence: map[string]string{"days": "24", "installed": "ModelBox", "exact": "ModelBox", "downloaded": "1", "signed": "1",
				"installer_version": "0.7.0", "app_version": "0.7.0"}},
		big: core.Finding{Rule: "stale.large-file", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm,
			Path: file("Movies/家庭录像_01.avi"), Bytes: core.Size(1_240_000_000), Title: "家庭录像_01.avi（1.24 GB）三年多没打开过",
			Evidence: map[string]string{"last_opened": opened}},
	}
	var skills []core.Finding
	for _, f := range m.report.Findings {
		if f.Category == core.CatSkill {
			if plugin {
				ev := map[string]string{}
				for k, v := range f.Evidence {
					ev[k] = v
				}
				ev["agent"] = "Claude Code 插件"
				f.Evidence = ev
			}
			skills = append(skills, f)
		}
	}
	now := core.Time{Time: time.Now()}
	pc.report = core.Report{StartedAt: now, FinishedAt: now, Findings: append([]core.Finding{pc.cache, pc.installer, pc.big}, skills...)}
	pc.s = m.service(nil, nil)
	if err := pc.s.Store.SaveReport(pc.report); err != nil {
		t.Fatal(err)
	}
	return pc
}

// cardParts: a card's components in the order added, by id, and its data model's choices.
func cardParts(t *testing.T, msgs []any) ([]map[string]any, map[string]any) {
	b, _ := json.Marshal(msgs)
	var raw []map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var comps []map[string]any
	choices := map[string]any{}
	for _, m := range raw {
		if uc, ok := m["updateComponents"].(map[string]any); ok {
			for _, c := range uc["components"].([]any) {
				comps = append(comps, c.(map[string]any))
			}
		}
		if ud, ok := m["updateDataModel"].(map[string]any); ok {
			if v, ok := ud["value"].(map[string]any)["choices"].(map[string]any); ok {
				choices = v
			}
		}
	}
	return comps, choices
}

func texts(comps []map[string]any) []string {
	var out []string
	for _, c := range comps {
		if c["component"] == "Text" || c["component"] == "ChoicePicker" {
			if s, ok := c["text"].(string); ok {
				out = append(out, s)
			} else if s, ok := c["label"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func indexOf(xs []string, prefix string) int {
	for i, x := range xs {
		if strings.HasPrefix(x, prefix) {
			return i
		}
	}
	return -1
}

// button: the button whose label text is label, and its event's context.
func button(comps []map[string]any, label string) map[string]any {
	byID := map[string]map[string]any{}
	for _, c := range comps {
		byID[c["id"].(string)] = c
	}
	for _, c := range comps {
		if c["component"] != "Button" {
			continue
		}
		if t := byID[c["id"].(string)+"-text"]; t != nil && t["text"] == label {
			return c["action"].(map[string]any)["event"].(map[string]any)["context"].(map[string]any)
		}
	}
	return nil
}

func TestScanPageCleanFirstEachItemSaysWhatItIs(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	comps, choices := cardParts(t, s.page("overview", s.state()))
	ts := texts(comps)
	clean, look := indexOf(ts, "可以清掉 "), indexOf(ts, "要你看看 ")
	if clean < 0 || look < 0 || clean > look {
		t.Fatalf("可以清掉 %d, 要你看看 %d: %q", clean, look, ts)
	}
	for _, want := range []string{"可以清掉 3", "会自动重建的缓存 1 项（62.9 MB）", "pip",
		"ModelBox 的安装包（830.9 MB）", "ModelBox-0.7.0.dmg · 24 天前下载，ModelBox 已经装好了",
		"家庭录像_01.avi（1.24 GB）", "3 年多没打开过", "上次查 "} {
		if indexOf(ts, want) < 0 {
			t.Errorf("page lacks %q: %q", want, ts)
		}
	}
	for _, x := range ts {
		for _, bad := range []string{"样", "懂电脑", "另外", "/Users/", "照建议清理"} {
			if strings.Contains(strings.NewReplacer("一样", "", "照样", "").Replace(x), bad) {
				t.Errorf("page says %q in %q", bad, x)
			}
		}
	}
	// The biggest first among what is to be chosen
	if indexOf(ts, "家庭录像_01.avi") > indexOf(ts, "ModelBox 的安装包") {
		t.Errorf("not by size: %q", ts)
	}
	// 清理 deletes just the cache; the bottom button never does (its choice is 先不动)
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	keys := map[string]string{}
	for _, it := range v.plan.Items {
		keys[it.FindingID] = it.Key
	}
	ck, ik, bk := keys[s.fid(pc.cache)], keys[s.fid(pc.installer)], keys[s.fid(pc.big)]
	only := button(comps, "清理")
	if only == nil || !reflect.DeepEqual(only["choices"], map[string]any{ck: []any{ChoiceRemove}}) {
		t.Errorf("清理 %v", only)
	}
	if all := button(comps, "按上面的选择清理"); all == nil || !reflect.DeepEqual(all["choices"], map[string]any{"path": "/choices"}) {
		t.Errorf("按上面的选择清理 %v", all)
	}
	want := map[string]any{ck: []any{ChoiceKeep}, ik: []any{ChoiceTrash}, bk: []any{ChoiceKeep}}
	if !reflect.DeepEqual(choices, want) {
		t.Errorf("choices %v, want %v (the installer automatic cleaning would take goes by default)", choices, want)
	}
	f := s.visible(*r, s.state())
	if want := len(f) - countInfo(f) - 1 + v.high; v.toLook != want { // the installer suggested to the Trash still counts
		t.Errorf("等你处理 %d, want %d: everything but the cache", v.toLook, want)
	}
}

func countInfo(fs []core.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Verdict == core.Info {
			n++
		}
	}
	return n
}

// The round's card: how much can go, that the caches need no choosing, how many wait; its button deletes just them.
func TestRoundCardCleansJustTheCaches(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := s.Store.LastReport()
	f := s.visible(*r, s.state())
	c := NewCard("round")
	title, summary := s.decisionsBody(c, *r, s.state(), f, roundID(*r))
	comps, choices := cardParts(t, c.Messages())
	ts := texts(comps)
	if !strings.HasPrefix(ts[0], "能清出 ") || !strings.HasPrefix(title, "能清出 ") {
		t.Errorf("heading %q title %q", ts[0], title)
	}
	if !strings.Contains(summary, "会重建的缓存 1 项，不用你选；另外 ") || !strings.Contains(summary, "项在「螺壳扫描」里等你看") {
		t.Errorf("summary %q", summary)
	}
	v := s.roundView(f, *r, roundID(*r))
	ck := ""
	for _, it := range v.plan.Items {
		if it.FindingID == s.fid(pc.cache) {
			ck = it.Key
		}
		if !reflect.DeepEqual(choices[it.Key], []any{ChoiceKeep}) {
			t.Errorf("%s defaults to %v", it.Key, choices[it.Key])
		}
	}
	if b := button(comps, "清理 1 项缓存"); b == nil || !reflect.DeepEqual(b["choices"], map[string]any{ck: []any{ChoiceRemove}}) {
		t.Errorf("清理 1 项缓存 %v", b)
	}
}

// What the user reads never sends them to find someone who knows computers (luoke-scan#129).
func TestNoAskSomeoneWhoKnowsComputers(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "懂电脑") {
			t.Errorf("%s still says 懂电脑", f)
		}
	}
}

func TestAgo(t *testing.T) {
	s := &Service{Config: Config{Clock: func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.Local) }}}
	for day, want := range map[string]string{"2026-11-09": "1 天", "2026-10-03": "37 天", "2026-06-01": "5 个月",
		"2018-06-01": "8 年多", "x": "x"} {
		if got := s.ago(day); got != want {
			t.Errorf("ago(%s) = %q, want %q", day, got, want)
		}
	}
}

// An AI plugin of the user's own (luoke-scan#152): in 「可以清掉」, to the Trash by default, not again under 「要你看看」.
func TestScanPageOwnPluginGoesToTheTrash(t *testing.T) {
	pc := newPageCaseWith(t, false)
	s := pc.s
	comps, choices := cardParts(t, s.page("overview", s.state()))
	ts := texts(comps)
	title := indexOf(ts, "「Claude Code」的插件「sync-notes」能操作你的电脑")
	if title < 0 || indexOf(ts, "可以清掉 4") < 0 || indexOf(ts, "要你看看 ") >= 0 {
		t.Fatalf("page %q", ts)
	}
	if buttonsOf(comps)["在访达里显示「sync-notes」"] == nil {
		t.Errorf("no way to look at it before it goes: %v", buttonsOf(comps))
	}
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	for _, it := range v.plan.Items {
		// It sends the user's notes and keys away (high risk): to the Trash by default
		if it.Category == string(core.CatSkill) && !reflect.DeepEqual(choices[it.Key], []any{ChoiceTrash}) {
			t.Errorf("plugin %s: %v", it.Key, choices[it.Key])
		}
	}
}

// The page's numbers add up (the walk-through of internal-1110-5: 「等你处理 23 项」 over 「可以清掉 25」): what waits is
// what the page lists but the rebuildable caches. A plan also carries things that are only for reference (an AI plugin
// of the user's own with a milder sign): listed under 「可以清掉」 with a choice like the rest, so counted as waiting like the rest.
func TestWaitingCountsWhatThePageLists(t *testing.T) {
	pc := newPageCaseWith(t, false)
	s := pc.s
	// A plugin of the user's own with a milder sign: only for reference and not serious, still in the plan
	var mild core.Finding
	for _, x := range pc.report.Findings {
		if x.Category == core.CatSkill {
			mild = x
		}
	}
	if mild.Path == "" {
		t.Fatal("the case has no skill finding")
	}
	mild.Path = filepath.Join(filepath.Dir(mild.Path), "tidy-notes")
	if err := os.MkdirAll(mild.Path, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(mild.Path, "SKILL.md"), []byte("x"), 0o644)
	mild.Severity, mild.Title = core.Medium, "Claude Code 的 skill「tidy-notes」：往外发东西"
	pc.report.Findings = append(pc.report.Findings, mild)
	if err := s.Store.SaveReport(pc.report); err != nil {
		t.Fatal(err)
	}
	r := s.Store.LastReport()
	f := s.visible(*r, s.state())
	v := s.roundView(f, *r, roundID(*r))
	listed := false
	for _, it := range v.plan.Items {
		listed = listed || (len(it.Targets) == 1 && it.Targets[0].Path == mild.Path)
	}
	if !listed {
		t.Fatalf("the milder plugin is not in the plan: %+v", v.plan.Items)
	}
	comps, _ := cardParts(t, s.page("overview", s.state()))
	ts := texts(comps)
	section := func(words string) int {
		for _, x := range ts {
			var n int
			if _, err := fmt.Sscanf(x, words+" %d", &n); err == nil {
				return n
			}
		}
		return 0
	}
	clean, look := section("可以清掉"), section("要你看看")
	if clean == 0 || len(v.caches) != 1 {
		t.Fatalf("可以清掉 %d, caches %d: %q", clean, len(v.caches), ts)
	}
	if want := clean - len(v.caches) + look; v.toLook != want {
		t.Errorf("等你处理 %d, want %d: 可以清掉 %d but its %d cache, and 要你看看 %d", v.toLook, want, clean, len(v.caches), look)
	}
	if indexOf(ts, fmt.Sprintf("%d 项", v.toLook)) < 0 {
		t.Errorf("the page does not say %d 项: %q", v.toLook, ts)
	}
}
