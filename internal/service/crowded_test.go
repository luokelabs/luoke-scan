package service

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// crowded: a round on a well-used Mac (luoke-scan#129, the numbers of a real one): 41 installers of apps already
// installed (several dots in their names), the caches of node-gyp, Cargo, Gradle (two), Go and Composer, 7 sets of
// duplicates (names a downloader kept percent-encoded), 5 AI plugins and 4 apps from nowhere.
type crowded struct {
	s          *Service
	trash      string
	installers []core.Finding
	plugins    []core.Finding
}

func newCrowded(t *testing.T) crowded {
	m := newModelSetup(t)
	home := m.ctx.Home
	file := func(rel string, size int) string {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(strings.Repeat("x", size)), 0o644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().AddDate(0, 0, -30) // as a round finds them: not changed since
		os.Chtimes(p, old, old)
		return p
	}
	var c crowded
	var fs []core.Finding
	for i := 0; i < 41; i++ {
		app, v := fmt.Sprintf("App%02d", i), fmt.Sprintf("1.%d.2", i)
		f := core.Finding{Rule: "leftover.installer", Category: core.CatLeftover, Severity: core.Low, Verdict: core.Confirm,
			Path: file(fmt.Sprintf("Downloads/%s-%s.dmg", app, v), 1), Bytes: core.Size(int64(i+1) * 10_000_000),
			Title: "下载文件夹里 30 天前的安装包 " + app + "-" + v + ".dmg（" + app + " 已经装好了）",
			Evidence: map[string]string{"days": "30", "installed": app, "exact": app, "downloaded": "1", "signed": "1",
				"installer_version": v, "app_version": v}}
		c.installers = append(c.installers, f)
		fs = append(fs, f)
	}
	for _, id := range []string{"node-gyp", "cargo-registry-cache", "gradle-caches", "gradle-wrapper", "go-build", "composer"} {
		kc, _ := knownCacheByRule("cache.rebuildable." + id)
		file(filepath.Join(kc.Path, "x"), 1)
		fs = append(fs, core.Finding{Rule: "cache.rebuildable." + id, Category: core.CatCache, Severity: core.Low, Verdict: core.Safe,
			Path: filepath.Join(home, kc.Path), Bytes: core.Size(300_000_000), Title: kc.Tool + " 的缓存，删了会自动重建",
			Evidence: map[string]string{"tool": kc.Tool}})
	}
	for i := 0; i < 7; i++ {
		name := fmt.Sprintf("%%E9%%A6%%99%%E6%%B8%%AF-%d.pdf", i) // 香港-i.pdf
		keep := file("Documents/"+name, 2)
		cp := file("Desktop/"+name, 2)
		fs = append(fs, core.Finding{Rule: "space.duplicates", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm,
			Path: keep, Bytes: core.Size(50_000_000), Title: "2 份一样的 " + core.DisplayName(keep),
			Evidence: map[string]string{"keep": "~/Documents/" + name, "copies": "~/Desktop/" + name, "targets": cp}})
	}
	for i := 0; i < 5; i++ {
		dir := filepath.Join(home, fmt.Sprintf(".claude/skills/helper-%d", i))
		file(filepath.Join(fmt.Sprintf(".claude/skills/helper-%d", i), "SKILL.md"), 1)
		f := core.Finding{Rule: "skill.exec", Category: core.CatSkill, Severity: core.High, Verdict: core.Info, Path: dir,
			Title: "skill", Evidence: map[string]string{"skill": fmt.Sprintf("helper-%d", i), "agent": "Claude Code"}}
		c.plugins = append(c.plugins, f)
		fs = append(fs, f)
	}
	for i := 0; i < 4; i++ {
		app := filepath.Join(home, fmt.Sprintf("Applications/Tool.%d.Beta.app", i))
		file(fmt.Sprintf("Applications/Tool.%d.Beta.app/Contents/Info.plist", i), 1)
		fs = append(fs, core.Finding{Rule: "apps.unsigned", Category: core.CatMalware, Severity: core.Medium, Verdict: core.Confirm,
			Path: app, Title: "unsigned"})
	}
	now := core.Time{Time: time.Now()}
	c.s = m.service(nil, nil)
	c.trash = filepath.Join(t.TempDir(), "Trash")
	c.s.Config.Trash = func(p string) (string, error) {
		os.MkdirAll(c.trash, 0o755)
		to := filepath.Join(c.trash, filepath.Base(p))
		return to, os.Rename(p, to)
	}
	c.s.Config.TrashFolders = []string{c.trash}
	if err := c.s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	return c
}

var everyFeature = map[string]bool{"placement": true, "badge": true, "strong": true, "maxLines": true, "optionIcons": true,
	"collapsed": true, "lucide": true, "tooltip": true, "doneGroup": true, "itemIcons": true, "countLabel": true,
	"countAlso": true, "openPage": true}

// Everything that can be cleaned stays in 「可以清掉」 and can be done there, however many (no cap of 30): the 41
// installers are one row (their total, how many, their apps' names), the caches one row naming each tool once, the
// duplicates one row; nothing of them in 「要你看看」. Within 200 components with every form the core draws, and without.
func TestEverythingCleanableStaysCleanable(t *testing.T) {
	c := newCrowded(t)
	s := c.s
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	if v.plan == nil || len(v.plan.Items) != 41+6+7 {
		t.Fatalf("plan %d items", len(v.plan.Items))
	}
	for _, x := range v.look {
		if x.Rule == "leftover.installer" || x.Category == core.CatCache || x.Rule == "space.duplicates" {
			t.Errorf("%s waits in 要你看看", x.Rule)
		}
	}
	groups := planGroups(v.plan.Items)
	if len(groups) != 2 || len(groups[0].items) != 41 || groups[0].items[0].Suggested != ChoiceTrash || len(groups[1].items) != 7 {
		t.Fatalf("groups %+v", groups)
	}
	var total int64
	for _, f := range c.installers {
		total += *f.Bytes
	}
	for _, features := range []map[string]bool{nil, everyFeature} {
		msgs := s.page("overview", s.state(), features)
		comps, choices := cardParts(t, msgs)
		t.Logf("features %v: %d components", features != nil, len(comps))
		if len(comps) > CardMaxComponents {
			t.Errorf("features %v: %d components", features != nil, len(comps))
		}
		ts := strings.Join(texts(comps), "\n")
		for _, want := range []string{"已经装好的应用留下的安装包，一共 41 项", "「App00」、「App01」、「App02」、「App03」等，这 41 项一起处理",
			"node-gyp、Cargo、Gradle、Go、Composer", "7 组重复的文件", "「香港-"} {
			if !strings.Contains(ts, want) {
				t.Errorf("features %v: no %q in %s", features != nil, want, ts)
			}
		}
		if strings.Count(ts, "Gradle") != 1 || strings.Contains(ts, "「dmg」") || strings.Contains(ts, "%E9") || strings.Contains(ts, "、等") {
			t.Errorf("features %v: %s", features != nil, ts)
		}
		size := core.FormatBytes(total)
		if !strings.Contains(ts, size) {
			t.Errorf("features %v: the installers' total %s is not on the page", features != nil, size)
		}
		g := groups[0].key
		if !reflect.DeepEqual(choices[g], []any{ChoiceTrash}) {
			t.Errorf("features %v: %s = %v", features != nil, g, choices[g])
		}
		for _, it := range groups[0].items {
			if _, own := choices[it.Key]; own {
				t.Errorf("features %v: %s has a choice of its own", features != nil, it.Key)
			}
		}
		// {n} would count the row of 41 as 1: the words stay
		if bs := buttonsOf(comps); bs["按上面的选择清理"] == nil || bs["移到废纸篓 {n} 项"] != nil {
			t.Errorf("features %v: %v", features != nil, bs)
		}
	}
}

// One choice for the row of 41 goes to each of them: all 41 go to the Trash with one click.
func TestOneChoiceForAKindGoesToEachOfIt(t *testing.T) {
	c := newCrowded(t)
	s := c.s
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	g := planGroups(v.plan.Items)[0]
	out, err := s.apply(O{"plan_id": v.plan.ID, "choices": map[string]any{g.key: []any{ChoiceTrash}}},
		O{UserAction: map[string]any{"surfaceId": "overview", "componentId": "b1", "at": time.Now().Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.Text, "移到废纸篓 41 项") {
		comps, _ := cardParts(t, out.Card)
		t.Fatalf("%q: %q", out.Text, texts(comps))
	}
	for _, f := range c.installers {
		if core.Exists(f.Path) {
			t.Errorf("%s is still there", filepath.Base(f.Path))
		}
	}
	// A choice the group does not offer is refused
	if _, err := s.apply(O{"plan_id": v.plan.ID, "choices": map[string]any{g.key: []any{ChoiceClone}}}, O{}); err == nil {
		t.Error("a choice no installer offers went through")
	}
}

// A line of several AI plugins (or apps from nowhere) tells the user to find them in the Finder: it has a button for each.
func TestSeveralPluginsCanEachBeFound(t *testing.T) {
	c := newCrowded(t)
	s := c.s
	for _, features := range []map[string]bool{nil, everyFeature} {
		comps, _ := cardParts(t, s.page("overview", s.state(), features))
		bs := buttonsOf(comps)
		for _, f := range c.plugins {
			b := bs["在访达里显示「"+f.Evidence["skill"]+"」"]
			if b == nil {
				t.Fatalf("features %v: no button for %s: %v", features != nil, f.Evidence["skill"], bs)
			}
			if name, ctx := eventOf(b); name != "scan_reveal" || ctx["finding_id"] != s.fid(f) {
				t.Errorf("%v", b)
			}
		}
		for i := 0; i < 4; i++ {
			if bs[fmt.Sprintf("在访达里显示「Tool.%d.Beta」", i)] == nil {
				t.Errorf("features %v: no button for Tool.%d.Beta", features != nil, i)
			}
		}
		// what to do, the short line of the design (负责人 11-11), not a sentence about one plugin
		ts := strings.Join(texts(comps), "\n")
		if !strings.Contains(ts, "不是你装的就删掉") || strings.Contains(ts, "AI 用到它时") {
			t.Errorf("features %v: the advice: %s", features != nil, ts)
		}
	}
}

// A plan an older version saved (every item 「先不动」) takes this version's defaults when it is read again; once.
func TestAnOlderPlanTakesTheNewDefaults(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	r := s.Store.LastReport()
	v := s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	old := *v.plan
	old.Tool = ""
	old.Items = append([]PlanItem(nil), old.Items...)
	for i := range old.Items {
		old.Items[i].Suggested = ChoiceKeep
	}
	old.Save(s.plansDir())
	v = s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	if v.plan.ID != old.ID {
		t.Fatalf("plan %s, was %s", v.plan.ID, old.ID)
	}
	want := map[string]string{s.fid(pc.cache): ChoiceRemove, s.fid(pc.installer): ChoiceTrash, s.fid(pc.big): ChoiceKeep}
	for _, it := range v.plan.Items {
		if w, ok := want[it.FindingID]; ok && it.Suggested != w {
			t.Errorf("%s: %s, want %s", it.Title, it.Suggested, w)
		}
	}
	saved, _ := LoadPlan(s.plansDir(), old.ID)
	if saved.Tool != ToolVersion {
		t.Errorf("saved as %q", saved.Tool)
	}
	// A plan of this version is taken as it is
	for i := range saved.Items {
		saved.Items[i].Suggested = ChoiceKeep
	}
	saved.Save(s.plansDir())
	v = s.roundView(s.visible(*r, s.state()), *r, roundID(*r))
	for _, it := range v.plan.Items {
		if it.Suggested != ChoiceKeep {
			t.Errorf("a plan of this version changed: %s %s", it.Title, it.Suggested)
		}
	}
}

func TestNameLists(t *testing.T) {
	s := &Service{}
	for name, want := range map[string]string{"oMLX-0.7.3.dmg": "oMLX-0.7.3.dmg", "macOS Sonoma 14.1.2 安装程序.dmg": "macOS Sonoma 14.1.2 安装程序.dmg",
		"Visual Studio Code.app": "Visual Studio Code", "com.example.SomeApp": "SomeApp", "Tool.2.Beta.app": "Tool.2.Beta",
		"report.final.v2.pdf": "report.final.v2.pdf", "%E9%A6%99%E6%B8%AF.v2.pdf": "香港.v2.pdf"} {
		if got := s.shortName(core.Finding{Path: "/x/" + name}); got != want {
			t.Errorf("shortName(%s) = %q, want %q", name, got, want)
		}
	}
	inst := core.Finding{Rule: "leftover.installer", Path: "/x/Hermes-2.1.0.dmg", Evidence: map[string]string{"installed": "Hermes"}}
	if got := s.shortName(inst); got != "Hermes" {
		t.Errorf("installer: %q", got)
	}
	if got := nameList([]string{"「A」", "「B」", "「C」", "「D」", "「Hermes」"}, 4); got != "「A」、「B」、「C」、「D」等" {
		t.Errorf("%q", got)
	}
	if got := nameList([]string{"「A」", "「Hermes」"}, 4); got != "「A」、「Hermes」" {
		t.Errorf("%q", got)
	}
}

// A line of several says their size together, not the first one's (「安装包（246.1 MB），一共 41 项」).
func TestAGroupsTitleHasItsTotal(t *testing.T) {
	c := newCrowded(t)
	s := c.s
	title, _, names := s.plainGroup(lookGroup{key: "leftover.installer", findings: c.installers})
	var total int64
	for _, f := range c.installers {
		total += *f.Bytes
	}
	if title != "已经装好的应用留下的安装包，一共 41 项（"+core.FormatBytes(total)+"）" {
		t.Errorf("%q", title)
	}
	if names != "「App00」、「App01」、「App02」、「App03」等" {
		t.Errorf("%q", names)
	}
}

// The plan's card (scan_plan) draws a kind of many as one choice too, and stays within 200 components.
func TestThePlansCardGroupsKindsToo(t *testing.T) {
	c := newCrowded(t)
	s := c.s
	out, err := s.planTool(O{}, s.state())
	if err != nil {
		t.Fatal(err)
	}
	comps, choices := cardParts(t, out.Card)
	if len(comps) > CardMaxComponents {
		t.Errorf("%d components", len(comps))
	}
	grouped := 0
	for k := range choices {
		if strings.HasPrefix(k, "g-") {
			grouped++
		}
	}
	if grouped != 2 || len(choices) != 2+6 { // the installers and the duplicates; each cache on its own
		t.Errorf("choices %v", choices)
	}
	if ts := strings.Join(texts(comps), "\n"); !strings.Contains(ts, "已经装好的应用留下的安装包，一共 41 项（") {
		t.Errorf("%s", ts)
	}
}

// weighed: what the window puts for {n} with countWeights: the weights (1 when not given) of the choices equal to
// count.value.
func weighed(choices map[string]any, count map[string]any) int {
	weights, _ := count["weights"].(map[string]any)
	n := 0
	for k, v := range choices {
		for _, x := range v.([]any) {
			if x == count["value"] {
				w := 1
				if f, ok := weights[k].(float64); ok {
					w = int(f)
				}
				n += w
			}
		}
	}
	return n
}

// Where the core weighs rows (countWeights), the bottom button counts on a page with rows of a kind too: each such row
// weighs its items, so the 41 installers chosen count 41, and with one more file 42. Without countWeights the words stay.
func TestCountWeighsAKindsRow(t *testing.T) {
	c := newCrowded(t)
	s := c.s
	home := s.Config.Context.Home
	big := filepath.Join(home, "Movies/clip.mov")
	os.MkdirAll(filepath.Dir(big), 0o755)
	os.WriteFile(big, []byte("x"), 0o644)
	old := time.Now().AddDate(0, 0, -30)
	os.Chtimes(big, old, old)
	r := s.Store.LastReport()
	rep := *r
	rep.Findings = append(append([]core.Finding(nil), r.Findings...), core.Finding{Rule: "stale.large-file", Category: core.CatSpace,
		Severity: core.Low, Verdict: core.Confirm, Path: big, Bytes: core.Size(2_000_000_000),
		Evidence: map[string]string{"last_opened": old.AddDate(-2, 0, 0).Format("2006-01-02")}})
	if err := s.Store.SaveReport(rep); err != nil {
		t.Fatal(err)
	}
	v := s.roundView(s.visible(rep, s.state()), rep, roundID(rep))
	groups := planGroups(v.plan.Items)
	single := ""
	for _, it := range v.plan.Items {
		if it.Rule == "stale.large-file" {
			single = it.Key
		}
	}

	comps, choices := cardParts(t, s.page("overview", s.state(), withFeature(everyFeature, "countWeights")))
	counted := buttonsOf(comps)["移到废纸篓 {n} 项"]
	if counted == nil {
		t.Fatalf("no counted button: %v", buttonsOf(comps))
	}
	count := counted["count"].(map[string]any)
	want := map[string]any{groups[0].key: float64(41), groups[1].key: float64(7)}
	if !reflect.DeepEqual(count["weights"], want) || count["value"] != ChoiceTrash || count["alsoLabel"] != "按上面的选择处理" {
		t.Errorf("count %v", count)
	}
	// As drawn at first: the row of 41 installers is chosen for the Trash (what automatic cleaning would take)
	if n := weighed(choices, count); n != 41 {
		t.Errorf("{n} = %d at first, want 41: %v", n, choices)
	}
	choices[single] = []any{ChoiceTrash}
	if n := weighed(choices, count); n != 42 {
		t.Errorf("{n} = %d with the file too, want 42", n)
	}
	choices[groups[1].key] = []any{ChoiceTrash}
	if n := weighed(choices, count); n != 49 {
		t.Errorf("{n} = %d with the duplicates too, want 49", n)
	}

	// countLabel and countAlso without countWeights: a page with rows of a kind keeps the words, and has no weights
	comps, _ = cardParts(t, s.page("overview", s.state(), everyFeature))
	if bs := buttonsOf(comps); bs["按上面的选择清理"] == nil || bs["移到废纸篓 {n} 项"] != nil || bs["按上面的选择清理"]["count"] != nil {
		t.Errorf("without countWeights: %v", bs)
	}
}
