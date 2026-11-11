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

// designFeatures: what the core that draws the scan page as in the design (luoke-scan#129) lists: every form so far,
// with big pages, chips, beige tags and a card per part.
func designFeatures() map[string]bool {
	f := withEveryFeature()
	for _, k := range []string{"bigPages", "chips", "neutralBadge", "pageSections"} {
		f[k] = true
	}
	return f
}

// pageTree: a page's components by id, and the root.
func pageTree(t *testing.T, msgs []any) (map[string]map[string]any, map[string]any) {
	comps, _ := cardParts(t, msgs)
	byID := map[string]map[string]any{}
	for _, c := range comps {
		byID[c["id"].(string)] = c
	}
	return byID, byID["root"]
}

func kidsOf(c map[string]any) []string {
	var out []string
	if ks, ok := c["children"].([]any); ok {
		for _, k := range ks {
			out = append(out, k.(string))
		}
	}
	return out
}

// textsUnder: every Text under a component, in order.
func textsUnder(byID map[string]map[string]any, id string) []string {
	c := byID[id]
	if c == nil {
		return nil
	}
	var out []string
	if c["component"] == "Text" {
		out = append(out, c["text"].(string))
	}
	if ch, ok := c["child"].(string); ok {
		out = append(out, textsUnder(byID, ch)...)
	}
	for _, k := range kidsOf(c) {
		out = append(out, textsUnder(byID, k)...)
	}
	return out
}

// partTitled: the part (a Column right under the root) whose small title starts with these words.
func partTitled(byID map[string]map[string]any, root map[string]any, words string) map[string]any {
	for _, k := range kidsOf(root) {
		c := byID[k]
		if c["component"] != "Column" {
			continue
		}
		for _, x := range kidsOf(c) {
			if byID[x]["component"] == "Divider" {
				continue
			}
			if ts := textsUnder(byID, x); byID[x]["component"] == "Row" && len(ts) > 0 && ts[0] == words {
				return c
			}
			break
		}
	}
	return nil
}

// lookDesignRound: four apps from nowhere (one kind, names as chips), FileVault off (a settings page), an app deleted
// but still allowed to record the screen, a password in a file (the Finder), and six programs that start with the
// computer, each a kind of its own: ten kinds, the first five shown, the rest folded.
func lookDesignRound(t *testing.T) *Service {
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
	var fs []core.Finding
	for i := 0; i < 4; i++ {
		file(fmt.Sprintf("Applications/Tool%d.app/Contents/Info.plist", i))
		fs = append(fs, core.Finding{Rule: "apps.unsigned", Category: core.CatMalware, Severity: core.Medium, Verdict: core.Confirm,
			Path: filepath.Join(home, fmt.Sprintf("Applications/Tool%d.app", i)), Title: "unsigned"})
	}
	fs = append(fs,
		core.Finding{Rule: "posture.filevault", Category: core.CatPosture, Severity: core.Medium, Verdict: core.Confirm, Title: "FileVault"},
		core.Finding{Rule: "permission.stale-grant", Category: core.CatPermission, Severity: core.Medium, Verdict: core.Confirm,
			Path: "/Applications/Recorder.app", Title: "Recorder", Evidence: map[string]string{"grants": "屏幕录制"}},
		core.Finding{Rule: "secrets.plaintext", Category: core.CatPosture, Severity: core.Medium, Verdict: core.Confirm,
			Path: file("Documents/config.ini"), Title: "配置文件里明文写着密码"})
	for i := 0; i < 6; i++ {
		fs = append(fs, core.Finding{Rule: fmt.Sprintf("startup.kind-%02d", i), Category: core.CatPersistence, Severity: core.Medium,
			Verdict: core.Confirm, Path: file(fmt.Sprintf("Library/LaunchAgents/io.example.prog-%02d.plist", i)),
			Evidence: map[string]string{"scope": "user-agent", "label": fmt.Sprintf("io.example.prog-%02d", i)}})
	}
	now := core.Time{Time: time.Now()}
	s := m.service(nil, nil)
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	return s
}

// 「要你看看」 as in the design (luoke-scan#129, 11-10) where the core draws pages a card per part: the page's root
// is laid out in sections; the part's small title is the eye, 「要你看看」 and the count apart; one line per kind in a
// List, the first five, then 「还有 5 类，共 N 项」 folding the rest in a List of their own; names as beige chips, three and
// 「等」; what to do in one short line; a line's one button with its icon and words (在访达里看, the gear for a settings
// page, 去设置移除), a startup item's only 在登录项里管理.
func TestLookPartAsInTheDesign(t *testing.T) {
	s := lookDesignRound(t)
	byID, root := pageTree(t, s.page("overview", s.state(), designFeatures()))
	if root["layout"] != "sections" {
		t.Fatalf("root %v", root)
	}
	look := partTitled(byID, root, "要你看看")
	if look == nil {
		t.Fatalf("no part 要你看看 under the root: %v", kidsOf(root))
	}
	kids := kidsOf(look)
	var title map[string]any
	for _, k := range kids {
		if byID[k]["component"] == "Row" {
			title = byID[k]
			break
		}
	}
	tk := kidsOf(title)
	if len(tk) != 3 || byID[tk[0]]["name"] != "eye" || byID[tk[1]]["text"] != "要你看看" || byID[tk[2]]["text"] != "13" {
		t.Errorf("title %v", textsUnder(byID, title["id"].(string)))
	}
	var lists []string
	var fold map[string]any
	for _, k := range kids {
		switch {
		case byID[k]["component"] == "List":
			lists = append(lists, k)
		case byID[k]["collapsed"] != nil:
			fold = byID[k]
		}
	}
	if len(lists) != 1 || len(kidsOf(byID[lists[0]])) != 5 {
		t.Fatalf("lines: %v", lists)
	}
	if fold == nil || !strings.HasPrefix(fold["collapsed"].(string), "还有 5 类，共 ") {
		t.Fatalf("fold %v", fold)
	}
	if fk := kidsOf(fold); len(fk) != 1 || byID[fk[0]]["component"] != "List" || len(kidsOf(byID[fk[0]])) != 5 {
		t.Errorf("folded: %v", fk)
	}
	// each line, by its title
	line := map[string]string{}
	for _, l := range append(kidsOf(byID[lists[0]]), kidsOf(byID[kidsOf(fold)[0]])...) {
		line[textsUnder(byID, l)[0]] = l
	}
	button := func(lineID string) []map[string]any {
		var out []map[string]any
		var walk func(string)
		walk = func(id string) {
			c := byID[id]
			if c == nil {
				return
			}
			if c["component"] == "Button" {
				out = append(out, c)
				return
			}
			for _, k := range kidsOf(c) {
				walk(k)
			}
		}
		walk(lineID)
		return out
	}
	one := func(title, words, icon string) {
		bs := button(line[title])
		if len(bs) != 1 {
			t.Errorf("%s: %d buttons", title, len(bs))
			return
		}
		row := byID[bs[0]["child"].(string)]
		rk := kidsOf(row)
		if len(rk) != 2 || byID[rk[0]]["name"] != icon || byID[rk[1]]["text"] != words {
			t.Errorf("%s: button %v %v", title, row, textsUnder(byID, bs[0]["id"].(string)))
		}
	}
	apps := line["4 个最近装的应用来路不明"]
	if apps == "" {
		t.Fatalf("lines %v", line)
	}
	// the names: Tool0, Tool1, Tool2 as beige chips, then 「等」
	var chips map[string]any
	var find func(string)
	find = func(id string) {
		c := byID[id]
		if c == nil || chips != nil {
			return
		}
		ks := kidsOf(c)
		if c["component"] == "Row" && len(ks) > 0 && byID[ks[0]]["variant"] == "badge" {
			chips = c
			return
		}
		for _, k := range ks {
			find(k)
		}
	}
	find(apps)
	if chips == nil {
		t.Fatalf("no chips under the apps' line: %v", textsUnder(byID, apps))
	}
	var names []string
	for _, k := range kidsOf(chips) {
		c := byID[k]
		if c["variant"] == "badge" && c["tone"] != "neutral" {
			t.Errorf("chip %v", c)
		}
		names = append(names, c["text"].(string))
	}
	if !reflect.DeepEqual(names, []string{"Tool0", "Tool1", "Tool2", "等"}) || byID[kidsOf(chips)[3]]["variant"] != "caption" {
		t.Errorf("chips %v", names)
	}
	one("硬盘没加密：电脑丢了，别人能直接读出里面的东西", "打开 FileVault 设置", "settings")
	one("已删除的「Recorder」仍有「屏幕录制」权限", "去设置移除", "settings")
	for title := range line {
		switch {
		case strings.Contains(title, "密码"):
			one(title, "在访达里看", "folder-open")
		case strings.Contains(title, "一起启动"): // 在登录项里管理 only, not also 在访达里显示
			one(title, "在登录项里管理", "settings")
		}
	}
	// what to do, one short line as in the design (负责人 11-11)
	for title, want := range map[string]string{
		"4 个最近装的应用来路不明":            "不是你装的就删掉",
		"已删除的「Recorder」仍有「屏幕录制」权限": "应用已经删了，权限可以一起移除",
		"硬盘没加密：电脑丢了，别人能直接读出里面的东西":  "打开时会给你恢复密钥，抄下来放好",
	} {
		if ts := textsUnder(byID, line[title]); !contains(ts, want) {
			t.Errorf("%s: %q", title, ts)
		}
	}
	for title, l := range line {
		if strings.Contains(title, "一起启动") && !contains(textsUnder(byID, l), "不认识的可以关掉开机启动") {
			t.Errorf("%s: %q", title, textsUnder(byID, l))
		}
	}
	if comps, _ := cardParts(t, s.page("overview", s.state(), designFeatures())); len(comps) > PageMaxComponents {
		t.Errorf("%d components", len(comps))
	}
}

// Where the core does not draw a card per part, the page is as before: no layout, no List, no chips, the buttons'
// words as they were.
func TestLookPartWithoutSectionsAsBefore(t *testing.T) {
	s := lookDesignRound(t)
	for _, features := range []map[string]bool{nil, withEveryFeature()} {
		comps, _ := cardParts(t, s.page("overview", s.state(), features))
		byID, root := pageTree(t, s.page("overview", s.state(), features))
		if root["layout"] != nil {
			t.Errorf("features %v: layout %v", features != nil, root["layout"])
		}
		for _, c := range comps {
			if c["component"] == "List" || c["tone"] != nil {
				t.Errorf("features %v: %v", features != nil, c)
			}
			if c["component"] == "Text" && (c["text"] == "在访达里看" || c["text"] == "去设置移除") {
				t.Errorf("features %v: %v", features != nil, c["text"])
			}
		}
		if indexOf(texts(comps), "要你看看 13") < 0 {
			t.Errorf("features %v: %q", features != nil, texts(comps))
		}
		_ = byID
	}
}

// The design's page as a whole: every part a Column under the root (urgent, 可以清掉, 要你看看, what was not checked)
// and the side column's parts too; the numbers a row of tiles; nothing else at the top but the page's first line.
func TestOverviewPartsUnderTheRoot(t *testing.T) {
	s := lookCrowd(t, 0)
	byID, root := pageTree(t, s.page("overview", s.state(), designFeatures()))
	for _, words := range []string{"可以清掉", "要你看看"} {
		if partTitled(byID, root, words) == nil {
			t.Errorf("no part %s: %v", words, kidsOf(root))
		}
	}
	for _, k := range kidsOf(root) {
		c := byID[k]
		switch {
		case c["component"] == "Column":
		case c["component"] == "Row" && (c["justify"] == "spaceBetween" || c["justify"] == "spaceEvenly"):
		default:
			t.Errorf("at the top: %v %q", c["component"], textsUnder(byID, k))
		}
		if c["placement"] == "aside" {
			for _, a := range kidsOf(c) {
				if ac := byID[a]; ac["component"] != "Column" && ac["justify"] != "spaceEvenly" {
					t.Errorf("in the side column: %v %q", ac["component"], textsUnder(byID, a))
				}
			}
		}
	}
	texts := strings.Join(textsUnder(byID, "root"), "\n")
	if strings.Contains(texts, "写在报告里") || strings.Contains(texts, "这一页放不下") {
		t.Errorf("%q", texts)
	}
}

// A kind counted in programs (「有 N 个会跟着电脑一起启动的程序」): one program with two items (two startup files) is one,
// as its chip; the title's number and the chips agree.
func TestProgramsCountedByName(t *testing.T) {
	s := &Service{}
	item := func(label, program string) core.Finding {
		return core.Finding{Rule: "persistence.launchagent", Category: core.CatPersistence, Severity: core.Medium,
			Verdict: core.Confirm, Path: "/u/Library/LaunchAgents/" + label + ".plist",
			Evidence: map[string]string{"scope": "user-agent", "label": label, "program": program}}
	}
	g := lookGroup{key: "persistence.launchagent", findings: []core.Finding{
		item("io.example.sync", "/u/Applications/Sync.app/Contents/MacOS/Sync"),
		item("io.example.sync-helper", "/u/Applications/Sync.app/Contents/MacOS/Sync"),
		item("io.example.backup", "/u/Applications/Backup.app/Contents/MacOS/Backup"),
	}}
	title, _, names := s.plainGroup(g)
	chips, more := s.groupChips(g, names)
	if title != "有 2 个会跟着电脑一起启动的程序" || len(chips) != 2 || more {
		t.Errorf("title %q, chips %v %v (names %q)", title, chips, more, names)
	}
}
