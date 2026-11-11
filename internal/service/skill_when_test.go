package service

import (
	"strings"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// What users ask first of an AI plugin 「能操作你的电脑」: does it run by itself, with no AI calling it? Each kind says
// it does not and when it does run, on a line; what to do on a line of its own, each fitting one line of an item row.
// One found to set up what starts by itself says so instead (「不会自己运行」 alone would say the opposite of why it is
// reported). A row of several of one kind says that kind's lines of them all; of several kinds, lines naming no tool.
func TestAIPluginsSayWhenTheyRun(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	home := m.ctx.Home
	own := core.Finding{Rule: "skill.exfil", Category: core.CatSkill, Path: home + "/.claude/skills/sync-notes",
		Evidence: map[string]string{"skill": "sync-notes", "agent": "Claude", "kinds": "exfil"}}
	codex := core.Finding{Rule: "skill.exfil", Category: core.CatSkill, Path: home + "/.codex/skills/tidy",
		Evidence: map[string]string{"skill": "tidy", "agent": "Codex", "kinds": "exfil"}}
	plugin := core.Finding{Rule: "skill.download-exec", Category: core.CatSkill, Path: home + "/.claude/plugins/x/skills/quick-setup",
		Evidence: map[string]string{"skill": "quick-setup", "agent": "Claude Code 插件", "kinds": "download-exec"}}
	starts := core.Finding{Rule: "skill.persistence", Category: core.CatSkill, Path: home + "/.claude/skills/keep-alive",
		Evidence: map[string]string{"skill": "keep-alive", "agent": "Claude", "kinds": "exfil,persistence"}}
	startsAlso := own
	startsAlso.Evidence = map[string]string{"skill": "sync-notes", "agent": "Claude", "kinds": "exfil,persistence"}
	file := core.Finding{Rule: "agentfile.injection", Category: core.CatSkill, Path: home + "/Codes/site/AGENTS.md"}
	fileStarts := core.Finding{Rule: "agentfile.persistence", Category: core.CatSkill, Path: home + "/Codes/app/CLAUDE.md"}
	cases := []struct {
		f        core.Finding
		runs, do string
	}{
		{own, "不会自己运行；AI 用到它时", "移到废纸篓"},
		{plugin, "不会自己运行；用 Claude Code 时", "/plugin 卸载"},
		{file, "不会自己运行；AI 在这个项目里写代码时", "删掉"},
		{starts, "本身不会自己运行，但 AI 用过它可能装上开机自启", "移到废纸篓"},
		{startsAlso, "可能装上开机自启", "移到废纸篓"},
		{fileStarts, "可能装上开机自启", "删掉"},
	}
	lines := func(what, advice string) []string {
		ls := strings.Split(advice, "\n")
		if len(ls) != 2 {
			t.Errorf("%s: when it runs, then what to do, a line each: %q", what, advice)
			return []string{advice, ""}
		}
		for _, l := range ls {
			if w := lineWidth(l); w > rowLineWidth {
				t.Errorf("%s: %q is %.1f wide, more than an item row's one line (%v)", what, l, w, rowLineWidth)
			}
		}
		return ls
	}
	for _, c := range cases {
		title, advice := s.plain(c.f)
		ls := lines(c.f.Path, advice)
		if !strings.Contains(ls[0], "不会自己运行") || !strings.Contains(ls[0], c.runs) {
			t.Errorf("%s: %q does not say when it runs (%q)", c.f.Path, ls[0], c.runs)
		}
		if !strings.Contains(ls[1], c.do) {
			t.Errorf("%s: %q does not say what to do (%q)", c.f.Path, ls[1], c.do)
		}
		if strings.Contains(title, "自己运行") {
			t.Errorf("%s: the title says it runs by itself: %q", c.f.Path, title)
		}
	}

	group := func(fs ...core.Finding) []string {
		_, advice, _ := s.plainGroup(lookGroup{key: "skill", findings: fs})
		return lines("a row", advice)
	}
	if ls := group(own, codex); !strings.Contains(ls[0], "AI 用到它们时") || !strings.Contains(ls[1], "移到废纸篓") {
		t.Errorf("a row of own plugins: %q", ls)
	}
	if ls := group(plugin, plugin); !strings.Contains(ls[0], "Claude Code") || !strings.Contains(ls[1], "/plugin 卸载") {
		t.Errorf("a row of Claude Code plugins: %q", ls)
	}
	for _, fs := range [][]core.Finding{{plugin, codex}, {codex, plugin}} {
		ls := group(fs...)
		if strings.Contains(ls[0], "Claude Code") || !strings.Contains(ls[0], "不会自己运行") {
			t.Errorf("Claude Code's and Codex's in a row, whichever first: %q", ls)
		}
		if !strings.Contains(ls[1], "Claude Code 的用 /plugin 卸载") || !strings.Contains(ls[1], "移到废纸篓") {
			t.Errorf("what to do with each: %q", ls)
		}
	}
	if ls := group(own, starts); !strings.Contains(ls[0], "可能装上开机自启") {
		t.Errorf("a row with one that sets up what starts by itself: %q", ls)
	}
	if ls := group(own, file); strings.Contains(ls[1], "Claude Code") || !strings.Contains(ls[1], "不是你写的") {
		t.Errorf("plugins and an instruction file: %q", ls)
	}
}

// On a 860-wide window an item row's line under 「可以清掉」 shows some 30 Chinese characters before it is cut (§4
// maxLines); a few less, so a narrower font or a size badge still leaves it whole.
const rowLineWidth = 27.0

// lineWidth counts a Chinese character as 1 and an ASCII one as half.
func lineWidth(s string) float64 {
	w := 0.0
	for _, r := range s {
		if r < 0x80 {
			w += 0.5
		} else {
			w++
		}
	}
	return w
}

// An item's detail of several lines is a text each where the core cuts texts, so a long first line does not push what
// to do out of sight.
func TestItemDetailIsALineEach(t *testing.T) {
	detail := pluginRuns + "\n" + pluginDo
	c := NewCard("t").Use(map[string]bool{"maxLines": true, "badge": true, "itemIcons": true, "lucide": true})
	c.ItemChoice("puzzle", "「Claude Code」的插件「x」能操作你的电脑", "", detail, "k", labeled([]string{ChoiceTrash, ChoiceKeep}), ChoiceTrash)
	var texts []string
	for _, m := range c.Updates(false) {
		up, _ := m.(O)["updateComponents"].(O)
		comps, _ := up["components"].([]any)
		for _, x := range comps {
			comp, _ := x.(O)
			if comp["component"] == "Text" && comp["variant"] == "caption" {
				if n, _ := comp["maxLines"].(int); n != 1 {
					t.Errorf("%v: cut to one line", comp)
				}
				texts = append(texts, comp["text"].(string))
			}
		}
	}
	if want := []string{pluginRuns, pluginDo}; strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("detail lines %q, want %q", texts, want)
	}
}

// Under 「要你看看」 a row of plugins or instruction files has one short line (the design's): it too says they do not
// run by themselves, and what to do, of the whole row whichever comes first; one found to set up what starts by
// itself only says what to do. One line each, as 「要你看看」 cuts it.
func TestLookLineSaysPluginsDoNotRunByThemselves(t *testing.T) {
	own := core.Finding{Rule: "skill.exfil", Category: core.CatSkill, Evidence: map[string]string{"skill": "a", "agent": "Claude", "kinds": "exfil"}}
	codex := core.Finding{Rule: "skill.exfil", Category: core.CatSkill, Evidence: map[string]string{"skill": "b", "agent": "Codex", "kinds": "exfil"}}
	plugin := core.Finding{Rule: "skill.download-exec", Category: core.CatSkill, Evidence: map[string]string{"skill": "c", "agent": "Claude Code 插件"}}
	starts := core.Finding{Rule: "skill.persistence", Category: core.CatSkill, Evidence: map[string]string{"skill": "d", "agent": "Claude"}}
	file := core.Finding{Rule: "agentfile.injection", Category: core.CatSkill, Path: "/x/AGENTS.md"}
	line := func(fs ...core.Finding) string { return lookAdvice(lookGroup{key: "skill", findings: fs}, "") }
	for _, c := range []struct {
		fs   []core.Finding
		want string
	}{
		{[]core.Finding{plugin, plugin}, "不会自己运行；不是你装的，就在 Claude Code 里用 /plugin 卸掉"},
		{[]core.Finding{own, codex}, "不会自己运行；不是你装的就删掉"},
		{[]core.Finding{codex, plugin}, "不会自己运行；不是你装的就删掉，Claude Code 的用 /plugin 卸掉"},
		{[]core.Finding{plugin, codex}, "不会自己运行；不是你装的就删掉，Claude Code 的用 /plugin 卸掉"},
		{[]core.Finding{file}, "不会自己运行；不是你写的就删掉"},
		{[]core.Finding{own, starts}, "不是你装的就删掉"},
		{[]core.Finding{plugin, starts}, "不是你装的就删掉，Claude Code 的用 /plugin 卸掉"},
	} {
		got := line(c.fs...)
		if got != c.want {
			t.Errorf("%v: %q, want %q", c.fs, got, c.want)
		}
		if w := lineWidth(got); w > 32 {
			t.Errorf("%q is %.1f wide: more than 「要你看看」's one line", got, w)
		}
	}
}
