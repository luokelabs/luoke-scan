package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

func compsByID(comps []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, c := range comps {
		out[c["id"].(string)] = c
	}
	return out
}

func compWithText(t *testing.T, comps []map[string]any, text string) map[string]any {
	t.Helper()
	for _, c := range comps {
		if c["component"] == "Text" && c["text"] == text {
			return c
		}
	}
	t.Fatalf("no text %q", text)
	return nil
}

// luoke-scan#129 (11-10): an item's title and what is under it are one line each where the core cuts texts (§4
// maxLines), as in the design; the lines under it a text each, one line each (names, then what to do: as one text cut
// to two lines, long names hid what to do; luoke-scan#153); sentences to follow (Whole) whole; nothing cut, and the
// lines one text as before, where the core does not cut.
func TestItemLinesOneEachWhereTheCoreCuts(t *testing.T) {
	opts := []Option{{Value: ChoiceKeep, Label: "先不动"}, {Value: "trash", Label: "移到废纸篓"}}
	build := func(features map[string]bool) []map[string]any {
		c := NewCard("p").Use(features)
		c.ItemChoice("file", "Hugging Face 的模型 some-org/speech-model-base", "3.1 GB", "37 天前下载", "k1", opts, ChoiceKeep)
		c.ItemButtons("puzzle", "AI 工具里有 7 个插件能自己运行命令", []ItemLine{{Text: "「a」、「b」、「c」、「d」等"}, {Text: "不是你装的就删掉"}}, nil)
		c.ItemButtons("cpu", "已经删掉的程序还在运行", []ItemLine{{Text: ""}, {Text: "它会跟着开机启动。\n要停掉它：照上面改，清理后重启。", Whole: true}}, nil)
		c.ItemChoiceShort("已经装好的应用留下的安装包，一共 41 项", "215.1 MB", "「A」、「B」等，这 41 项一起处理", "g-k", opts, "trash")
		comps, _ := cardParts(t, c.Messages())
		return comps
	}
	lines := func(c map[string]any) any { return c["maxLines"] }
	rows := map[string]bool{"itemIcons": true, "lucide": true, "badge": true, "maxLines": true}
	comps := build(rows)
	for text, want := range map[string]any{
		"Hugging Face 的模型 some-org/speech-model-base": 1.0, // JSON numbers
		"37 天前下载": 1.0,
		"3.1 GB":  nil, // the size tag stays whole after the cut title
		"AI 工具里有 7 个插件能自己运行命令":        1.0,
		"「a」、「b」、「c」、「d」等":            1.0, // a text each, one line each
		"不是你装的就删掉":                    1.0,
		"已经删掉的程序还在运行":                 1.0,
		"它会跟着开机启动。\n要停掉它：照上面改，清理后重启。": nil, // sentences to follow, whole
		"「A」、「B」等，这 41 项一起处理":         1.0, // under a choice as its label (no room for a row)
	} {
		if got := lines(compWithText(t, comps, text)); got != want {
			t.Errorf("item rows, %q: maxLines %v, want %v", text, got, want)
		}
	}

	// A core without item rows draws the title and the lines on their own: one line each too.
	comps = build(map[string]bool{"maxLines": true})
	for text, want := range map[string]any{
		"AI 工具里有 7 个插件能自己运行命令": 1.0, "「a」、「b」、「c」、「d」等": 1.0, "不是你装的就删掉": 1.0, "37 天前下载": 1.0,
		"它会跟着开机启动。\n要停掉它：照上面改，清理后重启。": nil,
	} {
		if got := lines(compWithText(t, comps, text)); got != want {
			t.Errorf("no item rows, %q: maxLines %v, want %v", text, got, want)
		}
	}

	// A core that does not cut texts: none written; the names and what to do one text, as before.
	for _, features := range []map[string]bool{nil, {"itemIcons": true, "lucide": true, "badge": true}} {
		comps := build(features)
		for _, c := range comps {
			if _, ok := c["maxLines"]; ok {
				t.Errorf("%v: maxLines on %v", features, c)
			}
		}
		compWithText(t, comps, "「a」、「b」、「c」、「d」等\n不是你装的就删掉")
	}
}

// luoke-scan#129 (11-10): the overview page starts with one line, 「扫描」 on the left, when it last looked and
// 「现在查一下」 on the right; the three numbers under it (in a wide window's side column when something waits). While
// a round runs the line has no button. Every item's title one line.
func TestOverviewStartsWithItsFirstLine(t *testing.T) {
	cr := newCrowded(t)
	s := cr.s
	head := func(features map[string]bool) (map[string]map[string]any, []any) {
		comps, _ := cardParts(t, s.page("overview", s.state(), features))
		by := compsByID(comps)
		return by, by["root"]["children"].([]any)
	}
	words := func(by map[string]map[string]any, ids []any) []string {
		var out []string
		for _, id := range ids {
			c := by[id.(string)]
			switch c["component"] {
			case "Text":
				out = append(out, c["variant"].(string)+":"+c["text"].(string))
			case "Button":
				out = append(out, "Button:"+by[c["child"].(string)]["text"].(string))
			default:
				out = append(out, c["component"].(string))
			}
		}
		return out
	}
	last := "caption:上次查 " + localTime(s.Store.LastReport().StartedAt.Time)

	for _, features := range []map[string]bool{nil, everyFeature} {
		by, top := head(features)
		first := by[top[0].(string)]
		if first["component"] != "Row" || first["justify"] != "spaceBetween" {
			t.Fatalf("%v: the page starts with %v", features != nil, first)
		}
		if got, want := strings.Join(words(by, first["children"].([]any)), " | "), "h4:扫描 | "+last+" | Button:现在查一下"; got != want {
			t.Errorf("%v: first line %q, want %q", features != nil, got, want)
		}
		// The numbers come next, in a side column (things wait on this page; a core without one draws it in place).
		next := by[top[1].(string)]
		if next["placement"] != "aside" {
			t.Fatalf("%v: after the first line %v", features != nil, next)
		}
		next = by[next["children"].([]any)[0].(string)]
		if next["component"] != "Row" || next["justify"] != "spaceEvenly" || len(next["children"].([]any)) != 3 {
			t.Errorf("%v: the numbers are not right under the first line: %v", features != nil, next)
		}
		if features == nil { // a core that does not cut texts (the title is the choice's label there): nothing cut
			for _, c := range by {
				if _, ok := c["maxLines"]; ok {
					t.Errorf("no forms: maxLines on %v", c)
				}
			}
			continue
		}
		title := "已经装好的应用留下的安装包，一共 41 项"
		var got any = "none"
		for _, c := range by {
			if c["component"] == "Text" && strings.HasPrefix(c["text"].(string), title) {
				got = c["maxLines"]
			}
		}
		if got != 1.0 {
			t.Errorf("the installers' title has maxLines %v, want 1", got)
		}
	}

	// A round running: the same line without the button, the progress right under it.
	lock := core.TakeLock(s.Store.Dir, "round.lock", 0)
	if lock == nil {
		t.Fatal("lock")
	}
	defer lock.Release()
	by, top := head(everyFeature)
	if got, want := strings.Join(words(by, by[top[0].(string)]["children"].([]any)), " | "), "h4:扫描 | "+last; got != want {
		t.Errorf("while a round runs: first line %q, want %q", got, want)
	}
	if got := words(by, top[1:2]); len(got) != 1 || got[0] != "Row" || !strings.Contains(strings.Join(texts(mapsOf(by)), "\n"), "正在查这台 Mac") {
		t.Errorf("while a round runs: after the first line %v", got)
	}
	for _, c := range by {
		if c["component"] == "Text" && c["text"] == "现在查一下" {
			t.Errorf("「现在查一下」 while a round runs")
		}
	}
}

// luoke-scan#153: in 「要你看看」 a kind's names and what to do with it are a text each, one line each, where the core
// cuts texts: four apps' names no longer push what to do out of sight.
func TestLookNamesAndAdviceOneLineEach(t *testing.T) {
	cr := newCrowded(t)
	comps, _ := cardParts(t, cr.s.page("overview", cr.s.state(), everyFeature))
	by := compsByID(comps)
	var groups []string
	for _, c := range comps {
		kids, _ := c["children"].([]any)
		if c["component"] != "Column" || len(kids) < 3 { // title, names, what to do (the plugins': two lines)
			continue
		}
		if names, _ := by[kids[1].(string)]["text"].(string); !strings.HasPrefix(names, "「") {
			continue
		}
		var lines []string
		for _, id := range kids {
			x := by[id.(string)]
			text, _ := x["text"].(string)
			lines = append(lines, text)
			if x["component"] != "Text" || x["maxLines"] != 1.0 || strings.Contains(text, "\n") {
				t.Errorf("not one line: %v", x)
			}
		}
		groups = append(groups, strings.Join(lines, " / "))
	}
	// the AI plugins and the four apps from nowhere: title, names, what to do
	if len(groups) != 2 || !strings.Contains(strings.Join(groups, "\n"), "「Tool.0.Beta」") {
		t.Errorf("kinds with names: %q", groups)
	}
}

// luoke-scan#153: what to do about a virus and about a known malicious package is done at once and read whole, not cut
// to one line (like the steps for a deleted program still running); their titles one line as any.
func TestUrgentAdviceWhole(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	home := m.ctx.Home
	virus := filepath.Join(home, "Downloads/invoice.com")
	os.MkdirAll(filepath.Dir(virus), 0o755)
	if err := os.WriteFile(virus, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := core.Time{Time: time.Now()}
	fs := []core.Finding{
		{Rule: "malware.clamav", Category: core.CatMalware, Severity: core.High, Verdict: core.Confirm, Path: virus,
			Bytes: core.Size(1), Title: "病毒库认出 invoice.com 是 Eicar-Test-Signature",
			Evidence: map[string]string{"signature": "Eicar-Test-Signature", "how": "移到废纸篓；如果是你刚下载的，别打开它"}},
		{Rule: "supplychain.malicious", Category: core.CatSupplyChain, Severity: core.High, Verdict: core.Confirm,
			Path: home + "/Projects/web/package-lock.json", Title: "项目 web 用了已知恶意的 evil-all@2.0.0", Key: "x",
			Evidence: map[string]string{"package": "evil-all@2.0.0", "lockfile": "~/Projects/web/package-lock.json"}},
	}
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	for _, features := range []map[string]bool{everyFeature, {"maxLines": true}} {
		comps, _ := cardParts(t, s.page("overview", s.state(), features))
		for part, want := range map[string]any{"病毒库认出了它": nil, "装过就当密码和登录已经泄露": nil,
			"「invoice.com」可能是病毒": 1.0, "装了一个已知的恶意软件包": 1.0} {
			var got any = "none"
			for _, c := range comps {
				if text, _ := c["text"].(string); c["component"] == "Text" && strings.Contains(text, part) {
					got = c["maxLines"]
				}
			}
			if got != want {
				t.Errorf("item rows %v, %q: maxLines %v, want %v", features["itemIcons"], part, got, want)
			}
		}
	}
}

func mapsOf(by map[string]map[string]any) []map[string]any {
	var out []map[string]any
	for _, c := range by {
		out = append(out, c)
	}
	return out
}
