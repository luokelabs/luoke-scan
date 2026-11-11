package service

import (
	"strings"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// Only what the virus database or YARA recognised is called 「病毒」: apps.* and malware.odd-name are CatMalware too;
// forced browser extensions and native hosts are CatPersistence but are about the browser (luoke-scan#121 review).
func TestPlainSaysWhatItIs(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	home := m.ctx.Home
	cases := []struct {
		f    core.Finding
		want string
		not  string
	}{
		{core.Finding{Rule: "malware.clamav", Category: core.CatMalware, Path: home + "/Downloads/x.com"}, "可能是病毒", ""},
		{core.Finding{Rule: "apps.unsigned", Category: core.CatMalware, Path: "/Applications/Odd.app"}, "「Odd」来路不明", "病毒"},
		{core.Finding{Rule: "malware.odd-name", Category: core.CatMalware, Path: home + "/Downloads/x"}, "名字很怪", "可能是病毒"},
		{core.Finding{Rule: "browser.forced-extensions", Category: core.CatPersistence, Path: home + "/x"}, "浏览器", "一起启动"},
		{core.Finding{Rule: "browser.native-host", Category: core.CatPersistence, Path: home + "/x"}, "浏览器", "一起启动"},
	}
	for _, c := range cases {
		title, advice := s.plain(c.f)
		got := title + "｜" + advice
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: %q lacks %q", c.f.Rule, got, c.want)
		}
		if c.not != "" && strings.Contains(got, c.not) {
			t.Errorf("%s: %q says %q", c.f.Rule, got, c.not)
		}
	}
	g := lookGroup{key: "browser.native-host", findings: []core.Finding{cases[4].f, cases[4].f}}
	if title, _, _ := s.plainGroup(g); !strings.Contains(title, "浏览器") {
		t.Errorf("group of browser findings: %q", title)
	}
}
