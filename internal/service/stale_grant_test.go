package service

import (
	"strings"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

func staleFinding(client, grants, app string) core.Finding {
	ev := map[string]string{"grants": grants}
	if app != "" {
		ev["app"] = app
	}
	return core.Finding{Rule: "permission.stale-grant", Category: core.CatPermission, Path: client, Evidence: ev}
}

// What a deleted app left: its grants, its place in Login Items & Extensions, said with where each is taken away.
func TestStaleGrantSaysWhereItIsLeft(t *testing.T) {
	tcc := staleFinding("io.gone.meet", "摄像头", "")
	both := staleFinding("io.gone.meet", "摄像头、登录项", "Gone Meet")
	login := staleFinding("io.gone.sync", "登录项", "Gone Sync")
	for _, c := range []struct {
		f             core.Finding
		title, advice string
	}{
		{tcc, "已删除的「meet」仍有「摄像头」权限", grantAdvice},
		{both, "已删除的「Gone Meet」仍有「摄像头」权限，还在「登录项」里", "在系统设置中选中它，点「−」移除；「登录项与扩展」的「允许在后台」里，关掉它的开关。"},
		{login, "已删除的「Gone Sync」还在「登录项」里", "在系统设置的「登录项与扩展」里：「登录时打开」中的选中它点「−」，「允许在后台」中的关掉它的开关。"},
	} {
		if title, advice := staleGrant([]core.Finding{c.f}); title != c.title || advice != c.advice {
			t.Errorf("%q %q", title, advice)
		}
	}
	if title, advice := staleGrant([]core.Finding{tcc, staleFinding("io.gone.docs", "文稿", "")}); title != "2 个已删除的应用仍有权限" ||
		advice != "在系统设置中选中它们，点「−」移除。" {
		t.Errorf("several: %q %q", title, advice)
	}
	if title, advice := staleGrant([]core.Finding{tcc, login}); title != "2 个已删除的应用还留着权限或登录项" ||
		!strings.Contains(advice, "选中它们") || !strings.Contains(advice, "关掉它们的开关") {
		t.Errorf("several, with login items: %q %q", title, advice)
	}
	// Each grant a button of its own page; Login Items & Extensions is the one for 「登录项」.
	s := &Service{}
	b := s.listButtons(both)
	if len(b) != 2 || b[0].Label != "打开「摄像头」" || b[1].Label != "打开「登录项」" || b[1].Context["grant"] != core.LoginItemsGrant {
		t.Errorf("buttons: %+v", b)
	}
}

func TestEveryGrantOpensItsSettingsPage(t *testing.T) {
	for g, anchor := range core.GrantPages {
		pane, url, ok := settingsPane(g)
		if !ok || pane != anchor || url != core.GrantSettingsURL(g) {
			t.Errorf("%s: %q %q %v", g, pane, url, ok)
		}
	}
	if pane, url, ok := settingsPane(core.LoginItemsGrant); !ok || pane != "LoginItems" || url != core.LoginItemsURL {
		t.Errorf("login items: %q %q", pane, url)
	}
}
