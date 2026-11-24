package service

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

// data/overview says of each stale grant whose it is, which grants it still holds and what it left in Login Items &
// Extensions, as names and yes-or-no: the window lists them an app a line (luoke-scan#212). No sentences.
func TestDataOverviewStaleGrantFacts(t *testing.T) {
	m := newModelSetup(t)
	tool := "/opt/gone/tool"
	plist := "/Library/LaunchDaemons/io.gone.vpn.helper.plist"
	with := func(f core.Finding, more map[string]string) core.Finding {
		f.Severity, f.Verdict, f.Title = core.Low, core.Confirm, "title: "+f.Path
		f.Evidence["hint"], f.Evidence["how"] = "hint words", "how words"
		for k, v := range more {
			f.Evidence[k] = v
		}
		return f
	}
	fs := []core.Finding{
		with(staleFinding("io.gone.docs", "文稿、下载", ""), nil),
		with(staleFinding("io.gone.sync", "登录项", "Gone Sync"), map[string]string{"login_items": "Gone Sync、Gone Sync Agent",
			core.LeftItemsKey: "Gone Sync\nGone Sync Agent", core.LeftStartsKey: "0", core.LeftDaemonKey: "0"}),
		with(staleFinding("io.gone.vpn", "完全磁盘访问、登录项", ""), map[string]string{"login_items": plist,
			core.LeftItemsKey: plist, core.LeftStartsKey: "1", core.LeftDaemonKey: "1"}),
		with(staleFinding(tool, "录屏", ""), nil),
		// a round from before the rule kept the facts apart: the items as shown, starting not known
		with(staleFinding("io.gone.old", "登录项", ""), map[string]string{"login_items": "~/Library/LaunchAgents/io.gone.old.plist"}),
	}
	now := core.Time{Time: time.Now()}
	s := m.service(nil, nil)
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, x := range readData(t, s, "data/overview")["attention"].(map[string]any)["items"].([]any) {
		it := x.(map[string]any)
		for _, k := range []string{"title", "hint", "how"} {
			if _, has := it[k]; has {
				t.Errorf("%s in %v", k, it)
			}
		}
		if it["rule"] == "permission.stale-grant" {
			facts := it["facts"].(map[string]any)
			got[facts["client"].(string)] = facts
		}
	}
	login := func(starts, root any, items ...any) map[string]any {
		return map[string]any{"grant": "登录项", "items": items, "starts": starts, "root": root}
	}
	want := map[string]map[string]any{
		"io.gone.docs": {"client": "io.gone.docs", "clientType": "bundle", "app": nil, "grants": []any{"文稿", "下载"}, "loginItems": nil},
		"io.gone.sync": {"client": "io.gone.sync", "clientType": "bundle", "app": "Gone Sync", "grants": []any{},
			"loginItems": login(false, false, "Gone Sync", "Gone Sync Agent")},
		"io.gone.vpn": {"client": "io.gone.vpn", "clientType": "bundle", "app": nil, "grants": []any{"完全磁盘访问"},
			"loginItems": login(true, true, plist)},
		tool: {"client": tool, "clientType": "path", "app": nil, "grants": []any{"录屏"}, "loginItems": nil},
		"io.gone.old": {"client": "io.gone.old", "clientType": "bundle", "app": nil, "grants": []any{},
			"loginItems": login(nil, nil, filepath.Join(m.ctx.Home, "Library/LaunchAgents/io.gone.old.plist"))},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("facts\n got %v\nwant %v", got, want)
	}
	// Each grant is a name scan_open_settings takes.
	for _, facts := range got {
		for _, g := range facts["grants"].([]any) {
			if _, _, ok := settingsPane(g.(string)); !ok {
				t.Errorf("no settings page for %v", g)
			}
		}
	}
}
