package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// A line of several of a kind whose one-item title names it: with several names the title says what kind they are,
// not the first one's name (「『Claude』的缓存，一共 6 项」 over Claude, discord, Slack…); the names are in the line under
// it. With one name the title is as before.
func TestAGroupOfSeveralNamesIsTitledByItsKind(t *testing.T) {
	s := &Service{}
	size := func(n int64) *int64 { return core.Size(n << 20) }
	two := func(rule string, cat core.Category, a, b core.Finding) []core.Finding {
		for _, f := range []*core.Finding{&a, &b} {
			f.Rule, f.Category, f.Severity, f.Verdict = rule, cat, core.Low, core.Confirm
		}
		return []core.Finding{a, b}
	}
	cases := map[string][]core.Finding{
		"cache.app": two("cache.app", core.CatCache,
			core.Finding{Path: "/u/Library/Caches/com.anthropic.claudefordesktop", Title: "「Claude」的缓存", Bytes: size(300)},
			core.Finding{Path: "/u/Library/Caches/com.tinyspeck.slackmacgap", Title: "「Slack」的缓存", Bytes: size(200)}),
		"cache.electron": two("cache.electron", core.CatCache,
			core.Finding{Path: "/u/Library/Application Support/discord", Title: "「discord」的缓存", Bytes: size(300)},
			core.Finding{Path: "/u/Library/Application Support/obsidian", Title: "「obsidian」的缓存", Bytes: size(200)}),
		"cache.logs": two("cache.logs", core.CatCache,
			core.Finding{Path: "/u/Library/Logs/Notes Pro", Title: "「Notes Pro」的日志", Bytes: size(300)},
			core.Finding{Path: "/u/Library/Logs/Mail Plus", Title: "「Mail Plus」的日志", Bytes: size(200)}),
		core.InstallScriptsRuleID: two(core.InstallScriptsRuleID, core.CatPosture,
			core.Finding{Path: "/u/.config/pip/pip.conf", Evidence: map[string]string{"tool": "pip"}},
			core.Finding{Path: "/u/.config/uv/uv.toml", Evidence: map[string]string{"tool": "uv"}}),
		"keyboard.unvouched": two("keyboard.unvouched", core.CatProcess,
			core.Finding{Path: "/Applications/Key Spy.app"}, core.Finding{Path: "/Applications/Type Watch.app"}),
		"malware.clamav": two("malware.clamav", core.CatMalware,
			core.Finding{Path: "/u/Downloads/eicar-one.com"}, core.Finding{Path: "/u/Downloads/eicar-two.com"}),
		"supplychain.malicious": two("supplychain.malicious", core.CatSupplyChain,
			core.Finding{Path: "/u/code/shop-web", Evidence: map[string]string{"package": "evil-pkg"}},
			core.Finding{Path: "/u/code/admin-ui", Evidence: map[string]string{"package": "bad-pkg"}}),
		"process.deleted-binary": two("process.deleted-binary", core.CatProcess,
			core.Finding{Path: "/u/bin/sync-helper"}, core.Finding{Path: "/u/bin/backup-agent"}),
		"process.dyld-insert": two("process.dyld-insert", core.CatProcess,
			core.Finding{Path: "/u/.cache/hook.dylib"}, core.Finding{Path: "/opt/proxy/libproxy.dylib"}),
		"process.library-temp": two("process.library-temp", core.CatProcess,
			core.Finding{Path: "/tmp/_MEI1/libpython.dylib", Evidence: map[string]string{"program": "/u/bin/packed-tool", "place": "临时文件夹"}},
			core.Finding{Path: "/u/Downloads/plugin.dylib", Evidence: map[string]string{"program": "/u/bin/loader", "place": "下载文件夹"}}),
		"process.library-deleted": two("process.library-deleted", core.CatProcess,
			core.Finding{Path: "/u/bin/server", Evidence: map[string]string{"program": "/u/bin/server"}},
			core.Finding{Path: "/u/bin/worker", Evidence: map[string]string{"program": "/u/bin/worker"}}),
	}
	for rule, fs := range cases {
		title, _, names := s.plainGroup(lookGroup{key: groupKey(fs[0]), findings: fs})
		one, _ := s.plain(fs[0])
		if strings.Contains(title, "「") {
			t.Errorf("%s: %q names one of them", rule, title)
		}
		if title == one || strings.HasPrefix(title, strings.TrimSuffix(one, plainSize(fs[0].Bytes))+"，") {
			t.Errorf("%s: %q is the first one's title", rule, title)
		}
		if strings.Count(names, "「") != 2 {
			t.Errorf("%s: names %q", rule, names)
		}
	}
	// One name (one app's caches in two places): its title as before
	same := two("cache.app", core.CatCache,
		core.Finding{Path: "/u/Library/Caches/Claude", Title: "「Claude」的缓存", Bytes: size(300)},
		core.Finding{Path: "/u/Library/Containers/x/Data/Library/Caches/Claude", Title: "「Claude」的缓存", Bytes: size(200)})
	if title, _, _ := s.plainGroup(lookGroup{key: groupKey(same[0]), findings: same}); !strings.HasPrefix(title, "「Claude」的缓存，一共 2 项") {
		t.Errorf("one name: %q", title)
	}
}

// The scan page: six apps' caches, one row (planGroups), titled by their kind, the apps named under it.
func TestSeveralAppsCachesAreOneRowTitledByTheKind(t *testing.T) {
	m := newModelSetup(t)
	home := m.ctx.Home
	var fs []core.Finding
	apps := []string{"Claude", "discord", "Slack", "obsidian", "Notion", "Figma"}
	for i, app := range apps {
		p := filepath.Join(home, "Library/Caches", app)
		os.MkdirAll(p, 0o755)
		if err := os.WriteFile(filepath.Join(p, "x"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		fs = append(fs, core.Finding{Rule: "cache.app", Category: core.CatCache, Severity: core.Low, Verdict: core.Confirm, Path: p,
			Bytes: core.Size(int64(i+1) * 300_000_000), Title: "「" + app + "」的缓存", Evidence: map[string]string{"app": app}})
	}
	now := core.Time{Time: time.Now()}
	s := m.service(nil, nil)
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	comps, _ := cardParts(t, s.page("overview", s.state(), allFeatures))
	all := strings.Join(texts(comps), "\n")
	want := fmt.Sprintf("几个应用的缓存，一共 %d 项", len(apps))
	if !strings.Contains(all, want) {
		t.Errorf("no %q in:\n%s", want, all)
	}
	for _, app := range apps {
		if strings.Contains(all, "「"+app+"」的缓存") {
			t.Errorf("a title names %s:\n%s", app, all)
		}
	}
	if !strings.Contains(all, "「Claude」") || !strings.Contains(all, "「Slack」") {
		t.Errorf("the apps are not named:\n%s", all)
	}
}
