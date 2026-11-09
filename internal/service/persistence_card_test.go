package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// A new background job with a serious sign: said plainly, "是我装的" first, stopping it is not the main button.
func TestPersistenceCardIsPlain(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	f := core.Finding{Rule: "persistence.new", Category: core.CatPersistence, Severity: core.High, Verdict: core.Confirm,
		Path: m.ctx.Home + "/Library/LaunchAgents/io.example.odd.plist", Title: "新加了一个开机自动运行的任务：io.example.odd",
		Evidence: map[string]string{"scope": "user-agent", "name": "io.example.odd", "program": "~/Downloads/odd",
			"why": "程序没有开发者签名，程序放在下载文件夹里，装好的程序很少放在那儿"}}
	item := s.persistenceItem(f, "security/x", m.report)
	b, _ := json.Marshal(item)
	text := string(b)
	for _, bad := range []string{"为什么现在说", "恶意软件", "停掉并移到废纸篓", "我认识它"} {
		if strings.Contains(text, bad) {
			t.Errorf("card still says %q", bad)
		}
	}
	for _, want := range []string{"它会运行 ~/Downloads/odd。", "如果是你自己装的，点「是我装的」就好", "配置文件：", "\"是我装的\""} {
		if !strings.Contains(text, want) {
			t.Errorf("card lacks %q", want)
		}
	}
	if i, j := strings.Index(text, "\"是我装的\""), strings.Index(text, "在访达里显示"); i < 0 || j < 0 || i > j {
		t.Errorf("「是我装的」should come first")
	}
	t.Log(text)
}

// A known malicious package in a project: urgent, what to do written out, the lockfile shown in Finder; nothing of the
// project's is offered for deletion.
func TestMaliciousPackageCard(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	f := core.Finding{Rule: "supplychain.malicious", Category: core.CatSupplyChain, Severity: core.High, Verdict: core.Confirm,
		Path: m.ctx.Home + "/Projects/web/package-lock.json", Title: "项目 web 用了已知恶意的 evil-all@2.0.0",
		Key: "x", Evidence: map[string]string{"ids": "MAL-2025-1", "list": "恶意包名单 2026-10-10（OSV 的 MAL- 条目）",
			"lockfile": "~/Projects/web/package-lock.json", "how": "删掉这个项目的 node_modules，……都要换"}}
	if !isUrgent(f) || s.plannable(f) {
		t.Fatalf("urgent %v, plannable %v", isUrgent(f), s.plannable(f))
	}
	item := s.maliciousPackageItem(f, "security/x", m.report)
	if item["urgency"] != "urgent" || item["kind"] != "security" {
		t.Fatalf("item %v %v", item["kind"], item["urgency"])
	}
	b, _ := json.Marshal(item)
	text := string(b)
	for _, want := range []string{"依据：恶意包名单 2026-10-10（OSV 的 MAL- 条目），MAL-2025-1", "位置：~/Projects/web/package-lock.json", "删掉这个项目的 node_modules",
		"在访达里显示", "处理好了，以后别提"} {
		if !strings.Contains(text, want) {
			t.Errorf("card lacks %q", want)
		}
	}
	for _, bad := range []string{"移到废纸篓", "scan_apply", "不是病毒"} {
		if strings.Contains(text, bad) {
			t.Errorf("card has %q", bad)
		}
	}
}

// One known malicious package in thirty projects, and twelve more in another: the rule gives one finding per package and
// at most ten of them plus one for the rest, so the outbox has eleven urgent cards, not forty-two. The merged card
// says how many places and lists them; the card for the rest has nothing to show in Finder.
func TestMaliciousPackageCardsMergedAndCapped(t *testing.T) {
	l := core.Layout{Root: t.TempDir()}
	store, err := core.OpenStore(l.Data())
	if err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	list := "# luoke-scan malicious packages 1\n# date 2026-10-10\n# entries 13\nnpm\tevil-all\tMAL-2025-1\t*\n"
	var pk []string
	for i := 0; i < 12; i++ {
		list += "npm\tother-" + strconv.Itoa(i) + "\tMAL-2025-" + strconv.Itoa(10+i) + "\t*\n"
		pk = append(pk, `"node_modules/other-`+strconv.Itoa(i)+`": {"version": "1.0.0"}`)
	}
	write(filepath.Join(store.Dir, core.MaliciousListName), list)
	for i := 0; i < 30; i++ {
		write(filepath.Join(l.Projects(), "app"+strconv.Itoa(100+i), "package-lock.json"),
			`{"lockfileVersion": 3, "packages": {"node_modules/evil-all": {"version": "1.0.0"}}}`)
	}
	write(filepath.Join(l.Projects(), "zz/package-lock.json"), `{"lockfileVersion": 3, "packages": {`+strings.Join(pk, ", ")+`}}`)
	ctx := l.Context(store)
	found, err := core.NewSupplyChainRule(&l, &core.Fakes{}).Run(&ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := core.Time{Time: time.Now()}
	report := core.Report{StartedAt: now, FinishedAt: now, Findings: found}
	s := New(store, NewConfig(ctx))
	items := s.securityItems(report, State{Acks: map[string]Ack{}, Ignored: map[string]core.Time{}})
	if len(items) != 11 {
		t.Fatalf("want 11 urgent cards, got %d", len(items))
	}
	first, _ := json.Marshal(items[0])
	if !strings.Contains(string(first), "30 处用了已知恶意的 evil-all@1.0.0") || !strings.Contains(string(first), "位置（30 处）：项目 app100") ||
		!strings.Contains(string(first), "在访达里显示") {
		t.Fatalf("merged card: %s", first)
	}
	last, _ := json.Marshal(items[10])
	if !strings.Contains(string(last), "另外还有 3 个已知恶意的包") || !strings.Contains(string(last), "包：other-") ||
		strings.Contains(string(last), "在访达里显示") || !strings.Contains(string(last), "处理好了，以后别提") {
		t.Fatalf("card for the rest: %s", last)
	}
}
