package service

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// What an outbox item says as data (top-level ADR 0028): the same plan and items its card's buttons send, the same
// numbers its sentences say, and no sentence of its own.

var han = regexp.MustCompile(`\p{Han}`)

// noSentences: nothing in the data is wording. Names of files, apps and tools are content and may be anything; they
// are given under the keys listed here, everything else is codes, ids and numbers.
func noSentences(t *testing.T, where string, v any) {
	t.Helper()
	names := map[string]bool{"name": true, "app": true, "program": true, "package": true, "tool": true, "tools": true,
		"partial": true, "failed": true, "unrecorded": true, "path": true, "left": true, "notes": true}
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(k, e)
			}
		case []any:
			for _, e := range x {
				walk(key, e)
			}
		case string:
			if !names[key] && han.MatchString(x) {
				t.Errorf("%s: %q under %q reads as wording", where, x, key)
			}
		}
	}
	walk("", v)
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStartupItemDataSaysWhatTheCardOffers(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	login := core.Finding{Rule: "persistence.new", Category: core.CatPersistence, Severity: core.Medium, Verdict: core.Confirm,
		Path: "/Applications/Example Sync.app/Contents/Library/LoginItems/SyncAgent.app/Contents/MacOS/SyncAgent",
		Evidence: map[string]string{"scope": "login-item", "name": "Example Sync", "app": "Example Sync",
			"program": "/Applications/Example Sync.app/Contents/Library/LoginItems/SyncAgent.app/Contents/MacOS/SyncAgent", "why": "程序没有开发者签名"}}
	item := asMap(t, s.persistenceItem(login, "security/x", m.report))
	d := item["data"].(map[string]any)
	noSentences(t, "login item", d)
	if d["type"] != "startup-new" || d["scope"] != "login-item" || d["submitted"] != false || d["app"] != "Example Sync" ||
		d["settings"] != true || d["reveal"] != true || d["stop"] != nil {
		t.Errorf("login item: %v", d)
	}
	card, _ := json.Marshal(item["card"])
	if strings.Contains(string(card), "scan_open_settings") != (d["settings"] == true) {
		t.Errorf("settings: data %v, card %s", d["settings"], card)
	}
	program := m.ctx.Home + "/Library/Caches/io.example.chat/helper/Updater.app/Contents/MacOS/Updater"
	submitted := login
	submitted.Path = program
	submitted.Evidence = map[string]string{"scope": "login-item", "app": "Chat", "submitted": "1", "program": program, "why": "x"}
	d = asMap(t, s.persistenceItem(submitted, "security/y", m.report))["data"].(map[string]any)
	if d["submitted"] != true || d["settings"] != false || d["program"] != "Updater" || d["app"] != "Chat" {
		t.Errorf("submitted: %v", d)
	}
}

func TestPackageItemData(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	one := core.Finding{Rule: "supplychain.malicious", Category: core.CatSupplyChain, Severity: core.High, Verdict: core.Confirm,
		Path: m.ctx.Home + "/Projects/a/package-lock.json", Evidence: map[string]string{"package": "left-pad-evil", "count": "3"}}
	d := asMap(t, s.maliciousPackageItem(one, "security/p", m.report))["data"].(map[string]any)
	noSentences(t, "package", d)
	if d["type"] != "malicious-package" || d["package"] != "left-pad-evil" || d["count"] != float64(3) || d["more"] != false || d["reveal"] != true {
		t.Errorf("one package: %v", d)
	}
	rest := one
	rest.Path = ""
	rest.Evidence = map[string]string{"packages": "a, b", "count": "12"}
	d = asMap(t, s.maliciousPackageItem(rest, "security/q", m.report))["data"].(map[string]any)
	if d["more"] != true || d["count"] != float64(12) || d["reveal"] != false {
		t.Errorf("the rest: %v", d)
	}
}

// The round's item: the plan and the cache keys in its data are the ones 「清理 N 项缓存」 sends, the counts are the
// ones the card says; after the click the answer carries the round again, with the caches gone.
func TestRoundItemDataMatchesItsCard(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	item, comps, _ := outboxItem(t, s, "findings")
	if item == nil {
		t.Fatal("no round item")
	}
	d, _ := item["data"].(map[string]any)
	noSentences(t, "round", d)
	decide, _ := d["decide"].(map[string]any)
	if d["type"] != "round" || decide == nil {
		t.Fatalf("round data: %v", d)
	}
	plan, _ := decide["plan"].(map[string]any)
	var sent map[string]any
	for _, c := range comps {
		if a, ok := c["action"].(map[string]any); ok {
			if ev, _ := a["event"].(map[string]any); ev["name"] == "scan_apply" {
				sent, _ = ev["context"].(map[string]any)
			}
		}
	}
	if (plan == nil) != (sent == nil) {
		t.Fatalf("plan %v, button %v", plan, sent)
	}
	if plan != nil {
		keys, _ := plan["caches"].([]any)
		choices, _ := sent["choices"].(map[string]any)
		if plan["id"] != sent["plan_id"] || len(keys) != len(choices) || float64(len(keys)) != decide["caches"] {
			t.Errorf("plan %v, button %v, caches %v", plan, sent, decide["caches"])
		}
		for _, k := range keys {
			if _, ok := choices[k.(string)]; !ok {
				t.Errorf("key %v is not on the button", k)
			}
		}
	}
	// luoke-scan#205 (5b): cachesBytes is what the one button frees: the sizes, as the plan has them, of exactly the
	// items the button sends; no more than everything the plan clears as suggested.
	if plan != nil {
		saved, ok := LoadPlan(s.plansDir(), plan["id"].(string))
		if !ok {
			t.Fatalf("no plan %v", plan["id"])
		}
		onButton := map[string]bool{}
		for _, k := range plan["caches"].([]any) {
			onButton[k.(string)] = true
		}
		var want int64
		for _, it := range saved.Items {
			if onButton[it.Key] && it.Bytes != nil {
				want += *it.Bytes
			}
		}
		got, has := decide["cachesBytes"].(float64)
		if !has || int64(got) != want || want <= 0 || got > decide["bytes"].(float64) {
			t.Errorf("cachesBytes %v, the button's items are %d, everything suggested %v", decide["cachesBytes"], want, decide["bytes"])
		}
	}
	if rest, _ := decide["rest"].(float64); rest > 0 && !strings.Contains(item["summary"].(string), "另外 ") {
		t.Errorf("rest %v, summary %q", rest, item["summary"])
	}
	out, _ := clickRoundCaches(t, s, "openPage")
	answer, _ := asMap(t, out.Extra)["data"].(map[string]any)
	noSentences(t, "answer", answer)
	removed, _ := answer["removed"].(map[string]any)
	if answer["type"] != "applied" || removed["count"] != decide["caches"] {
		t.Fatalf("answer: %v", answer)
	}
	if round, _ := answer["round"].(map[string]any); round != nil {
		after, _ := round["decide"].(map[string]any)
		if after["caches"] != float64(0) || after["cleaned"] != decide["caches"] {
			t.Errorf("the round after the click: %v", after)
		}
	}
}

func TestAutoDoneDataNamesByKind(t *testing.T) {
	d := asMap(t, autoDoneData(AutoDone{Batch: "auto-1", Bytes: 100, Tools: []string{"pip"}, Partial: []string{"Xcode"},
		Moved: []Moved{{Kind: "temp", Items: 21, Bytes: 9, Names: []string{"临时文件夹 puppeteer_dev_chrome_profile-P00001"}},
			{Kind: "installer", Items: 1, Bytes: 5, Names: []string{"安装包 App-2.0.dmg"}}},
		Unrecorded: []string{"x.dmg"}}, true))
	moved := d["moved"].([]any)
	first := moved[0].(map[string]any)["names"].([]any)[0].(map[string]any)
	if first["name"] != "puppeteer_dev_chrome_profile-P00001" || first["tool"] != "Puppeteer" {
		t.Errorf("a known temp folder: %v", first)
	}
	if n := moved[1].(map[string]any)["names"].([]any)[0].(map[string]any); n["name"] != "App-2.0.dmg" || n["tool"] != "" {
		t.Errorf("an installer: %v", n)
	}
	if d["restorable"] != true || d["offerStop"] != true || len(d["tools"].([]any)) != 2 {
		t.Errorf("auto-done: %v", d)
	}
	for _, m := range moved {
		if han.MatchString(m.(map[string]any)["kind"].(string)) {
			t.Errorf("kind is a code: %v", m)
		}
	}
}
