package core

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const cleanupCases = "../../evals/cleanup/cases.json"

func TestCleanupCasesCoverEveryKind(t *testing.T) {
	suite, err := LoadCleanupEval(cleanupCases)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range suite.Cases {
		if ids[c.ID] {
			t.Fatalf("用例的 id 重了：%s", c.ID)
		}
		ids[c.ID] = true
	}
	for _, k := range AutoKinds {
		n, auto, keep := 0, false, 0
		for _, c := range suite.Cases {
			if c.Kind == k {
				n++
				auto = auto || len(c.Auto) > 0
				if len(c.Keep) > 0 {
					keep++
				}
			}
		}
		if n < 8 || !auto || keep < 4 {
			t.Fatalf("%s：%d 个用例，有该清的 %v，不该清的 %d 个", k, n, auto, keep)
		}
	}
}

// The eval is only worth something if it fails a looser picker: no waiting, and kinds the user turned off still cleaned.
func TestCleanupEvalCatchesALooserPicker(t *testing.T) {
	suite, err := LoadCleanupEval(cleanupCases)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"dup-just-downloaded": true, "temp-not-quiet-long-enough": true, "installer-turned-off": true}
	var cases []CleanupCase
	for _, c := range suite.Cases {
		if want[c.ID] || c.ID == "dup-kept-in-documents" {
			cases = append(cases, c)
		}
	}
	suite.Cases = cases
	score, err := RunCleanupEval(suite, func(p *AutoPick) {
		p.DuplicateQuiet, p.TempQuiet, p.Off = 0, 0, map[AutoKind]bool{}
	})
	if err != nil {
		t.Fatal(err)
	}
	caught := map[string]bool{}
	for _, r := range score.Results {
		if len(r.Wrong) > 0 {
			caught[r.ID] = true
		}
		if len(r.Missed) > 0 {
			t.Fatalf("%s missed %v", r.ID, r.Missed)
		}
	}
	if !reflect.DeepEqual(caught, want) {
		t.Fatalf("caught %v", caught)
	}
}

// The cache rule does not report a cache whose place is a link; the picker does not take one either.
func TestPickNoCacheAtALink(t *testing.T) {
	home := Canonical(t.TempDir())
	elsewhere := filepath.Join(home, "Documents/work")
	os.MkdirAll(elsewhere, 0o755)
	os.MkdirAll(filepath.Join(home, "Library/Caches"), 0o755)
	pip := filepath.Join(home, "Library/Caches/pip")
	os.Symlink(elsewhere, pip)
	f := Finding{Rule: "cache.rebuildable.pip", Category: CatCache, Severity: Low, Verdict: Safe, Path: pip, Bytes: Size(60 << 20), Title: "pip"}
	if got := NewAutoPick(home, "", time.Now(), map[string]bool{}).Pick([]Finding{f}); len(got) != 0 {
		t.Fatalf("a link: %v", got)
	}
	os.Remove(pip)
	os.MkdirAll(pip, 0o755)
	if got := NewAutoPick(home, "", time.Now(), map[string]bool{}).Pick([]Finding{f}); len(got) != 1 || got[0].Path != pip {
		t.Fatalf("a folder: %v", got)
	}
}

// luoke-scan#51 item 6: a cache whose users are not written down was cleaned even while its tool ran.
func TestEveryCacheSaysWhoUsesIt(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range KnownCaches {
		if ids[c.ID] {
			t.Fatalf("缓存的 id 重了：%s", c.ID)
		}
		ids[c.ID] = true
		if len(CacheUsers[c.ID]) == 0 {
			t.Fatalf("%s 没写哪些程序在用它", c.ID)
		}
	}
	for id := range CacheUsers {
		if !ids[id] {
			t.Fatalf("写了用的程序、却没有这处缓存：%s", id)
		}
	}
	if !CacheIdle("pip", map[string]bool{"Finder": true}) || CacheIdle("pip", map[string]bool{"pip3": true}) || CacheIdle("no-such-cache", nil) {
		t.Fatal("idle: not in use, in use, not known")
	}
}

func TestPickNothingOfOtherRules(t *testing.T) {
	f := Finding{Rule: "stale.large-file", Category: CatSpace, Severity: Low, Verdict: Confirm, Path: "/tmp/x", Bytes: Size(1 << 30), Title: "x"}
	if got := NewAutoPick("/tmp", "", time.Now(), map[string]bool{}).Pick([]Finding{f}); len(got) != 0 {
		t.Fatal(got)
	}
}

// What the rules already leave out (too recent, links, clones) is checked again when picking: these findings are made
// up, since the rules would not report them.
func TestPickChecksAgainWhatTheRulesLeaveOut(t *testing.T) {
	home := Canonical(t.TempDir())
	for _, d := range []string{"Downloads", "Documents"} {
		os.MkdirAll(filepath.Join(home, d), 0o755)
	}
	dmg := filepath.Join(home, "Downloads/Firefox 131.0.dmg")
	os.WriteFile(dmg, make([]byte, 6<<20), 0o644)
	ev := map[string]string{"exact": "Firefox", "downloaded": "1", "signed": "1", "installer_version": "131.0", "app_version": "131.0", "days": "30"}
	installer := func(e map[string]string, path string) Finding {
		return Finding{Rule: "leftover.installer", Category: CatLeftover, Severity: Low, Verdict: Confirm, Path: path, Bytes: Size(6 << 20), Title: "x", Evidence: e}
	}
	with := func(k, v string) map[string]string {
		out := map[string]string{}
		for a, b := range ev {
			out[a] = b
		}
		out[k] = v
		return out
	}
	pick := NewAutoPick(home, "", time.Now(), map[string]bool{})
	if len(pick.Pick([]Finding{installer(ev, dmg)})) != 1 {
		t.Fatal("对照：都对得上的会挑")
	}
	if len(pick.Pick([]Finding{installer(with("days", "10"), dmg)})) != 0 {
		t.Fatal("没满 14 天")
	}
	link := filepath.Join(home, "Downloads/Firefox link.dmg")
	os.Symlink(dmg, link)
	if len(pick.Pick([]Finding{installer(ev, link)})) != 0 {
		t.Fatal("安装包是链接")
	}

	// Duplicates: the kept copy in Documents, a link and a clone of it in Downloads, all a month old.
	keep, real := filepath.Join(home, "Documents/a.bin"), filepath.Join(home, "Downloads/a.bin")
	data := []byte(strings.Repeat("\x07", 3<<20))
	os.WriteFile(keep, data, 0o644)
	os.WriteFile(real, data, 0o644)
	dlink, clone := filepath.Join(home, "Downloads/a-link.bin"), filepath.Join(home, "Downloads/a-clone.bin")
	os.Symlink(keep, dlink)
	if err := clonefile(keep, clone); err != nil {
		t.Fatal(err)
	}
	month := time.Now().Add(-30 * 24 * time.Hour)
	for _, p := range []string{keep, real, clone} {
		os.Chtimes(p, month, month)
	}
	p := NewAutoPick(home, "", time.Now(), map[string]bool{})
	p.Added = func(string) (time.Time, bool) { return month, true }
	dup := Finding{Rule: "space.duplicates", Category: CatSpace, Severity: Low, Verdict: Confirm, Path: keep, Bytes: Size(6 << 20), Title: "x",
		Evidence: map[string]string{"targets": strings.Join([]string{real, dlink, clone}, "\n")}}
	if got := paths(p.Pick([]Finding{dup})); !reflect.DeepEqual(got, []string{real}) {
		t.Fatalf("链接不挑，克隆腾不出空间也不挑：%v", got)
	}
	any := p
	any.MinFree = 0 // a link frees next to nothing anyway: without this the size check would hide the link check
	lutimes(dlink, month)
	inner := filepath.Join(home, "Downloads/a-inner-link.bin")
	os.Symlink(real, inner)
	lutimes(inner, month)
	linked := dup
	linked.Evidence = map[string]string{"targets": strings.Join([]string{inner, real, clone}, "\n")}
	if got := paths(any.Pick([]Finding{linked})); !reflect.DeepEqual(got, []string{real, clone}) {
		t.Fatalf("链接不挑：%v", got)
	}

	// One file in two findings (a big installer that also has a copy elsewhere) is taken once.
	twice := Finding{Rule: "space.duplicates", Category: CatSpace, Severity: Low, Verdict: Confirm, Path: keep, Bytes: Size(6 << 20), Title: "x",
		Evidence: map[string]string{"targets": dmg}}
	os.Chtimes(dmg, month, month)
	if got := paths(p.Pick([]Finding{installer(ev, dmg), twice})); !reflect.DeepEqual(got, []string{dmg}) {
		t.Fatalf("同一个文件挑两次：%v", got)
	}
}

func paths(items []AutoItem) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.Path)
	}
	return out
}
