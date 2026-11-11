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

// A startup item is called by the app its program is in, else by the program file's name: never by its label's last
// part (「agent」「socket」), nor by what its label or plist says it belongs to.
func TestStartupItemsAreNamedByTheirProgram(t *testing.T) {
	s := newPageCase(t).s
	jump := "/Applications/Jump Desktop Connect.app/Contents/MacOS/JumpConnect"
	for _, c := range []struct {
		label, program, want string
	}{
		{"com.p5sys.jump.connect.agent", jump, "Jump Desktop Connect"},
		{"com.p5sys.jump.connect.service", "/Applications/Jump Desktop Connect.app/Contents/Library/LaunchServices/x", "Jump Desktop Connect"},
		{"com.docker.socket", "/Library/PrivilegedHelperTools/com.docker.socket", "com.docker.socket"},
		{"com.google.keystone.agent", "~/Library/Application Support/.x/updater", "updater"},
		{"", "/Applications/Foo.app", "Foo"},
		{"", "/Applications/Foo.app/Contents/Library/LoginItems/Foo Helper.app/Contents/MacOS/Foo Helper", "Foo"},
		{"io.example.tidy", "/bin/sh", "tidy"}, // macOS's own program: only the label is left
		{"io.example.tidy", "", "tidy"},
	} {
		ev := map[string]string{"scope": "system-daemon", "label": c.label}
		if c.label == "" {
			ev = map[string]string{"scope": "login-item", "name": "x"}
		}
		if c.program != "" {
			ev["program"] = c.program
		}
		f := core.Finding{Rule: "persistence.new", Category: core.CatPersistence, Severity: core.Medium, Verdict: core.Confirm,
			Path: "/Library/LaunchDaemons/" + c.label + ".plist", Evidence: ev}
		if got := s.shortName(f); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.label, c.program, got, c.want)
		}
		if title, _ := s.plain(f); title != "会跟着电脑一起启动的「"+c.want+"」" {
			t.Errorf("title %q", title)
		}
	}
	// Two jobs of one app: one name in the group's line
	two := []core.Finding{}
	for _, l := range []string{"agent", "service"} {
		two = append(two, core.Finding{Rule: "persistence.new", Category: core.CatPersistence, Severity: core.Medium,
			Verdict: core.Confirm, Path: "/Library/LaunchAgents/com.p5sys.jump.connect." + l + ".plist",
			Evidence: map[string]string{"scope": "system-agent", "label": "com.p5sys.jump.connect." + l, "program": jump}})
	}
	if _, _, names := s.plainGroup(lookGroup{key: groupKey(two[0]), findings: two}); names != "「Jump Desktop Connect」" {
		t.Errorf("names %q", names)
	}
}

func TestPercentEncodedFileNamesAreShownDecoded(t *testing.T) {
	for in, want := range map[string]string{
		"/u/Downloads/%E9%A6%99%E6%B8%AF%E8%A1%8C.pdf": "香港行.pdf",
		"/u/Downloads/my%20notes.txt":                  "my notes.txt",
		"/u/Downloads/plain.txt":                       "plain.txt",
		"/u/Downloads/100%.txt":                        "100%.txt",   // not an encoding
		"/u/Downloads/a%2Fb.txt":                       "a%2Fb.txt",  // would read as a folder
		"/u/Downloads/x%00y":                           "x%00y",      // not printable
		"/u/Downloads/%FF%FE.bin":                      "%FF%FE.bin", // not text
	} {
		if got := fileName(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
	s := newPageCase(t).s
	f := core.Finding{Rule: "stale.large-file", Category: core.CatSpace, Severity: core.Low, Verdict: core.Confirm,
		Path: "/u/Downloads/%E9%A6%99%E6%B8%AF%E8%A1%8C.zip", Bytes: core.Size(2_000_000_000),
		Evidence: map[string]string{"last_opened": time.Now().AddDate(-1, 0, 0).Format("2006-01-02")}}
	if title, _ := s.planLines(f); !strings.HasPrefix(title, "香港行.zip") {
		t.Errorf("plan line %q", title)
	}
}

// One tool's caches (Cargo keeps two) are one line among what waits, not two lines that say the same.
func TestOneToolsCachesAreOneLine(t *testing.T) {
	s := newPageCase(t).s
	cache := func(id, tool string, b int64) core.Finding {
		return core.Finding{Rule: "cache.rebuildable." + id, Category: core.CatCache, Severity: core.Low, Verdict: core.Safe,
			Path: "/u/" + id, Bytes: core.Size(b), Title: tool + " 的缓存，删了会自动重建", Evidence: map[string]string{"tool": tool}}
	}
	groups := groupLook([]core.Finding{cache("cargo-registry-cache", "Cargo", 600_000_000), cache("pip", "pip", 1_000_000),
		cache("cargo-registry-src", "Cargo", 400_000_000)})
	if len(groups) != 2 || len(groups[0].findings) != 2 {
		t.Fatalf("groups %+v", groups)
	}
	title, advice, names := s.plainGroup(groups[0])
	if title != "Cargo 的缓存 2 项（"+core.FormatBytes(1_000_000_000)+"），删了会自动重建" || names != "" || advice == "" {
		t.Errorf("%q %q %q", title, advice, names)
	}
}

// The sidebar's line says what the round's card says, also with more caches than a card lists one by one.
func TestSidebarSaysWhatTheCardSays(t *testing.T) {
	m := newModelSetup(t)
	var fs []core.Finding
	for i := 0; i < 35; i++ {
		p := filepath.Join(m.ctx.Home, "Library/Caches", fmt.Sprintf("t%02d", i))
		os.MkdirAll(p, 0o755)
		if err := os.WriteFile(filepath.Join(p, "x"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		fs = append(fs, core.Finding{Rule: fmt.Sprintf("cache.rebuildable.t%02d", i), Category: core.CatCache, Severity: core.Low,
			Verdict: core.Safe, Path: p, Bytes: core.Size(int64(i+1) * 100_000_000), Title: fmt.Sprintf("T%02d 的缓存，删了会自动重建", i),
			Evidence: map[string]string{"tool": fmt.Sprintf("T%02d", i)}})
	}
	now := core.Time{Time: time.Now()}
	s := m.service(nil, nil)
	if err := s.Store.SaveReport(core.Report{StartedAt: now, FinishedAt: now, Findings: fs}); err != nil {
		t.Fatal(err)
	}
	r := s.Store.LastReport()
	title, _ := s.decisionsBody(NewCard("round"), *r, s.state(), s.visible(*r, s.state()), roundID(*r))
	if got := s.summary(s.state())["text"]; got != title {
		t.Errorf("sidebar %q, card %q", got, title)
	}
	if strings.Contains(title, "另外") { // all 35 are in the plan: none waits on the page (no cap of 30 any more)
		t.Errorf("card %q", title)
	}
}
