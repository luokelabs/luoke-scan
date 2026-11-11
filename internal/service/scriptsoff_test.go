package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

type scriptsSetup struct {
	t      *testing.T
	l      core.Layout
	s      *Service
	report core.Report
}

// newScriptsSetup: a fake home where npm 11 is used; npmrc "" means there is no ~/.npmrc.
func newScriptsSetup(t *testing.T, npmrc string) *scriptsSetup {
	root := t.TempDir()
	l := core.Layout{Root: root}
	home := l.Home()
	os.MkdirAll(filepath.Join(home, ".npm"), 0o755)
	os.MkdirAll(l.Projects(), 0o755)
	os.MkdirAll(filepath.Join(root, "usr-local/lib/node_modules/npm"), 0o755)
	os.WriteFile(filepath.Join(root, "usr-local/lib/node_modules/npm/package.json"), []byte(`{"version":"11.6.2"}`), 0o644)
	if npmrc != "" {
		os.WriteFile(filepath.Join(home, ".npmrc"), []byte(npmrc), 0o600)
	}
	store, err := core.OpenStore(l.Data())
	if err != nil {
		t.Fatal(err)
	}
	cfg := FixtureConfig(l, &core.Fakes{})
	m := &scriptsSetup{t: t, l: l, s: New(store, cfg)}
	m.scan()
	return m
}

func (m *scriptsSetup) scan() {
	ctx := m.l.Context(nil)
	f, err := core.NewInstallScriptsRule(&m.l, nil).Run(&ctx)
	if err != nil {
		m.t.Fatal(err)
	}
	now := core.Time{Time: time.Now()}
	m.report = core.Report{StartedAt: now, FinishedAt: now, Findings: f}
}

func (m *scriptsSetup) npmrc() string { return filepath.Join(m.l.Home(), ".npmrc") }

func (m *scriptsSetup) plan() *Plan {
	return m.s.plan(m.report.Findings, m.report, "findings", "", false)
}

func (m *scriptsSetup) apply(p *Plan) ToolOutput {
	out, err := m.s.apply(O{"plan_id": p.ID, "choices": map[string]any{"i0": []any{ChoiceScriptsOff}}}, O{})
	if err != nil {
		m.t.Fatal(err)
	}
	return out
}

func read(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func trashed(l core.Layout) []string {
	var out []string
	for _, p := range core.Children(filepath.Join(l.Root, "Trash")) {
		out = append(out, p)
	}
	return out
}

func TestScriptsOffAppendsAndPutsBack(t *testing.T) {
	old := "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}"
	m := newScriptsSetup(t, old)
	p := m.plan()
	if p == nil || len(p.Items) != 1 {
		t.Fatalf("plan %+v", p)
	}
	it := p.Items[0]
	if it.Suggested != ChoiceKeep || !contains(it.Options, ChoiceScriptsOff) || it.Tool != "npm" || it.Targets[0].Path != m.npmrc() {
		t.Fatalf("item %+v", it)
	}
	// The card offers 关闭自动运行 in plain words; the setting it writes stays in the report (no config lines on cards).
	c := NewCard("x")
	m.s.planBody(c, *p, "t", "", m.report.Findings)
	if b, _ := json.Marshal(c.Messages()); !strings.Contains(string(b), "关闭自动运行") || strings.Contains(string(b), "ignore-scripts=true") {
		t.Errorf("card %s", b)
	}
	for _, f := range m.report.Findings {
		if _, say := m.s.plain(f); f.Rule == core.InstallScriptsRuleID && !strings.Contains(say, "装不上") {
			t.Errorf("what turning them off costs: %q", say)
		}
	}
	before, _ := os.Stat(m.npmrc())
	out := m.apply(p)
	if !strings.Contains(out.Text, "改了 1 个包管理器的设置") {
		t.Errorf("answer %q", out.Text)
	}
	if got := read(t, m.npmrc()); got != old+"\nignore-scripts=true\n" {
		t.Errorf("new npmrc %q", got)
	}
	after, _ := os.Stat(m.npmrc())
	if after.Mode().Perm() != 0o600 || os.SameFile(before, after) {
		t.Errorf("mode %v, same file %v", after.Mode().Perm(), os.SameFile(before, after))
	}
	tr := trashed(m.l)
	if len(tr) != 1 || read(t, tr[0]) != old {
		t.Fatalf("trash %v", tr)
	}
	// The project's own config is never touched; the scan agrees it is done.
	m.scan()
	if len(m.report.Findings) != 0 {
		t.Errorf("still reported: %+v", m.report.Findings)
	}
	back := m.s.PutBackIDs([]string{p.ID})
	if len(back) != 1 || back[0].To != m.npmrc() || back[0].Note != "" {
		t.Fatalf("put back %+v", back)
	}
	if got := read(t, m.npmrc()); got != old {
		t.Errorf("after putting back %q", got)
	}
	// The one written went to the Trash too, nothing lost.
	var edited int
	for _, p := range trashed(m.l) {
		if strings.HasSuffix(read(t, p), "ignore-scripts=true\n") {
			edited++
		}
	}
	if edited != 1 {
		t.Errorf("written one not in the Trash: %v", trashed(m.l))
	}
	if again := m.s.PutBackIDs([]string{p.ID}); again[0].Note != AlreadyBack {
		t.Errorf("twice %+v", again)
	}
}

// Changed after 改成不跑: putting back keeps the user's file and puts the old one beside it.
func TestScriptsOffPutBackKeepsLaterChanges(t *testing.T) {
	m := newScriptsSetup(t, "registry=x\n")
	p := m.plan()
	m.apply(p)
	os.WriteFile(m.npmrc(), []byte("registry=x\nignore-scripts=true\nsave-exact=true\n"), 0o600)
	back := m.s.PutBackIDs([]string{p.ID})
	if len(back) != 1 || back[0].To == m.npmrc() || !strings.Contains(back[0].Note, "又动过") {
		t.Fatalf("put back %+v", back)
	}
	if !strings.Contains(read(t, m.npmrc()), "save-exact") || read(t, back[0].To) != "registry=x\n" {
		t.Error("the user's change or the old file was lost")
	}
}

// No ~/.npmrc before: one is written; putting back takes it away again (to the Trash).
func TestScriptsOffNewFile(t *testing.T) {
	m := newScriptsSetup(t, "")
	p := m.plan()
	if p == nil || p.Items[0].Targets[0].Inode != 0 {
		t.Fatalf("plan %+v", p)
	}
	m.apply(p)
	if got := read(t, m.npmrc()); got != "ignore-scripts=true\n" {
		t.Errorf("new file %q", got)
	}
	if st, _ := os.Stat(m.npmrc()); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	back := m.s.PutBackIDs([]string{p.ID})
	if len(back) != 1 || back[0].To == "" || core.Exists(m.npmrc()) {
		t.Errorf("put back %+v, still there %v", back, core.Exists(m.npmrc()))
	}
}

// Between the plan and the click: replaced by another file, made a link, written where there was none: not touched.
func TestScriptsOffRefusesWhatChanged(t *testing.T) {
	m := newScriptsSetup(t, "registry=x\n")
	p := m.plan()
	os.Remove(m.npmrc())
	os.WriteFile(m.npmrc(), []byte("registry=y\n"), 0o600)
	out := m.apply(p)
	if !strings.Contains(out.Text, "1 项未能更改") || strings.Contains(out.Text, "未能清理") || read(t, m.npmrc()) != "registry=y\n" || len(trashed(m.l)) != 0 {
		t.Errorf("replaced file changed: %q", out.Text)
	}

	m = newScriptsSetup(t, "registry=x\n")
	p = m.plan()
	elsewhere := filepath.Join(m.l.Root, "elsewhere-npmrc")
	os.WriteFile(elsewhere, []byte("registry=x\n"), 0o600)
	os.Remove(m.npmrc())
	os.Symlink(elsewhere, m.npmrc())
	m.apply(p)
	if read(t, elsewhere) != "registry=x\n" {
		t.Error("followed a link")
	}

	m = newScriptsSetup(t, "")
	p = m.plan()
	os.WriteFile(m.npmrc(), []byte("registry=z\n"), 0o600)
	m.apply(p)
	if read(t, m.npmrc()) != "registry=z\n" {
		t.Error("overwrote a file made after the plan")
	}

	// A folder on the way that became a link: not followed.
	m = newScriptsSetup(t, "")
	m.s.Config.Context.Home = m.l.Home()
	os.MkdirAll(filepath.Join(m.l.Home(), "Library/Caches/pip/wheels"), 0o755)
	os.WriteFile(filepath.Join(m.l.Home(), "Library/Caches/pip/wheels/x-1.0-py3-none-any.whl"), nil, 0o644)
	m.scan()
	var pip core.Finding
	for _, f := range m.report.Findings {
		if f.Key == "pip" {
			pip = f
		}
	}
	p = m.s.plan([]core.Finding{pip}, m.report, "findings", "", false)
	if p == nil {
		t.Fatalf("no pip plan: %+v", pip)
	}
	target := filepath.Join(m.l.Root, "target")
	os.MkdirAll(target, 0o755)
	os.Symlink(target, filepath.Join(m.l.Home(), ".config"))
	m.apply(p)
	if core.Exists(filepath.Join(target, "pip/pip.conf")) {
		t.Error("wrote through a linked folder")
	}
}

// A linked config is never offered: no plan item.
func TestScriptsOffNotForALink(t *testing.T) {
	m := newScriptsSetup(t, "")
	real := filepath.Join(m.l.Root, "dotfiles-npmrc")
	os.WriteFile(real, []byte("registry=x\n"), 0o600)
	os.Symlink(real, m.npmrc())
	m.scan()
	if p := m.plan(); p != nil {
		t.Errorf("plan for a linked config: %+v", p)
	}
}

// A record naming another file is not acted on by putting back.
func TestScriptsOffPutBackOnlyTheConfigs(t *testing.T) {
	m := newScriptsSetup(t, "")
	victim := filepath.Join(m.l.Home(), "notes.txt")
	os.WriteFile(victim, []byte("mine"), 0o600)
	var st = mustStat(t, victim)
	e := Cleaned{ID: "c-forged", Batch: "p-000000000000", Rule: core.InstallScriptsRuleID, Title: "x", Original: victim, Wrote: &st}
	if to, why := m.s.putBackOne(e, ""); to != "" || why == "" || !core.Exists(victim) {
		t.Errorf("forged record acted on: %q %q", to, why)
	}
}

func mustStat(t *testing.T, p string) Wrote {
	var w Wrote
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	w.Size = fi.Size()
	return w
}

// Review fixes (#111): putting back never leaves the user without a config, a whole config is at its name at every
// moment, and what is changed meanwhile is not lost.

func applied(t *testing.T) (*scriptsSetup, *Plan) {
	m := newScriptsSetup(t, "registry=x\n")
	p := m.plan()
	m.apply(p)
	if read(t, m.npmrc()) != "registry=x\nignore-scripts=true\n" {
		t.Fatal("not applied")
	}
	return m, p
}

// The Trash emptied (or the old one taken out of it): the written config stays, and that is said.
func TestScriptsOffPutBackTrashEmptiedKeepsConfig(t *testing.T) {
	m, p := applied(t)
	for _, f := range trashed(m.l) {
		os.Remove(f)
	}
	back := m.s.PutBackIDs([]string{p.ID})
	if len(back) != 1 || back[0].To != "" || !strings.Contains(back[0].Note, "留着没动") {
		t.Errorf("put back %+v", back)
	}
	if read(t, m.npmrc()) != "registry=x\nignore-scripts=true\n" {
		t.Error("the config went with nothing to replace it")
	}
}

// The old one in the Trash lost this tool's mark (put there by someone else): not taken; the written config stays.
func TestScriptsOffPutBackUnmarkedKeepsConfig(t *testing.T) {
	m, p := applied(t)
	tr := trashed(m.l)
	data, _ := os.ReadFile(tr[0])
	os.Remove(tr[0])
	os.WriteFile(tr[0], data, 0o600) // same name and contents, another file without the mark
	back := m.s.PutBackIDs([]string{p.ID})
	if back[0].To != "" || read(t, m.npmrc()) != "registry=x\nignore-scripts=true\n" {
		t.Errorf("put back %+v", back)
	}
}

// Known to have been there, but where it went in the Trash is not known: nothing is touched.
func TestScriptsOffPutBackUnknownTrashPlace(t *testing.T) {
	m, _ := applied(t)
	entries := m.s.Cleaned()
	e := entries[len(entries)-1]
	if e.Inode == 0 || e.Trashed == nil {
		t.Fatalf("entry %+v", e)
	}
	e.Trashed = nil
	if to, why := m.s.putBackOne(e, ""); to != "" || why == "" || read(t, m.npmrc()) != "registry=x\nignore-scripts=true\n" {
		t.Errorf("reported %q %q", to, why)
	}
}

// Whenever the old config goes to the Trash, the whole new one is already at its name, and no file is left over.
func TestScriptsOffConfigAlwaysThere(t *testing.T) {
	m := newScriptsSetup(t, "registry=x\n")
	p := m.plan()
	trash := m.s.Config.Trash
	seen := ""
	m.s.Config.Trash = func(path string) (string, error) {
		b, _ := os.ReadFile(m.npmrc())
		seen = string(b)
		return trash(path)
	}
	m.apply(p)
	if seen != "registry=x\nignore-scripts=true\n" {
		t.Errorf("at the move to the Trash the config was %q", seen)
	}
	for _, c := range core.Children(m.l.Home()) {
		if b := filepath.Base(c); strings.Contains(b, "luoke-scan") {
			t.Errorf("left over: %s", b)
		}
	}
	if tr := trashed(m.l); len(tr) != 1 || filepath.Base(tr[0])[9:] != ".npmrc" {
		t.Errorf("trash %v", tr)
	}
}

// Written in place while being changed (npm config set does that): the user's change stays, nothing of ours.
func TestScriptsOffConcurrentEditNotLost(t *testing.T) {
	m := newScriptsSetup(t, "registry=x\n")
	p := m.plan()
	beforeSwap = func() {
		f, _ := os.OpenFile(m.npmrc(), os.O_WRONLY|os.O_APPEND, 0)
		f.WriteString("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
		f.Close()
	}
	defer func() { beforeSwap = func() {} }()
	out := m.apply(p)
	if !strings.Contains(out.Text, "未能更改") {
		t.Errorf("answer %q", out.Text)
	}
	if got := read(t, m.npmrc()); got != "registry=x\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n" {
		t.Errorf("config now %q", got)
	}
	if len(trashed(m.l)) != 0 {
		t.Error("something went to the Trash")
	}
	for _, c := range core.Children(m.l.Home()) {
		if strings.Contains(filepath.Base(c), "luoke-scan") {
			t.Errorf("left over: %s", c)
		}
	}
}

// A config with a second name (a hard link): not offered; one linked after the plan: not changed.
func TestScriptsOffNotForAHardLink(t *testing.T) {
	m := newScriptsSetup(t, "registry=x\n")
	os.Link(m.npmrc(), filepath.Join(m.l.Root, "npmrc-twin"))
	m.scan()
	if p := m.plan(); p != nil {
		t.Errorf("plan for a hard-linked config: %+v", p)
	}
	if f := m.report.Findings[0]; f.Evidence["append"] != "" || !strings.Contains(f.Evidence["how"], "共用一个文件") {
		t.Errorf("evidence %+v", f.Evidence)
	}
	m = newScriptsSetup(t, "registry=x\n")
	p := m.plan()
	os.Link(m.npmrc(), filepath.Join(m.l.Root, "npmrc-twin"))
	m.apply(p)
	if read(t, filepath.Join(m.l.Root, "npmrc-twin")) != "registry=x\n" || read(t, m.npmrc()) != "registry=x\n" {
		t.Error("changed a hard-linked config")
	}
}

// A folder on the way that is a link: no button; a folder gone since the plan: refused, and not made again.
func TestScriptsOffFoldersOnTheWay(t *testing.T) {
	m := newScriptsSetup(t, "")
	os.MkdirAll(filepath.Join(m.l.Home(), "Library/Caches/pip/wheels"), 0o755)
	os.WriteFile(filepath.Join(m.l.Home(), "Library/Caches/pip/wheels/x-1.0-py3-none-any.whl"), nil, 0o644)
	target := filepath.Join(m.l.Root, "dotconfig")
	os.MkdirAll(target, 0o755)
	os.Symlink(target, filepath.Join(m.l.Home(), ".config"))
	m.scan()
	for _, f := range m.report.Findings {
		if f.Key == "pip" && f.Evidence["append"] != "" {
			t.Errorf("button offered through a linked folder: %+v", f.Evidence)
		}
		if p := m.s.plan([]core.Finding{f}, m.report, "findings", "", false); f.Key == "pip" && p != nil {
			t.Errorf("plan through a linked folder: %+v", p)
		}
	}

	m = newScriptsSetup(t, "")
	os.MkdirAll(filepath.Join(m.l.Home(), "Library/Caches/pip/wheels"), 0o755)
	os.WriteFile(filepath.Join(m.l.Home(), "Library/Caches/pip/wheels/x-1.0-py3-none-any.whl"), nil, 0o644)
	os.MkdirAll(filepath.Join(m.l.Home(), ".config/pip"), 0o755)
	os.WriteFile(filepath.Join(m.l.Home(), ".config/pip/pip.conf"), []byte("[global]\ntimeout = 5\n"), 0o600)
	m.scan()
	var pip core.Finding
	for _, f := range m.report.Findings {
		if f.Key == "pip" {
			pip = f
		}
	}
	p := m.s.plan([]core.Finding{pip}, m.report, "findings", "", false)
	if p == nil {
		t.Fatalf("no plan: %+v", pip)
	}
	os.RemoveAll(filepath.Join(m.l.Home(), ".config"))
	m.apply(p)
	if core.Exists(filepath.Join(m.l.Home(), ".config")) {
		t.Error("made the folders again for a change it refused")
	}
}

// The old config cannot go to the Trash: swapped back, reported not changed, nothing written down and nothing left
// over beside it (in a folder of its own or under a temporary name).
func TestScriptsOffTrashFailsSwapsBack(t *testing.T) {
	for _, c := range []struct {
		name  string
		trash func(string) (string, error)
	}{
		{"error", func(string) (string, error) { return "", os.ErrPermission }},
		{"not moved", func(string) (string, error) { return "", nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			old := "registry=x\n"
			m := newScriptsSetup(t, old)
			p := m.plan()
			before, _ := os.Stat(m.npmrc())
			m.s.Config.Trash = c.trash
			out := m.apply(p)
			if !strings.Contains(out.Text, "未能更改") || strings.Contains(out.Text, "改了") {
				t.Errorf("answer %q", out.Text)
			}
			if ok, why := m.s.scriptsOff(p.Items[0], *p); ok || !strings.Contains(why, "换回了原来那份，没改") {
				t.Errorf("again: %v %q", ok, why)
			}
			after, err := os.Stat(m.npmrc())
			if err != nil || !os.SameFile(before, after) || read(t, m.npmrc()) != old {
				t.Errorf("the original is not back at its name: %v", err)
			}
			for _, x := range core.Children(m.l.Home()) {
				if strings.Contains(filepath.Base(x), "luoke-scan") {
					t.Errorf("left over: %s", filepath.Base(x))
				}
			}
			if len(trashed(m.l)) != 0 || len(m.s.Cleaned()) != 0 {
				t.Errorf("trash %v, record %+v", trashed(m.l), m.s.Cleaned())
			}
		})
	}
}

// A config made where there was none: the record page offers 「放回」, which takes it away; then it says so.
func TestScriptsOffNewFileRecordPage(t *testing.T) {
	m := newScriptsSetup(t, "")
	p := m.plan()
	m.apply(p)
	page := func() string {
		c := NewCard("x")
		m.s.cleanedPage(c)
		b, _ := json.Marshal(c.Messages())
		return string(b)
	}
	if got := page(); !strings.Contains(got, "scan_restore") || !strings.Contains(got, p.ID) {
		t.Fatalf("no 放回 for the new config: %s", got)
	}
	back := m.s.PutBackIDs([]string{p.ID})
	if len(back) != 1 || back[0].To == "" || core.Exists(m.npmrc()) {
		t.Fatalf("put back %+v, still there %v", back, core.Exists(m.npmrc()))
	}
	if got := page(); strings.Contains(got, "scan_restore") || !strings.Contains(got, "已放回") {
		t.Errorf("after putting back: %s", got)
	}

	// Changed by the user since: not ours to take away, no button.
	m = newScriptsSetup(t, "")
	p = m.plan()
	m.apply(p)
	os.WriteFile(m.npmrc(), []byte("ignore-scripts=true\nsave-exact=true\n"), 0o600)
	if got := page(); strings.Contains(got, "scan_restore") {
		t.Errorf("button for a config the user changed: %s", got)
	}
}
