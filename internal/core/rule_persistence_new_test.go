package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func agentPlist(t *testing.T, dir, label, program string) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	body := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>` + label + `</string>
<key>ProgramArguments</key><array><string>` + program + `</string></array></dict></plist>`
	if err := os.WriteFile(filepath.Join(dir, label+".plist"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newFindings(f []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, x := range f {
		if x.Rule == "persistence.new" {
			out[x.Evidence["name"]] = x
		}
	}
	return out
}

// Rounds on a real clock (with nanoseconds): what the first round saw is never "new", however the baseline's float
// seconds round; a later unsigned job is worth a look, one run from Downloads is urgent.
func TestPersistenceBaselineOnARealClock(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	agents := filepath.Join(home, "Library/LaunchAgents")
	for _, p := range []string{"bin/old", "bin/fresh", "Downloads/odd"} {
		os.MkdirAll(filepath.Dir(filepath.Join(home, p)), 0o755)
		os.WriteFile(filepath.Join(home, p), []byte("#!/bin/sh\n"), 0o755)
	}
	agentPlist(t, agents, "io.example.old", filepath.Join(home, "bin/old"))
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	r := &PersistenceRule{
		PlistDirs:       func(string) []ScopedDir { return []ScopedDir{{agents, ScopeUserAgent}} },
		SessionLabels:   func(uint32) (map[string]string, bool) { return map[string]string{}, true },
		DescribeJob:     func(uint32, string) (SessionJob, bool) { return SessionJob{}, false },
		JobDetailsFor:   time.Hour,
		Crontab:         func() (string, bool) { return "", true },
		Signature:       func(string) Signature { return Signature{Kind: SigAdhoc} },
		FindApp:         func(string) string { return "" },
		CanReplace:      func(string) bool { return false },
		NewFor:          7 * 24 * time.Hour,
		SystemPathFiles: func() []string { return nil },
	}
	round := func(at time.Time) map[string]Finding {
		ctx := NewContext(home)
		ctx.Store, ctx.Now = store, at
		f, err := r.Run(&ctx)
		if err != nil {
			t.Fatal(err)
		}
		return newFindings(f)
	}
	// Many baselines, so that some round down: each in a store of its own.
	for i := 0; i < 40; i++ {
		s, _ := OpenStore(filepath.Join(root, "data-"+string(rune('a'+i%26))+string(rune('a'+i/26))))
		store = s
		t0 := time.Date(2026, 11, 5, 13, 41, 9, 123456789+i*7919, time.UTC)
		if n := round(t0); len(n) != 0 {
			t.Fatalf("baseline round reported %v", n)
		}
		if n := round(t0.Add(14 * time.Minute)); len(n) != 0 {
			t.Fatalf("baseline %v: the next round reported what the first saw: %v", t0, n)
		}
	}
	t1 := time.Date(2026, 11, 5, 14, 30, 0, 987654321, time.UTC)
	agentPlist(t, agents, "io.example.fresh", filepath.Join(home, "bin/fresh"))
	agentPlist(t, agents, "io.example.odd", filepath.Join(home, "Downloads/odd"))
	n := round(t1)
	if len(n) != 2 {
		t.Fatalf("new jobs: %v", n)
	}
	if f := n["io.example.fresh"]; f.Severity != Medium || f.Title != "新加了一个开机自动运行的任务：io.example.fresh" {
		t.Errorf("unsigned job: %+v", f)
	}
	if f := n["io.example.odd"]; f.Severity != High {
		t.Errorf("job run from Downloads: %+v", f)
	}
}

// Jobs a running app submitted: named for the app, said to be gone after a restart. Sparkle's updater, copied into the
// app's cache folder to run an update, is where it always is: submitted by the app and signed by the same developer as
// the installed app, it is not news. Anything else in that place is as odd as in any cache folder: no signature, a
// developer other than the app's, no such app installed, or a plist that starts it with the Mac.
func TestSubmittedJobsAndSparkle(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	agents := filepath.Join(home, "Library/LaunchAgents")
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	sparkle := func(id, dir string) string {
		return filepath.Join(home, "Library/Caches", id, "org.sparkle-project.Sparkle/Launcher", dir, "Updater.app/Contents/MacOS/Updater")
	}
	chatApp := filepath.Join(home, "Applications/Chat.app")
	otherApp := filepath.Join(home, "Applications/Other.app")
	signed := sparkle("io.example.chat", "pNLz8")
	unsigned := sparkle("io.example.chat", "aa1")
	foreign := sparkle("io.example.other", "bb2") // Other.app is another developer's
	orphan := sparkle("io.example.gone", "cc3")   // no such app installed
	byPlist := sparkle("io.example.chat", "dd4")  // started by a LaunchAgent, not submitted
	cached := filepath.Join(home, "Library/Caches/io.example.chat/helper")
	jobs := map[string]SessionJob{}
	r := &PersistenceRule{
		PlistDirs: func(string) []ScopedDir { return []ScopedDir{{agents, ScopeUserAgent}} },
		SessionLabels: func(uint32) (map[string]string, bool) {
			m := map[string]string{}
			for l := range jobs {
				m[l] = "1"
			}
			return m, true
		},
		DescribeJob:   func(_ uint32, l string) (SessionJob, bool) { j, ok := jobs[l]; return j, ok },
		JobDetailsFor: time.Hour,
		Crontab:       func() (string, bool) { return "", true },
		Signature: func(p string) Signature {
			switch p {
			case unsigned:
				return Signature{Kind: SigAdhoc}
			case otherApp:
				return Signature{Kind: SigDeveloper, Team: "OTHER00000"}
			}
			return Signature{Kind: SigDeveloper, Team: "TEAM123456"}
		},
		FindApp: func(id string) string {
			return map[string]string{"io.example.chat": chatApp, "io.example.other": otherApp}[id]
		},
		CanReplace:      func(string) bool { return false },
		NewFor:          7 * 24 * time.Hour,
		SystemPathFiles: func() []string { return nil },
	}
	round := func(at time.Time) map[string]Finding {
		ctx := NewContext(home)
		ctx.Store, ctx.Now = store, at
		f, err := r.Run(&ctx)
		if err != nil {
			t.Fatal(err)
		}
		return newFindings(f)
	}
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	os.MkdirAll(agents, 0o755)
	if n := round(t0); len(n) != 0 {
		t.Fatalf("baseline: %v", n)
	}
	submit := func(label, by, program string) {
		jobs[label] = SessionJob{Label: label, Path: "(submitted by " + by + "[10])", SubmittedBy: by, Program: program}
	}
	submit("io.example.chat-sparkle-progress", "Chat", signed)
	submit("io.example.chat-unsigned", "Chat", unsigned)
	submit("io.example.other-sparkle-progress", "Other", foreign)
	submit("io.example.gone-sparkle-progress", "Gone", orphan)
	submit("io.example.chat.helper", "Chat", cached)
	agentPlist(t, agents, "io.example.chat-updater", byPlist)
	n := round(t0.Add(time.Hour))
	if f, ok := n["io.example.chat-sparkle-progress"]; ok {
		t.Errorf("the app's own signed Sparkle updater reported: %+v", f)
	}
	for _, name := range []string{"io.example.chat-unsigned", "io.example.other-sparkle-progress", "io.example.gone-sparkle-progress", "io.example.chat-updater"} {
		if f, ok := n[name]; !ok || f.Severity != High {
			t.Errorf("%s: want an urgent finding (cache folder), got %+v", name, f)
		}
	}
	if f := n["io.example.chat-updater"]; f.Evidence["submitted"] != "" || !strings.HasPrefix(f.Title, "新加了一个开机自动运行的任务") {
		t.Errorf("a LaunchAgent is not a submitted job: %+v", f)
	}
	f, ok := n["io.example.chat.helper"]
	if !ok || f.Severity != High || f.Evidence["app"] != "Chat" || f.Evidence["submitted"] != "1" ||
		f.Title != "新加了一个交给系统运行的后台程序：io.example.chat.helper" || !strings.Contains(f.Evidence["how"], "重启后不会再自己起来") {
		t.Errorf("submitted job in a cache folder: %+v", f)
	}
}
