package core

import (
	"os"
	"path/filepath"
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
