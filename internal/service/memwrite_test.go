package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMemoryRecordLine(t *testing.T) {
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.Local)
	r := MemoryRecord{Topic: "scan-auto-cleaned", Speaker: "system", Kind: "activity", Text: "螺壳扫描按规则自动清了 pip 的缓存，\"3 B\"", Ref: "auto-1",
		HappenedAt: at, Data: map[string]any{"by": "rule", "bytes": int64(3), "caches": []any{map[string]any{"tool": "pip", "bytes": int64(3)}},
			"partial": []string{}, "on": true, "ratio": 0.5}}
	want := `{"data":{"by":"rule","bytes":3,"caches":[{"bytes":3,"tool":"pip"}],"on":true,"partial":[],"ratio":0.5},"happened_at":"2026-11-05 10:00:00",` +
		`"kind":"activity","ref":"auto-1","speaker":"system","text":"螺壳扫描按规则自动清了 pip 的缓存，\"3 B\"","topic":"scan-auto-cleaned"}` + "\n"
	if got := string(r.Line()); got != want {
		t.Errorf("line\n%s\nwant\n%s", got, want)
	}
	r.Ref, r.Data = "", nil
	if got := string(r.Line()); strings.Contains(got, `"ref"`) || !strings.Contains(got, `"data":{}`) {
		t.Errorf("without ref: %s", got)
	}
}

// fakeLuokeCore is a luoke-core app in a temp folder whose Python is a script that writes down how it was run and
// answers {"id": N} for each line (never the real one).
func fakeLuokeCore(t *testing.T, bundleID string) (app, python string) {
	app = filepath.Join(t.TempDir(), "luoke-core.app")
	python = filepath.Join(app, "Contents/Resources/python/bin/python3.12")
	os.MkdirAll(filepath.Dir(python), 0o755)
	os.WriteFile(filepath.Join(app, "Contents/Info.plist"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>`+bundleID+`</string></dict></plist>
`), 0o644)
	script := `#!/bin/sh
pwd > "$LUOKE_HOME/cwd"
env > "$LUOKE_HOME/env"
printf '%s\n' "$@" > "$LUOKE_HOME/args"
n=0
while IFS= read -r line; do
  n=$((n+1))
  printf '%s\n' "$line" >> "$LUOKE_HOME/lines"
  echo "{\"id\": $n}"
done
echo 'not json'
echo '{"error": "x"}'
`
	os.WriteFile(python, []byte(script), 0o755)
	return app, python
}

func TestMemoryInterpreterOnlyLuokeCoresOwn(t *testing.T) {
	yes := func(string) bool { return true }
	app, python := fakeLuokeCore(t, "ai.luoke.core")
	real, _ := realPath(python)
	if p, ok := memInterpreter(map[string]any{"luoke_mem": map[string]any{"python": python}}, yes); !ok || p != real {
		t.Errorf("python: %q %v", p, ok)
	}
	sitePackages := filepath.Join(app, "Contents/Resources/python/lib/python3.12/site-packages")
	os.MkdirAll(sitePackages, 0o755)
	os.Symlink("python3.12", filepath.Join(app, "Contents/Resources/python/bin/python3"))
	if p, ok := memInterpreter(map[string]any{"luoke_mem": map[string]any{"path": sitePackages}}, yes); !ok || p != real {
		t.Errorf("from its path: %q %v", p, ok)
	}
	if _, ok := memInterpreter(map[string]any{"luoke_mem": map[string]any{"python": python}}, func(string) bool { return false }); ok {
		t.Error("not signed by luoke")
	}
	if _, ok := memInterpreter(map[string]any{"tasks": map[string]any{}}, yes); ok {
		t.Error("no luoke_mem")
	}
	_, other := fakeLuokeCore(t, "com.example.other")
	if _, ok := memInterpreter(map[string]any{"luoke_mem": map[string]any{"python": other}}, yes); ok {
		t.Error("another app's Python")
	}
	if _, ok := memInterpreter(map[string]any{"luoke_mem": map[string]any{"python": "/bin/sh"}}, yes); ok {
		t.Error("a program outside luoke-core")
	}
	// A development build has no release Team: nothing is trusted.
	if SignedByLuoke("/bin/ls") || SignedByLuoke(python) {
		t.Error("trusted without a Team")
	}
}

func TestMemoryRecordsWrittenThroughLuokeCoresPython(t *testing.T) {
	_, python := fakeLuokeCore(t, "ai.luoke.core")
	f := newFakeCore(t, map[string]string{}, answers)
	f.extra = map[string]any{"luoke_mem": map[string]any{"python": python}}
	saved := memTrusted
	memTrusted = func(string) bool { return true }
	defer func() { memTrusted = saved }()
	out := t.TempDir()
	t.Setenv("LUOKE_SCAN_TEST_LEAK", "x")
	env := map[string]string{"LUOKE_HUB_SOCKET": f.socket, "LUOKE_HOME": out, "HOME": "/tmp/la-home", "LUOKE_SCAN_TEST_LEAK": "x"}
	records := []MemoryRecord{
		{Topic: "scan-autoclean", Speaker: "user", Kind: "statement", Text: "在螺壳扫描里打开了不用点就清", HappenedAt: time.Now(), Data: map[string]any{"on": true}},
		{Topic: "scan-ignored", Speaker: "user", Kind: "statement", Text: "在螺壳扫描里说这一样缓存以后别提", Ref: "p1", HappenedAt: time.Now(),
			Data: map[string]any{"category": "cache", "rule": "cache.rebuildable.pip", "items": 1}},
	}
	if n := rememberRecords(records, "0.1.0", env); n != 2 {
		t.Fatalf("remembered %d", n)
	}
	read := func(name string) string { b, _ := os.ReadFile(filepath.Join(out, name)); return string(b) }
	if read("lines") != string(records[0].Line())+string(records[1].Line()) {
		t.Errorf("lines %q", read("lines"))
	}
	if read("args") != "-I\n-B\n-m\nluoke_mem\nrecord\n--tool\nluoke-scan\n" || strings.TrimSpace(read("cwd")) != "/" {
		t.Errorf("args %q, cwd %q", read("args"), read("cwd"))
	}
	e := read("env")
	for _, want := range []string{"HOME=/tmp/la-home\n", "PATH=/usr/bin:/bin\n", "PYTHONDONTWRITEBYTECODE=1\n", "LANG=en_US.UTF-8\n", "LUOKE_HOME=" + out + "\n"} {
		if !strings.Contains(e, want) {
			t.Errorf("env lacks %q:\n%s", want, e)
		}
	}
	if strings.Contains(e, "LUOKE_SCAN_TEST_LEAK") || strings.Contains(e, "LUOKE_HUB_SOCKET") {
		t.Errorf("env leaks this process's:\n%s", e)
	}
	// Who asks, as V1 says.
	f.mu.Lock()
	asked := strings.Join(f.seen, "")
	f.mu.Unlock()
	if !strings.Contains(asked, "GET /tasks HTTP/1.1\r\n") || !strings.Contains(asked, "X-Luoke-Accessory: luoke-scan/0.1.0\r\n") {
		t.Errorf("asked %q", asked)
	}

	// The recorder: only for a run that talks to luoke-core, and it writes.
	if MemoryRecorder(false, false, "0.1.0", map[string]string{}) != nil || MemoryRecorder(true, true, "0.1.0", env) != nil ||
		MemoryRecorder(false, true, "0.1.0", env) != nil {
		t.Error("a recorder for a run that does not talk to luoke-core")
	}
	os.Remove(filepath.Join(out, "lines"))
	MemoryRecorder(false, false, "0.1.0", env)(records[:1])
	if read("lines") != string(records[0].Line()) {
		t.Errorf("recorder wrote %q", read("lines"))
	}
	// luoke-core not there, or no records: nothing, quickly.
	f.stop()
	if n := rememberRecords(records, "0.1.0", env); n != 0 {
		t.Errorf("remembered %d without luoke-core", n)
	}
	if n := rememberRecords(nil, "0.1.0", env); n != 0 {
		t.Error("nothing to remember")
	}
}
