package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

func TestFixtureOnlyRefusal(t *testing.T) {
	for _, c := range []struct {
		command string
		args    []string
		ok      bool
	}{
		{"version", nil, true},
		{"mcp", []string{"--fixture", "/x", "--clock", "2026-10-20T12:00:00Z", "--no-full-disk-access"}, true},
		{"scan", []string{"--fixture", "/x", "--autoclean"}, true},
		{"scan", []string{"--fixture", "/x", "--quick"}, true},
		{"cleaned", []string{"--fixture", "/x", "--json"}, true},
		{"restore", []string{"--fixture", "/x", "p-000000000001"}, true},
		{"system", []string{"--fixture", "/x"}, true},
		{"report", []string{"--data", "/x/data"}, true},
		{"status", []string{"--data", "/x/data", "--json"}, true},
		{"mcp", []string{"--this-mac"}, false},
		{"scan", []string{"--this-mac", "--autoclean"}, false},
		{"scan", []string{"--fixture", "/x", "--this-mac"}, false},
		{"scan", []string{"--home", "/x", "--data", "/y"}, false},
		{"scan", []string{"--fixture", "/x", "--tmp", "/y"}, false},
		{"scan", []string{"--fixture", "/x", "--projects", "/y"}, false},
		{"mcp", []string{"--fixture", "/x", "--tool-dir", "/y"}, false},
		{"update", []string{"--this-mac"}, false},
		{"update", []string{"--data", "/x/data"}, false},
		{"malicious-import", []string{"--data", "/x/data", "/y.json"}, false},
		{"eval-cleanup", nil, false},
		{"eval-skills", nil, false},
		{"eval-agentfiles", nil, false},
		{"make-skill-evalset", nil, false},
		{"nonsense", nil, false},
	} {
		why := fixtureOnlyRefusal(c.command, c.args)
		if (why == "") != c.ok {
			t.Errorf("%s %v: refusal %q, want ok=%v", c.command, c.args, why, c.ok)
		}
		if why != "" && !strings.Contains(why, fixtureOnlyWord) {
			t.Errorf("%s %v: the refusal does not name the build: %q", c.command, c.args, why)
		}
	}
}

// fakeMac makes the smallest fake Mac the fixture-only build takes: a home folder and fakes.json.
func fakeMac(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "fake")
	if err := os.MkdirAll(filepath.Join(root, "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fakes.json"), []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFakeMacProblem(t *testing.T) {
	elsewhere := t.TempDir()
	good := fakeMac(t)
	if why := fakeMacProblem(core.Layout{Root: good}, true, elsewhere); why != "" {
		t.Errorf("a fake Mac refused: %s", why)
	}
	if why := fakeMacProblem(core.Layout{Root: good}, false, elsewhere); why == "" {
		t.Error("a fake Mac without fakes.json taken")
	}
	if why := fakeMacProblem(core.Layout{Root: good}, true, filepath.Join(good, "home")); why == "" {
		t.Error("a fake Mac whose home is this Mac's home taken")
	}
	linked := filepath.Join(t.TempDir(), "linked")
	os.MkdirAll(linked, 0o755)
	if err := os.Symlink(elsewhere, filepath.Join(linked, "home")); err != nil {
		t.Fatal(err)
	}
	if why := fakeMacProblem(core.Layout{Root: linked}, true, filepath.Join(t.TempDir(), "x")); why == "" {
		t.Error("a fake Mac whose home is a link taken")
	}
	if why := fakeMacProblem(core.Layout{Root: filepath.Join(t.TempDir(), "none")}, true, elsewhere); why == "" {
		t.Error("a folder without a home taken")
	}
}

// The test binary also plays luoke-scan (TestLuokeScanHelper), built either way.
const (
	helperArgs        = "LUOKE_SCAN_TEST_ARGS"
	helperFixtureOnly = "LUOKE_SCAN_TEST_FIXTURE_ONLY"
)

type ran struct {
	code   int
	stdout string
	stderr string
}

// luokeScan runs main with args, as the fixture-only build or the plain development one. Its home and temporary
// folder are empty folders of the test's own: a refusal that let something through would find nothing of this Mac.
func luokeScan(t *testing.T, fixtureOnly bool, args ...string) ran {
	t.Helper()
	encoded, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLuokeScanHelper$")
	flag := ""
	if fixtureOnly {
		flag = "1"
	}
	home, tmp := t.TempDir(), t.TempDir()
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home, "TMPDIR=" + tmp, "LANG=en_US.UTF-8",
		helperArgs + "=" + string(encoded), helperFixtureOnly + "=" + flag}
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	if e, ok := err.(*exec.ExitError); ok {
		code = e.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return ran{code, out.String(), errOut.String()}
}

func TestFixtureOnlyBuild(t *testing.T) {
	if r := luokeScan(t, true, "version"); r.code != 0 || !strings.Contains(r.stdout, fixtureOnlyWord) {
		t.Errorf("version: %d %q %q", r.code, r.stdout, r.stderr)
	}
	if r := luokeScan(t, false, "version"); r.code != 0 || strings.Contains(r.stdout, fixtureOnlyWord) {
		t.Errorf("the plain build's version: %d %q", r.code, r.stdout)
	}
	data := t.TempDir()
	// Each of these would read or write something besides a fake Mac; refused before it does.
	for _, args := range [][]string{
		{"mcp", "--this-mac"},
		{"cleaned", "--this-mac"},
		{"mcp", "--data", data},
		{"report"},
		{"update", "--data", data, "--tool-dir", data},
		{"eval-cleanup", "--cases", filepath.Join(data, "none.json")},
	} {
		if r := luokeScan(t, true, args...); r.code != 64 || !strings.Contains(r.stderr, fixtureOnlyWord) {
			t.Errorf("%v: %d %q", args, r.code, r.stderr)
		}
	}
	linked := filepath.Join(t.TempDir(), "linked")
	os.MkdirAll(linked, 0o755)
	os.Symlink(t.TempDir(), filepath.Join(linked, "home"))
	os.WriteFile(filepath.Join(linked, "fakes.json"), []byte(`{"version":1}`), 0o644)
	noFakes := fakeMac(t)
	os.Remove(filepath.Join(noFakes, "fakes.json"))
	for _, root := range []string{linked, noFakes} {
		if r := luokeScan(t, true, "mcp", "--fixture", root); r.code != 64 || !strings.Contains(r.stderr, "不是假 Mac") {
			t.Errorf("%s: %d %q", root, r.code, r.stderr)
		}
	}
	// A fake Mac: a round, then its report from the data directory beside it.
	root := fakeMac(t)
	if r := luokeScan(t, true, "scan", "--fixture", root, "--clock", "2026-10-20T12:00:00Z", "--for-agent"); r.code != 0 {
		t.Fatalf("a round on a fake Mac: %d %q", r.code, r.stderr)
	}
	if r := luokeScan(t, true, "status", "--data", filepath.Join(root, "data"), "--json"); r.code != 0 || !strings.Contains(r.stdout, "startedAt") {
		t.Errorf("status: %d %q %q", r.code, r.stdout, r.stderr)
	}
}

// TestLuokeScanHelper is not a test: it is luoke-scan for TestFixtureOnlyBuild.
func TestLuokeScanHelper(t *testing.T) {
	encoded, ok := os.LookupEnv(helperArgs)
	if !ok {
		t.Skip("helper for TestFixtureOnlyBuild")
	}
	var a []string
	if err := json.Unmarshal([]byte(encoded), &a); err != nil {
		t.Fatal(err)
	}
	fixtureOnlyFlag = os.Getenv(helperFixtureOnly)
	os.Args = append([]string{"luoke-scan"}, a...)
	main()
	os.Exit(0)
}
