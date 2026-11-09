package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// signedTool copies /usr/bin/true to dir/name and signs it ad hoc with the given identifier ("" leaves it unsigned).
func signedTool(t *testing.T, dir, name, identifier string) string {
	t.Helper()
	b, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Skip("no /usr/bin/true")
	}
	p := filepath.Join(dir, name)
	os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
	// /usr/bin/true is a universal binary signed by Apple: drop that signature first.
	Run(codesign, []string{"--remove-signature", p}, RunOpts{})
	if identifier != "" {
		if r := Run(codesign, []string{"-s", "-", "-f", "-i", identifier, p}, RunOpts{}); r.Status != 0 {
			t.Fatalf("codesign: %s", r.Stderr)
		}
	}
	return p
}

func TestPackedToolsAreCheckedBeforeUse(t *testing.T) {
	helpers := t.TempDir() // as 螺壳.app's Contents/Helpers
	exe := filepath.Join(helpers, "luoke-scan")
	good := signedTool(t, helpers, "yara", "ai.luoke.scan.yara")
	signedTool(t, helpers, "clamscan", "ai.luoke.scan.sigtool") // someone else's identifier
	signedTool(t, helpers, "sigtool", "")                       // not signed
	if got := findToolBeside(exe, "yara", true); got != good {
		t.Errorf("signed yara: got %q, want %q", got, good)
	}
	for _, name := range []string{"clamscan", "sigtool", "freshclam"} {
		if got := findToolBeside(exe, name, true); got != "" {
			t.Errorf("%s: the packed build used %q", name, got)
		}
	}
	// Changed after signing.
	f, _ := os.OpenFile(good, os.O_WRONLY|os.O_APPEND, 0)
	f.Write([]byte("x"))
	f.Close()
	toolChecks.Delete(good)
	if got := findToolBeside(exe, "yara", true); got != "" {
		t.Errorf("yara changed after signing was used: %q", got)
	}
	// A development build takes what is there, unchecked, and never needs it signed.
	if got := findToolBeside(exe, "sigtool", false); got != filepath.Join(helpers, "sigtool") {
		t.Errorf("development build: got %q", got)
	}
}

func TestToolRequirement(t *testing.T) {
	if got := ToolRequirement("clamscan", ""); got != `identifier "ai.luoke.scan.clamscan"` {
		t.Errorf("no team: %s", got)
	}
	got := ToolRequirement("clamscan", "ABCDE12345")
	for _, want := range []string{`identifier "ai.luoke.scan.clamscan"`, "anchor apple generic", `certificate leaf[subject.OU] = "ABCDE12345"`,
		"certificate 1[field.1.2.840.113635.100.6.2.6]", "certificate leaf[field.1.2.840.113635.100.6.1.13]"} {
		if !strings.Contains(got, want) {
			t.Errorf("with a team, %q lacks %q", got, want)
		}
	}
}

func TestClamAVCertsWrittenForOneRun(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	args, done := clamAVCertsFrom(fstest.MapFS{
		"packaging/clamav-certs/clamav.crt": {Data: []byte(pem)},
		"packaging/clamav-certs/README.md":  {Data: []byte("x")},
	})
	if len(args) != 1 || !strings.HasPrefix(args[0], "--cvdcertsdir=") {
		t.Fatalf("args %v", args)
	}
	dir := strings.TrimPrefix(args[0], "--cvdcertsdir=")
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("folder %s: %v %v", dir, fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "clamav.crt")); string(b) != pem {
		t.Errorf("certificate: %q", b)
	}
	if Exists(filepath.Join(dir, "README.md")) {
		t.Error("only the certificates go in")
	}
	done()
	if Exists(dir) {
		t.Error("done left the folder")
	}
	if args, _ := clamAVCertsFrom(fstest.MapFS{"packaging/clamav-certs/README.md": {Data: []byte("x")}}); args != nil {
		t.Errorf("no certificate: %v", args)
	}
	if args, _ := ClamAVCerts(); args != nil && !Packed() {
		t.Errorf("a development build points Homebrew's tools elsewhere: %v", args)
	}
}

func TestFreshclamSettingsAreTheCarriedOnes(t *testing.T) {
	f, made, ok := settingsFile()
	if !ok {
		t.Fatal("no settings")
	}
	defer os.RemoveAll(made)
	want, _ := os.ReadFile("../../packaging/freshclam.conf")
	got, _ := os.ReadFile(f)
	if len(want) == 0 || string(got) != string(want) {
		t.Errorf("settings differ from packaging/freshclam.conf")
	}
	if fi, _ := os.Stat(made); fi == nil || fi.Mode().Perm() != 0o700 || filepath.Dir(f) != made {
		t.Errorf("settings not in a folder of their own: %s", f)
	}
}
