package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The same property list written by plutil as XML and as binary decodes to the same values.
func TestPlistXMLAndBinary(t *testing.T) {
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "a.plist")
	os.WriteFile(xmlPath, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.example.ok</string>
<key>ProgramArguments</key><array><string>/bin/ls</string><string>/</string></array>
<key>RunAtLoad</key><true/><key>N</key><integer>42</integer><key>Name</key><string>螺壳 &amp; co</string>
</dict></plist>`), 0o644)
	binPath := filepath.Join(dir, "b.plist")
	if out, err := exec.Command("/usr/bin/plutil", "-convert", "binary1", "-o", binPath, xmlPath).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	for _, p := range []string{xmlPath, binPath} {
		d := ReadPlistDict(p)
		if PlistString(d, "Label") != "io.example.ok" || PlistString(d, "Name") != "螺壳 & co" || d["RunAtLoad"] != true || d["N"] != int64(42) {
			t.Errorf("%s: %#v", p, d)
		}
		if a, _ := d["ProgramArguments"].([]any); len(a) != 2 || a[0] != "/bin/ls" {
			t.Errorf("%s: %#v", p, d["ProgramArguments"])
		}
	}
	if ReadPlistDict(filepath.Join(dir, "missing")) != nil {
		t.Error("missing file")
	}
	os.WriteFile(filepath.Join(dir, "broken.plist"), []byte("not a plist"), 0o644)
	if ReadPlistDict(filepath.Join(dir, "broken.plist")) != nil {
		t.Error("broken")
	}
}
