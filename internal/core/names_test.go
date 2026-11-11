package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		"/x/%E9%A6%99%E6%B8%AF.pdf":   "香港.pdf",
		"/x/report%20final.pdf":       "report final.pdf",
		"/x/plain.pdf":                "plain.pdf",
		"/x/100%.txt":                 "100%.txt",    // not an encoding
		"/x/a%2Fb.txt":                "a%2Fb.txt",   // would make a slash
		"/x/bell%07.txt":              "bell%07.txt", // would not print
		"/x/%E9%A6%99%E6%B8%AF.app":   "香港.app",
		"/x/Downloads/oMLX-0.7.3.dmg": "oMLX-0.7.3.dmg",
	} {
		if got := DisplayName(in); got != want {
			t.Errorf("DisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A duplicate set whose file name a downloader kept percent-encoded: the title names it decoded, the report's paths
// (evidence) keep it as the file system has it (luoke-scan#113).
func TestDuplicatesTitleDecodesTheName(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("香港"), 1<<19)
	for _, name := range []string{"%E9%A6%99%E6%B8%AF.pdf", "%E9%A6%99%E6%B8%AF (1).pdf", "%E9%A6%99%E6%B8%AF (2).pdf"} {
		p := filepath.Join(home, "Downloads", name)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := NewContext(home)
	rule := &DuplicateRule{Places: []string{"Downloads"}, MinBytes: 1 << 20, MinWaste: 1 << 20, MaxSets: 20, MaxFiles: 1000}
	found, err := rule.Run(&ctx)
	if err != nil {
		t.Fatal(err)
	}
	var dup *Finding
	for i := range found {
		if found[i].Rule == "space.duplicates" {
			dup = &found[i]
		}
	}
	if dup == nil {
		t.Fatalf("no duplicate set: %+v", found)
	}
	if !strings.HasPrefix(dup.Title, "3 份一样的 香港") || strings.Contains(dup.Title, "%E9") {
		t.Errorf("title %q", dup.Title)
	}
	if !strings.Contains(dup.Evidence["copies"], "%E9%A6%99%E6%B8%AF") {
		t.Errorf("the evidence keeps the names as they are: %q", dup.Evidence["copies"])
	}
}
