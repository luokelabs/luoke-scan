package core

import (
	"os"
	"path/filepath"
	"testing"
)

// A tool that fails the first times it is asked for its version is asked again; one that never answers gives "".
func TestToolVersionAsksAgain(t *testing.T) {
	dir := t.TempDir()
	tool := func(name, script string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	never := func() bool { return false }

	steady := tool("steady", "echo 'Tool 1.2.3'\necho more\n")
	if got := toolVersion(steady, never); got != "Tool 1.2.3" {
		t.Fatalf("a tool that answers: %q", got)
	}

	// fails twice, then answers: each call leaves a mark, the third finds two
	marks := filepath.Join(dir, "marks")
	shaky := tool("shaky", "n=$(ls '"+marks+"' 2>/dev/null | wc -l | tr -d ' ')\nmkdir -p '"+marks+"' && touch '"+marks+"'/$n\n[ \"$n\" -ge 2 ] || exit 3\necho 'Tool 9'\n")
	if got := toolVersion(shaky, never); got != "Tool 9" {
		t.Fatalf("a tool that fails twice first: %q", got)
	}
	if n, _ := os.ReadDir(marks); len(n) != toolVersionTries {
		t.Fatalf("asked %d times, want %d", len(n), toolVersionTries)
	}

	calls := filepath.Join(dir, "calls")
	broken := tool("broken", "echo x >> '"+calls+"'\nexit 1\n")
	if got := toolVersion(broken, never); got != "" {
		t.Fatalf("a tool that never answers: %q", got)
	}
	if b, _ := os.ReadFile(calls); len(b) != 2*toolVersionTries {
		t.Fatalf("asked %d times, want %d", len(b)/2, toolVersionTries)
	}

	// cancelled: not asked again
	os.Remove(calls)
	if got := toolVersion(broken, func() bool { return true }); got != "" {
		t.Fatalf("cancelled: %q", got)
	}
	if b, _ := os.ReadFile(calls); len(b) != 2 {
		t.Fatalf("cancelled: asked %d times, want 1", len(b)/2)
	}

	if got := toolVersion(filepath.Join(dir, "missing"), never); got != "" {
		t.Fatalf("no such tool: %q", got)
	}
}
