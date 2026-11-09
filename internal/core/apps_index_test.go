package core

import (
	"os"
	"path/filepath"
	"testing"
)

func writeApp(t *testing.T, path, id string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "Contents"), 0o700); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>` + id + `</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(path, "Contents/Info.plist"), []byte(plist), 0o600); err != nil {
		t.Fatal(err)
	}
}

// During a round FindAppIn answers from one reading of the folders, the same as reading them each time: the first
// folder wins, a folder's own apps before those one level down, any case; after the round, a new app is seen again.
func TestFindAppInIndexAnswersTheSame(t *testing.T) {
	real := func(d string) string {
		r, err := filepath.EvalSymlinks(d)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	a, b := real(t.TempDir()), real(t.TempDir())
	writeApp(t, filepath.Join(a, "Utilities/Tool.app"), "io.example.Tool")
	writeApp(t, filepath.Join(a, "Zed.app"), "io.example.tool") // a's own entries come before its subfolders'
	writeApp(t, filepath.Join(b, "Tool.app"), "io.example.tool")
	writeApp(t, filepath.Join(b, "Other.app"), "io.example.other")
	writeApp(t, filepath.Join(b, "Empty.app"), "")
	dirs := []string{a, b}
	ids := []string{"io.example.tool", "IO.EXAMPLE.TOOL", "io.example.other", "io.example.none", ""}
	want := map[string]string{}
	for _, id := range ids {
		want[id] = FindAppIn(id, dirs)
	}
	if want["io.example.tool"] != filepath.Join(a, "Zed.app") || want["io.example.other"] != filepath.Join(b, "Other.app") || want[""] != "" {
		t.Fatalf("without the index: %v", want)
	}
	withAppIndex(func() {
		for _, id := range ids {
			if got := FindAppIn(id, dirs); got != want[id] {
				t.Errorf("%q: index %q, folders %q", id, got, want[id])
			}
		}
		writeApp(t, filepath.Join(b, "New.app"), "io.example.new")
		if got := FindAppIn("io.example.new", dirs); got != "" {
			t.Errorf("an app added during the round is read at the next one, not this: %q", got)
		}
	})
	if got := FindAppIn("io.example.new", dirs); got != filepath.Join(b, "New.app") {
		t.Errorf("after the round: %q", got)
	}
	if len(appIndexes) != 0 || appIndexRounds != 0 {
		t.Errorf("indexes kept after the round: %d, rounds %d", len(appIndexes), appIndexRounds)
	}
}
