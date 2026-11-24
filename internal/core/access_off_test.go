package core

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// With access switched off macOS may still allow everything: MayLook stops at what macOS alone would have stopped.
func TestMayLookWithAccessSwitchedOff(t *testing.T) {
	home := t.TempDir()
	no := false
	denied := Context{Home: home, FullDiskAccess: &no}
	off := Context{Home: home, FullDiskAccess: &no, AccessOff: true}
	for _, rel := range []string{"Library/Mail", "Library/Mail/V10/x.emlx", "Library/Safari", "library/messages",
		"Library/Application Support/AddressBook"} {
		p := filepath.Join(home, rel)
		if !denied.MayLook(p) {
			t.Errorf("denied by macOS: nothing here to stop %s", rel)
		}
		if off.MayLook(p) {
			t.Errorf("switched off: looked at %s", rel)
		}
	}
	for _, rel := range []string{"Documents", "Downloads/a.dmg", "Library/Containers/x"} {
		if off.MayLook(filepath.Join(home, rel)) {
			t.Errorf("switched off: looked at guarded %s", rel)
		}
	}
	for _, rel := range []string{"Library/Caches", "Library/Application Support/Example", "Library/Mailbox"} {
		if !off.MayLook(filepath.Join(home, rel)) {
			t.Errorf("switched off: %s is open to any app", rel)
		}
	}
}

// Without Full Disk Access the libraries macOS asks about stay closed: walking in raises a dialog nobody asked for.
func TestMayLookStaysOutOfMediaLibraries(t *testing.T) {
	home := t.TempDir()
	no := false
	denied := Context{Home: home, FullDiskAccess: &no}
	for _, rel := range []string{"Music", "Music/Music/Media.localized/a.m4a", "Movies/TV", "Movies/TV/x.tvlibrary",
		"Library/Photos", "Library/Photos/Libraries/Syndication.photoslibrary",
		"Pictures/Photos Library.photoslibrary", "Pictures/Photos Library.photoslibrary/database/Photos.sqlite",
		"Movies/Old.photoslibrary/originals"} {
		if denied.MayLook(filepath.Join(home, rel)) {
			t.Errorf("no access: looked at %s", rel)
		}
	}
	for _, rel := range []string{"Pictures", "Pictures/a.jpg", "Movies", "Movies/a.mov"} {
		if !denied.MayLook(filepath.Join(home, rel)) {
			t.Errorf("no access: %s is open to any app", rel)
		}
	}
	yes := true
	if !(&Context{Home: home, FullDiskAccess: &yes}).MayLook(filepath.Join(home, "Music")) {
		t.Error("with access: Music")
	}
}

// A walk from an open folder stops at the library inside it: opening it is what makes macOS ask.
func TestWalkStopsAtWhatTheRoundMayNotLookAt(t *testing.T) {
	home := t.TempDir()
	library := filepath.Join(home, "Pictures", "Photos Library.photoslibrary")
	if err := os.MkdirAll(filepath.Join(library, "database"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(library, "database", "Photos.sqlite"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(home, "Pictures", "a.jpg"), []byte("x"), 0o644)
	no := false
	ctx := Context{Home: home, FullDiskAccess: &no}
	seen := func() (out []string) {
		Tree(filepath.Join(home, "Pictures"), nil, func(e Entry) bool { out = append(out, e.Name); return true })
		return out
	}
	if got := len(seen()); got != 4 {
		t.Fatalf("no round running: %d items", got)
	}
	done := limitWalks(&ctx)
	got := seen()
	if _, ok := List(library); ok {
		t.Error("listed the library")
	}
	if _, ok := spaceListEntries(library, nil); ok {
		t.Error("listed the library to measure it")
	}
	if n := AllocatedSize(library); n != 0 {
		t.Errorf("measured the library: %d", n)
	}
	done()
	if len(got) != 2 {
		t.Errorf("walked into the library: %v", got)
	}
	if len(seen()) != 4 {
		t.Error("the limit outlived the round")
	}
	yes := true
	done = limitWalks(&Context{Home: home, FullDiskAccess: &yes})
	defer done()
	if len(seen()) != 4 {
		t.Error("with access: everything is open")
	}
}

// A readable TCC database is not read with access switched off: said as when macOS refuses it.
func TestPermissionRuleWithAccessSwitchedOff(t *testing.T) {
	home := t.TempDir()
	db := filepath.Join(home, "TCC.db")
	sql := `CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER);
		INSERT INTO access VALUES ('kTCCServiceCamera', 'io.example.gone', 0, 2);`
	if out, err := exec.Command("/usr/bin/sqlite3", db, sql).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	no := false
	ctx := Context{Home: home, TCCDatabases: []string{db}, FullDiskAccess: &no}
	found, err := (&PermissionRule{}).Run(&ctx)
	if err != nil || len(found) != 1 || !strings.Contains(found[0].Title, "io.example.gone") {
		t.Fatalf("readable: %v %v", found, err)
	}
	ctx.AccessOff = true
	found, err = (&PermissionRule{}).Run(&ctx)
	var skipped *SkippedError
	if len(found) != 0 || !errors.As(err, &skipped) || !strings.Contains(skipped.Reason, "完全磁盘访问") {
		t.Fatalf("switched off: %v %v", found, err)
	}
}
