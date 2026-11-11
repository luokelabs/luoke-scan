package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 9000)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appCacheHome(t *testing.T) (string, Context) {
	t.Helper()
	// Spelled as the file system lists it (/private/var/… for /var/…): the rule's paths come from listing folders.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	apps := filepath.Join(home, "Applications")
	writeApp(t, filepath.Join(apps, "Foo.app"), "com.example.Foo")
	writeApp(t, filepath.Join(apps, "Slack.app"), "com.tinyspeck.slackmacgap")
	writeApp(t, filepath.Join(apps, "1Password.app"), "com.1password.1password")
	writeApp(t, filepath.Join(apps, "Safari.app"), "com.apple.Safari")

	caches := filepath.Join(home, "Library/Caches")
	writeFile(t, filepath.Join(caches, "com.example.foo/data/blob")) // the folder's case differs from the app's id
	writeFile(t, filepath.Join(caches, "com.1password.1password/x")) // a password manager: never
	writeFile(t, filepath.Join(caches, "com.apple.Safari/x"))        // Apple's: never
	writeFile(t, filepath.Join(caches, "com.gone.App/x"))            // its app is gone: a leftover, not this rule's
	writeFile(t, filepath.Join(caches, "Homebrew/x"))                // a rebuildable cache: cache.rebuildable's

	support := filepath.Join(home, "Library/Application Support")
	writeFile(t, filepath.Join(support, "Slack/Local State"))
	writeFile(t, filepath.Join(support, "Slack/Cache/Cache_Data/f"))
	writeFile(t, filepath.Join(support, "Slack/Code Cache/js/f"))
	writeFile(t, filepath.Join(support, "Slack/Service Worker/CacheStorage/f")) // sites' offline data: never
	writeFile(t, filepath.Join(support, "Slack/IndexedDB/f"))
	writeFile(t, filepath.Join(support, "NotChromium/Cache/f"))    // no Local State: not a Chromium app
	writeFile(t, filepath.Join(support, "Odd/Local State"))        // a folder named Cache that is not Chromium's disk cache
	writeFile(t, filepath.Join(support, "Odd/Cache/notes.txt"))    //
	writeFile(t, filepath.Join(support, "Vendor/App/Local State")) // one level down
	writeFile(t, filepath.Join(support, "Vendor/App/GPUCache/f"))
	writeFile(t, filepath.Join(support, "1Password/Local State")) // protected by name
	writeFile(t, filepath.Join(support, "1Password/Cache/Cache_Data/f"))

	logs := filepath.Join(home, "Library/Logs")
	writeFile(t, filepath.Join(logs, "com.example.Foo/run.log"))
	writeFile(t, filepath.Join(logs, "DiagnosticReports/Foo-2026-11-09.ips"))
	writeFile(t, filepath.Join(logs, "com.apple.xpc.launchd/x.log")) // Apple's: never
	writeFile(t, filepath.Join(logs, "Tailscale/x.log"))             // a VPN's: never

	ctx := NewContext(home)
	ctx.AppDirs = []string{apps}
	return home, ctx
}

func TestAppCacheRule(t *testing.T) {
	home, ctx := appCacheHome(t)
	r := &AppCacheRule{MinBytes: 1, MinLogBytes: 1, MaxItems: 8}
	fs, err := r.Run(&ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Finding{}
	var keys []string
	for _, f := range fs {
		rel, _ := filepath.Rel(home, f.Path)
		key := f.Rule + " " + rel
		got[key] = f
		keys = append(keys, key)
		if f.Category != CatCache || f.Verdict != Confirm {
			t.Errorf("%s: %s/%s, want cache/confirm: never safe, never cleaned automatically", key, f.Category, f.Verdict)
		}
	}
	sort.Strings(keys)
	want := []string{
		"cache.app Library/Caches/com.example.foo",
		"cache.electron Library/Application Support/Slack",
		"cache.electron Library/Application Support/Vendor/App",
		"cache.logs Library/Logs/DiagnosticReports",
		"cache.logs Library/Logs/com.example.Foo",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(keys, "\n"), strings.Join(want, "\n"))
	}
	if f := got["cache.app Library/Caches/com.example.foo"]; f.Title != "「Foo」的缓存" || f.Evidence["app_id"] != "com.example.foo" {
		t.Errorf("app cache: %q %v", f.Title, f.Evidence)
	}
	slack := got["cache.electron Library/Application Support/Slack"]
	support := filepath.Join(home, "Library/Application Support/Slack")
	if slack.Evidence["targets"] != filepath.Join(support, "Cache")+"\n"+filepath.Join(support, "Code Cache") {
		t.Errorf("Slack's targets: only its cache folders, not Service Worker or IndexedDB: %q", slack.Evidence["targets"])
	}
	if f := got["cache.logs Library/Logs/DiagnosticReports"]; f.Title != "应用的崩溃报告" {
		t.Errorf("crash reports: %q", f.Title)
	}
	if f := got["cache.logs Library/Logs/com.example.Foo"]; f.Title != "「Foo」的日志" {
		t.Errorf("an installed app's logs are named after it: %q", f.Title)
	}
}

func TestAppCacheRuleThresholdsAndCap(t *testing.T) {
	_, ctx := appCacheHome(t)
	fs, _ := (&AppCacheRule{MinBytes: 1 << 40, MinLogBytes: 1 << 40, MaxItems: 8}).Run(&ctx)
	if len(fs) != 0 {
		t.Errorf("below the sizes nothing is mentioned: %d", len(fs))
	}
	fs, _ = (&AppCacheRule{MinBytes: 1, MinLogBytes: 1, MaxItems: 1}).Run(&ctx)
	n := map[string]int{}
	for _, f := range fs {
		n[f.Rule]++
	}
	if n["cache.app"] != 1 || n["cache.electron"] != 1 || n["cache.logs"] != 1 {
		t.Errorf("at most MaxItems of each kind: %v", n)
	}
}

func TestAppCacheIsProtected(t *testing.T) {
	for _, name := range []string{"com.apple.Safari", "group.com.apple.notes", "com.agilebits.onepassword7", "com.bitwarden.desktop",
		"com.crowdstrike.falcon.Agent", "com.spotify.client", "com.getdropbox.dropbox", "com.google.drivefs", "Tailscale",
		"com.apple.inputmethod.Kotoeri", "com.eset.remoteadministrator"} {
		if !AppCacheIsProtected(name) {
			t.Errorf("%s should be protected", name)
		}
	}
	for _, name := range []string{"com.tinyspeck.slackmacgap", "com.example.assets", "com.figma.Desktop", "com.microsoft.VSCode"} {
		if AppCacheIsProtected(name) {
			t.Errorf("%s should not be protected", name)
		}
	}
}

func TestChromiumCaches(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "Local State"))
	writeFile(t, filepath.Join(root, "Cache/index"))
	writeFile(t, filepath.Join(root, "Cache/data_0"))
	writeFile(t, filepath.Join(root, "GPUCache/f"))
	if err := os.Symlink(filepath.Join(root, "GPUCache"), filepath.Join(root, "ShaderCache")); err != nil {
		t.Fatal(err)
	}
	got := ChromiumCaches(root)
	want := []string{filepath.Join(root, "Cache"), filepath.Join(root, "GPUCache")}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("caches %v, want %v (the old disk cache layout counts; a link does not)", got, want)
	}
}

// Where the round may not look (access switched off: the folders macOS asks about, AddressBook, Knowledge… in
// Application Support) is not so much as listed, stat'ed or opened, even when it looks like a Chromium app's folder or
// holds one a level down. What it may look at is found as before.
func TestAppCacheRuleNeverLooksWhereItMayNot(t *testing.T) {
	home, ctx := appCacheHome(t)
	support := filepath.Join(home, "Library/Application Support")
	writeFile(t, filepath.Join(support, "AddressBook/Local State"))
	writeFile(t, filepath.Join(support, "AddressBook/Cache/Cache_Data/f"))
	writeFile(t, filepath.Join(support, "Knowledge/Vendor/Local State"))
	writeFile(t, filepath.Join(support, "Knowledge/Vendor/GPUCache/f"))

	var looked []string
	children, item, exists := acChildren, acItem, acExists
	defer func() { acChildren, acItem, acExists = children, item, exists }()
	acChildren = func(p string) []string { looked = append(looked, p); return children(p) }
	acItem = func(p string) (Entry, bool) { looked = append(looked, p); return item(p) }
	acExists = func(p string) bool { looked = append(looked, p); return exists(p) }
	privacy := func(p string) bool {
		return strings.HasPrefix(p, filepath.Join(support, "AddressBook")) || strings.HasPrefix(p, filepath.Join(support, "Knowledge"))
	}
	run := func(c Context) []Finding {
		looked = nil
		fs, err := (&AppCacheRule{MinBytes: 1, MinLogBytes: 1, MaxItems: 8}).Run(&c)
		if err != nil {
			t.Fatal(err)
		}
		return fs
	}

	// With Full Disk Access the recorder does see these folders read: the check below would catch them
	open := ctx
	yes := true
	open.FullDiskAccess = &yes
	run(open)
	seen := false
	for _, p := range looked {
		seen = seen || privacy(p)
	}
	if !seen {
		t.Fatal("with access the privacy folders are read; the recorder saw none of it, so the test proves nothing")
	}

	off := ctx
	no := false
	off.FullDiskAccess, off.AccessOff = &no, true
	fs := run(off)
	for _, p := range looked {
		if !off.MayLook(p) {
			t.Errorf("looked at %s, where the round may not look", p)
		}
	}
	found := map[string]bool{}
	for _, f := range fs {
		rel, _ := filepath.Rel(home, f.Path)
		found[f.Rule+" "+rel] = true
		if privacy(f.Path) {
			t.Errorf("reported %s", f.Path)
		}
	}
	for _, want := range []string{"cache.electron Library/Application Support/Slack", "cache.electron Library/Application Support/Vendor/App",
		"cache.app Library/Caches/com.example.foo"} {
		if !found[want] {
			t.Errorf("lost %s: %v", want, found)
		}
	}
}
