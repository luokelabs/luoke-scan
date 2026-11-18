package core

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testItem is one record for a made-up archive (testArchive).
type testItem struct {
	user, name, id, container, url, bundle string
	assoc                                  []string
	typ, disp                              int64
}

const testUser = "0A1B2C3D-0000-4000-8000-00000000ABCD"

// testArchive writes items as Login Items & Extensions' archive would be (an NSKeyedArchiver XML property list: the
// UIDs as {"CF$UID": n}) and returns it.
func testArchive(items []testItem) string {
	objs := []string{"<string>$null</string>"}
	add := func(x string) int { objs = append(objs, x); return len(objs) - 1 }
	uid := func(i int) string { return fmt.Sprintf("<dict><key>CF$UID</key><integer>%d</integer></dict>", i) }
	str := func(s string) int { return add("<string>" + html.EscapeString(s) + "</string>") }
	classes := map[string]int{}
	class := func(name string) int {
		if i, ok := classes[name]; ok {
			return i
		}
		classes[name] = add("<dict><key>$classname</key><string>" + name + "</string><key>$classes</key><array><string>" + name +
			"</string><string>NSObject</string></array></dict>")
		return classes[name]
	}
	opt := func(s string) string {
		if s == "" {
			return uid(0)
		}
		return uid(str(s))
	}
	byUser := map[string][]int{}
	var users []string
	for _, it := range items {
		u := it.user
		if u == "" {
			u = testUser
		}
		if _, ok := byUser[u]; !ok {
			users = append(users, u)
		}
		rec := "<dict><key>$class</key>" + uid(class("ItemRecord")) +
			fmt.Sprintf("<key>type</key><integer>%d</integer><key>disposition</key><integer>%d</integer>", it.typ, it.disp) +
			"<key>name</key>" + opt(it.name) + "<key>identifier</key>" + opt(it.id) + "<key>container</key>" + opt(it.container) +
			"<key>bundleIdentifier</key>" + opt(it.bundle)
		if it.url != "" {
			rec += "<key>url</key>" + uid(add("<dict><key>$class</key>"+uid(class("NSURL"))+"<key>NS.base</key>"+uid(0)+
				"<key>NS.relative</key>"+uid(str(it.url))+"</dict>"))
		}
		if len(it.assoc) > 0 {
			var refs string
			for _, a := range it.assoc {
				refs += uid(str(a))
			}
			rec += "<key>associatedBundleIdentifiers</key>" + uid(add("<dict><key>$class</key>"+uid(class("NSArray"))+
				"<key>NS.objects</key><array>"+refs+"</array></dict>"))
		}
		byUser[u] = append(byUser[u], add(rec+"</dict>"))
	}
	var keys, values string
	for _, u := range users {
		keys += uid(str(u))
		var refs string
		for _, r := range byUser[u] {
			refs += uid(r)
		}
		values += uid(add("<dict><key>$class</key>" + uid(class("NSMutableArray")) + "<key>NS.objects</key><array>" + refs + "</array></dict>"))
	}
	dict := add("<dict><key>$class</key>" + uid(class("NSMutableDictionary")) + "<key>NS.keys</key><array>" + keys +
		"</array><key>NS.objects</key><array>" + values + "</array></dict>")
	store := add("<dict><key>$class</key>" + uid(class("Storage")) + "<key>itemsByUserIdentifier</key>" + uid(dict) + "</dict>")
	return `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>$archiver</key><string>NSKeyedArchiver</string>` +
		`<key>$version</key><integer>100000</integer><key>$top</key><dict><key>store</key>` + uid(store) +
		`</dict><key>$objects</key><array>` + strings.Join(objs, "") + `</array></dict></plist>`
}

// writeArchive puts the archive in dir as version 16, in the binary form macOS writes (plutil), or as XML when there
// is no plutil.
func writeArchive(t *testing.T, dir string, items []testItem) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	xml := filepath.Join(dir, "archive.xml")
	if err := os.WriteFile(xml, []byte(testArchive(items)), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "BackgroundItems-v16.btm")
	if err := exec.Command("/usr/bin/plutil", "-convert", "binary1", "-o", out, xml).Run(); err != nil {
		os.Rename(xml, out)
		return
	}
	os.Remove(xml)
}

func fileURL(p string) string { return (&url.URL{Scheme: "file", Path: p}).String() }

func TestKeyedArchiveReadsTheRecordsBinaryAndXML(t *testing.T) {
	items := []testItem{
		{name: "Gone Sync", id: "2.io.gone.sync", url: "file:///Applications/Gone%20Sync.app/", bundle: "io.gone.sync", typ: btmApp, disp: 3},
		{name: "Helper", id: "8.io.gone.sync.agent", container: "2.io.gone.sync", url: "Contents/Library/LaunchAgents/a.plist",
			bundle: "io.gone.sync.agent", assoc: []string{"io.gone.sync"}, typ: btmAgent, disp: 3, user: RootUserUUID},
	}
	check := func(what string, got []BackgroundItem, why string) {
		t.Helper()
		if why != "" || len(got) != 2 {
			t.Fatalf("%s: %v %q", what, got, why)
		}
		byName := map[string]BackgroundItem{}
		for _, it := range got {
			byName[it.Name] = it
		}
		g, h := byName["Gone Sync"], byName["Helper"]
		if g.User != testUser || g.Identifier != "2.io.gone.sync" || g.BundleID != "io.gone.sync" || g.Type != btmApp ||
			g.Disposition != 3 || fileURLPath(g.URL) != "/Applications/Gone Sync.app" || g.Container != "" {
			t.Errorf("%s: app %+v", what, g)
		}
		if h.User != RootUserUUID || h.Container != "2.io.gone.sync" || h.URL != "Contents/Library/LaunchAgents/a.plist" ||
			fileURLPath(h.URL) != "" || len(h.Associated) != 1 || h.Associated[0] != "io.gone.sync" {
			t.Errorf("%s: agent %+v", what, h)
		}
	}
	dir := t.TempDir()
	writeArchive(t, dir, items)
	data, _ := os.ReadFile(filepath.Join(dir, "BackgroundItems-v16.btm"))
	if strings.HasPrefix(string(data), "bplist00") {
		v, err := DecodePlist(data)
		top, _ := v.(map[string]any)["$top"].(map[string]any)
		if _, ok := top["store"].(PlistUID); err != nil || !ok {
			t.Fatalf("binary UIDs: %v %T", err, top["store"])
		}
	} else {
		t.Log("no plutil: the XML form only")
	}
	got, why := ReadBackgroundItems(dir)
	check("as written", got, why)
	xml := t.TempDir()
	os.WriteFile(filepath.Join(xml, "BackgroundItems-v16.btm"), []byte(testArchive(items)), 0o644)
	got, why = ReadBackgroundItems(xml)
	check("XML", got, why)
}

func TestBackgroundItemsNewestArchiveAndWhatIsNotRead(t *testing.T) {
	dir := t.TempDir()
	if got, why := ReadBackgroundItems(dir); got != nil || why != "" {
		t.Errorf("no archive: %v %q", got, why)
	}
	if got, why := ReadBackgroundItems(""); got != nil || why != "" {
		t.Errorf("not looked at: %v %q", got, why)
	}
	os.WriteFile(filepath.Join(dir, "BackgroundItems-v9.btm"), []byte(testArchive([]testItem{{name: "old", typ: btmApp, disp: 3}})), 0o644)
	os.WriteFile(filepath.Join(dir, "BackgroundItems-v16.btm"), []byte("not a property list"), 0o644)
	if got, why := ReadBackgroundItems(dir); got != nil || why != "「登录项与扩展」的记录读不懂" {
		t.Errorf("the newest is read, and it is not one: %v %q", got, why)
	}
	// A property list, not shaped as known: nothing guessed at.
	os.WriteFile(filepath.Join(dir, "BackgroundItems-v16.btm"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict>`+
		`<key>$archiver</key><string>NSKeyedArchiver</string><key>$top</key><dict><key>root</key><integer>1</integer></dict>`+
		`<key>$objects</key><array><string>$null</string></array></dict></plist>`), 0o644)
	if got, why := ReadBackgroundItems(dir); got != nil || why == "" {
		t.Errorf("another shape: %v %q", got, why)
	}
	os.WriteFile(filepath.Join(dir, "BackgroundItems-v16.btm"), []byte(testArchive([]testItem{{name: "new", typ: btmApp, disp: 3}})), 0o644)
	if got, why := ReadBackgroundItems(dir); len(got) != 1 || got[0].Name != "new" || why != "" {
		t.Errorf("the newest: %v %q", got, why)
	}
	os.Chmod(filepath.Join(dir, "BackgroundItems-v16.btm"), 0)
	defer os.Chmod(filepath.Join(dir, "BackgroundItems-v16.btm"), 0o644)
	if os.Getuid() != 0 {
		if got, why := ReadBackgroundItems(dir); got != nil || why != "读不了「登录项与扩展」的记录" {
			t.Errorf("unreadable: %v %q", got, why)
		}
		// A folder that cannot be listed (some macOS versions, without Full Disk Access) is not read, not 「none」.
		os.Chmod(dir, 0)
		defer os.Chmod(dir, 0o755)
		if got, why := ReadBackgroundItems(dir); got != nil || why != "读不了「登录项与扩展」的记录" {
			t.Errorf("folder not listed: %v %q", got, why)
		}
	}
	if got, why := ReadBackgroundItems(filepath.Join(t.TempDir(), "nope")); got != nil || why != "" {
		t.Errorf("no folder (an older macOS): %v %q", got, why)
	}
}

func TestBackgroundLeftoversOnlyOfAppsReallyGone(t *testing.T) {
	home := t.TempDir()
	apps := filepath.Join(home, "Applications")
	os.MkdirAll(filepath.Join(apps, "Present.app/Contents"), 0o755)
	os.WriteFile(filepath.Join(apps, "Present.app/Contents/Info.plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict>`+
		`<key>CFBundleIdentifier</key><string>org.present.app</string></dict></plist>`), 0o644)
	ctx := Context{Home: home, AppDirs: []string{apps}}
	installed := NewInstalledApps(ctx.AppDirs, false)
	at := func(name string) string { return fileURL(filepath.Join(apps, name)) + "/" }
	items := []BackgroundItem{
		{User: testUser, Name: "Gone", Identifier: "2.io.gone", URL: at("Gone.app"), BundleID: "io.gone", Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Gone Agent", Identifier: "8.io.gone.agent", Container: "2.io.gone", URL: "Contents/Library/LaunchAgents/x.plist",
			BundleID: "io.gone.agent", Type: btmAgent, Disposition: 3},
		{User: RootUserUUID, Name: "Gone Daemon", Identifier: "16.io.gone.daemon", Container: "2.io.gone", BundleID: "io.gone.daemon",
			Type: btmDaemon, Disposition: 3}, // the system's: under root, its container is not
		{User: testUser, Name: "Present", Identifier: "2.p", URL: at("Present.app"), BundleID: "org.present.app", Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Moved", Identifier: "2.m", URL: at("Old/Present.app"), BundleID: "org.present.app", Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Helper of present", Identifier: "2.h", URL: at("Helper.app"), BundleID: "org.present.app.helper", Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Hidden", Identifier: "2.x", URL: at("Hidden.app"), BundleID: "io.hidden", Type: btmApp, Disposition: 7},
		{User: testUser, Name: "Apple", Identifier: "2.a", URL: at("Apple.app"), BundleID: "com.apple.gone", Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Outside", Identifier: "2.o", URL: "file:///Volumes/Outside/Outside.app/", BundleID: "io.outside", Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Another user's", Identifier: "2.u", URL: "file:///Users/x/Applications/U.app/", BundleID: "io.u", Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Developer", Identifier: "Dev", Type: 0x20, Disposition: 3},
		{User: testUser, Name: "Legacy", Identifier: "16.l", URL: at("Legacy.app"), BundleID: "io.legacy", Type: btmDaemon | btmLegacy, Disposition: 3},
		{User: testUser, Name: "No id", Identifier: "2.n", URL: at("NoID.app"), Type: btmApp, Disposition: 3},
		{User: testUser, Name: "Orphan", Identifier: "4.or", Container: "2.nowhere", URL: "Contents/Library/LoginItems/O.app", BundleID: "io.or", Type: btmLoginItem, Disposition: 3},
		{User: "11111111-2222-3333-4444-555555555555", Name: "Theirs", Identifier: "2.t", URL: at("Theirs.app"), BundleID: "io.theirs", Type: btmApp, Disposition: 3},
	}
	got := backgroundLeftovers(&ctx, items, testUser, installed)
	if len(got) != 1 {
		t.Fatalf("only the gone app: %v", got)
	}
	g := got["io.gone"]
	if g == nil || g.name != "Gone" || strings.Join(g.items, "、") != "Gone、Gone Agent" || g.daemon || g.starts { // only in the archive: nothing starts
		t.Errorf("gone: %+v", g)
	}
	// Every user's (a fake home): the other user's too; the root one has no container under root.
	if all := backgroundLeftovers(&ctx, items, "", installed); len(all) != 2 || all["io.theirs"] == nil {
		t.Errorf("every user's: %v", all)
	}
	// Without Full Disk Access a gone app in a guarded folder is not said to be gone.
	no := false
	guarded := Context{Home: home, AppDirs: []string{apps}, FullDiskAccess: &no}
	in := []BackgroundItem{{User: testUser, Name: "In Downloads", Identifier: "2.d", URL: fileURL(filepath.Join(home, "Downloads/D.app")) + "/",
		BundleID: "io.d", Type: btmApp, Disposition: 3}}
	if got := backgroundLeftovers(&guarded, in, testUser, installed); len(got) != 0 {
		t.Errorf("guarded: %v", got)
	}
}

func TestLaunchdLeftoversNameTheirApp(t *testing.T) {
	root := t.TempDir()
	home, lib := filepath.Join(root, "home"), filepath.Join(root, "Library")
	ctx := Context{Home: home, SystemLibrary: lib, AppDirs: []string{filepath.Join(home, "Applications")}}
	prog := filepath.Join(root, "opt/helper")
	os.MkdirAll(filepath.Dir(prog), 0o755)
	os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o755)
	job := func(dir, name, body string) {
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, name+".plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>`+
			name+`</string>`+body+`</dict></plist>`), 0o644)
	}
	daemons, agents := filepath.Join(lib, "LaunchDaemons"), filepath.Join(home, "Library/LaunchAgents")
	job(daemons, "io.gone.vpn.helper", `<key>Program</key><string>`+prog+`</string><key>AssociatedBundleIdentifiers</key><array><string>io.gone.vpn</string></array>`)
	job(agents, "io.gone.one", `<key>ProgramArguments</key><array><string>`+prog+`</string></array><key>AssociatedBundleIdentifiers</key><string>io.gone.one</string>`)
	job(agents, "io.gone.missing", `<key>Program</key><string>/nowhere/x</string><key>AssociatedBundleIdentifiers</key><string>io.gone.missing</string>`)
	job(agents, "io.gone.off", `<key>Program</key><string>`+prog+`</string><key>Disabled</key><true/><key>AssociatedBundleIdentifiers</key><string>io.gone.off</string>`)
	job(agents, "io.nobody", `<key>Program</key><string>`+prog+`</string>`)
	job(agents, "com.apple.x", `<key>Program</key><string>`+prog+`</string><key>AssociatedBundleIdentifiers</key><string>com.apple.x</string>`)
	got := launchdLeftovers(&ctx, NewInstalledApps(ctx.AppDirs, false))
	if len(got) != 2 {
		t.Fatalf("two: %v", got)
	}
	if v := got["io.gone.vpn"]; v == nil || !v.daemon || !v.starts || len(v.items) != 1 || !strings.HasSuffix(v.items[0], "io.gone.vpn.helper.plist") {
		t.Errorf("daemon: %+v", v)
	}
	if v := got["io.gone.one"]; v == nil || v.daemon || !v.starts {
		t.Errorf("agent: %+v", v)
	}
}

func TestPermissionRuleFoldsLoginItemsIntoTheApp(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	db := filepath.Join(root, "TCC.db")
	sql := `CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER);
		INSERT INTO access VALUES ('kTCCServiceCamera', 'io.gone.meet', 0, 2);
		INSERT INTO access VALUES ('kTCCServiceAddressBook', 'io.gone.crm', 0, 2);
		INSERT INTO access VALUES ('kTCCServiceSystemPolicyAppBundles', 'io.gone.updater', 0, 2);`
	if out, err := exec.Command("/usr/bin/sqlite3", db, sql).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	btm := filepath.Join(root, "btm")
	apps := filepath.Join(home, "Applications")
	writeArchive(t, btm, []testItem{
		{name: "Gone Meet", id: "2.io.gone.meet", url: fileURL(filepath.Join(apps, "Gone Meet.app")) + "/", bundle: "IO.gone.meet", typ: btmApp, disp: 3},
		{name: "Gone Sync", id: "2.io.gone.sync", url: fileURL(filepath.Join(apps, "Gone Sync.app")) + "/", bundle: "io.gone.sync", typ: btmApp, disp: 3},
		{name: "Gone Sync Daemon", id: "16.io.gone.sync.d", container: "2.io.gone.sync", bundle: "io.gone.sync.d", typ: btmDaemon, disp: 3},
	})
	ctx := Context{Home: home, TCCDatabases: []string{db}, BackgroundItems: btm, AppDirs: []string{apps}}
	found, err := (&PermissionRule{}).Run(&ctx)
	if err != nil || len(found) != 4 {
		t.Fatalf("%v %v", found, err)
	}
	by := map[string]Finding{}
	for _, f := range found {
		by[f.Path] = f
	}
	meet := by["io.gone.meet"]
	if meet.Title != "io.gone.meet 已经不在这台 Mac 上，还拿着「摄像头」，还在「登录项」里" || meet.Evidence["grants"] != "摄像头、登录项" ||
		meet.Evidence["app"] != "Gone Meet" || meet.Evidence["login_items"] != "Gone Meet" || meet.Severity != Low ||
		meet.Evidence["settings"] != "x-apple.systempreferences:com.apple.preference.security?Privacy_Camera "+LoginItemsURL ||
		!strings.Contains(meet.Evidence["how"], "登录项与扩展") {
		t.Errorf("meet: %+v", meet)
	}
	sync := by["io.gone.sync"]
	// Only in the archive: its daemon's program went with the app, nothing starts; only the switch is left.
	if sync.Title != "io.gone.sync 已经不在这台 Mac 上，还在「登录项」里" || sync.Evidence["grants"] != "登录项" || sync.Severity != Low ||
		sync.Evidence["login_items"] != "Gone Sync、Gone Sync Daemon" || sync.Evidence["hint"] != "系统设置里还留着它的开关" {
		t.Errorf("sync: %+v", sync)
	}
	if crm := by["io.gone.crm"]; crm.Evidence["grants"] != "通讯录" || crm.Severity != Low ||
		crm.Evidence["settings"] != "x-apple.systempreferences:com.apple.preference.security?Privacy_Contacts" {
		t.Errorf("crm: %+v", crm)
	}
	if up := by["io.gone.updater"]; up.Evidence["grants"] != "App 管理" || up.Severity != Medium ||
		up.Evidence["settings"] != "x-apple.systempreferences:com.apple.preference.security?Privacy" {
		t.Errorf("updater: %+v", up)
	}

	// Not known which user this is: no background item is said to be theirs.
	found, _ = (&PermissionRule{UserUUID: func() string { return "" }}).Run(&ctx)
	for _, f := range found {
		if f.Evidence["login_items"] != "" {
			t.Errorf("no user: %+v", f)
		}
	}
	// Another user's: not this one's; the system's (root) are.
	found, _ = (&PermissionRule{UserUUID: func() string { return "11111111-2222-3333-4444-555555555555" }}).Run(&ctx)
	for _, f := range found {
		if f.Evidence["login_items"] != "" {
			t.Errorf("another user: %+v", f)
		}
	}

	// TCC unreadable, and something left in Login Items: that is said, and that the rest was not read.
	bad := filepath.Join(root, "bad.db")
	os.WriteFile(bad, []byte("not a database"), 0o644)
	ctx.TCCDatabases = []string{bad}
	found, err = (&PermissionRule{}).Run(&ctx)
	if err != nil || len(found) != 3 || found[2].Rule != "permission.partial" || found[0].Evidence["grants"] != "登录项" {
		t.Fatalf("TCC unreadable: %v %v", found, err)
	}
	// Access switched off: the archive is left alone as TCC is, and the round says it did not look.
	ctx.AccessOff = true
	if found, err := (&PermissionRule{}).Run(&ctx); err == nil || len(found) != 0 {
		t.Errorf("access off: %v %v", found, err)
	}
	// Nothing in Login Items either: not looked at, as before.
	ctx.AccessOff, ctx.BackgroundItems = false, ""
	if _, err := (&PermissionRule{}).Run(&ctx); err == nil {
		t.Error("TCC unreadable and no archive: skipped")
	}
}

func TestEveryGrantHasItsSettingsPage(t *testing.T) {
	for svc, g := range grantNames {
		if GrantSettingsURL(g) == "" {
			t.Errorf("%s (%s): no page", g, svc)
		}
	}
	if GrantSettingsURL(LoginItemsGrant) != LoginItemsURL {
		t.Error("login items")
	}
}
