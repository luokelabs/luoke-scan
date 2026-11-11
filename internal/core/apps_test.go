package core

import (
	"reflect"
	"testing"
)

// The cases of the Swift version's unit tests (MoreRulesTests, CleanupEvalTests, PersistenceTests) for the helpers of
// the apps group; the rules themselves are checked from outside (blackbox/).

func TestBundleIDs(t *testing.T) {
	if !LooksLikeBundleID("io.example.App") || LooksLikeBundleID("Google") || LooksLikeBundleID("example.app") {
		t.Error("LooksLikeBundleID")
	}
	for name, want := range map[string]string{"io.example.x.plist": "io.example.x", "io.example.x.savedState": "io.example.x",
		"2BUA8C4S2C.com.agilebits.x": "com.agilebits.x", "group.net.whatsapp.WhatsApp.shared": "net.whatsapp.WhatsApp.shared",
		"Google": ""} {
		if got := LeftoverBundleID(name); got != want {
			t.Errorf("LeftoverBundleID(%q) = %q, want %q", name, got, want)
		}
	}
	if AppVendor("com.agilebits.onepassword7") != "com.agilebits" {
		t.Error("AppVendor")
	}
	if !VendorInstalled("solo", nil) || !VendorInstalled("io.vendor.app", []string{"io.vendor.helper"}) || VendorInstalled("io.vendor.app", []string{"io.other.x"}) {
		t.Error("VendorInstalled")
	}
}

func TestPathExtension(t *testing.T) {
	for p, want := range map[string]string{"/a/Foo.app": "app", "/a/.profile": "", "/a/x.tar.gz": "gz", "/a/noext": "", "/a/dot.": ""} {
		if got := PathExtension(p); got != want {
			t.Errorf("PathExtension(%q) = %q, want %q", p, got, want)
		}
	}
	if NameWithoutExtension("/a/Lumen-2.4.1-arm64.dmg") != "Lumen-2.4.1-arm64" || NameWithoutExtension("/a/.profile") != ".profile" {
		t.Error("NameWithoutExtension")
	}
}

func TestInstallerNames(t *testing.T) {
	var apps []InstalledApp
	for _, n := range []string{"Firefox", "Google Chrome", "Docker", "Slack", "Notion", "Go"} {
		apps = append(apps, InstalledApp{Name: n, Path: "/Applications/" + n + ".app"})
	}
	apps = append(apps, InstalledApp{Name: "Photos", Path: "/System/Applications/Photos.app"},
		InstalledApp{Name: "Keynote", Path: "/Applications/Keynote.app", BundleID: "com.apple.iWork.Keynote"},
		InstalledApp{Name: "Xcode", Path: "/Applications/Xcode.app", BundleID: "com.apple.dt.Xcode"},
		InstalledApp{Name: "Claude", Path: "/Users/x/Applications/Claude.app", WebShim: true})
	exact := func(n string) string {
		a, _ := ExactApp(n, apps)
		return a.Name
	}
	for n, want := range map[string]string{"Firefox 131.0.dmg": "Firefox", "Firefox 131.0 (1).dmg": "Firefox", "googlechrome.dmg": "Google Chrome",
		"Docker-arm64.dmg": "Docker", "Slack-4.41.105-macOS.dmg": "Slack", "NotionCalendar-1.2.dmg": "",
		"Firefox Developer Edition 132.0b5.dmg": "", "Go-1.22.dmg": "", "Photos.dmg": "", "Keynote.dmg": "",
		"Xcode_16.1.xip": "Xcode", "Xcode.dmg": "", "Claude.dmg": ""} {
		if got := exact(n); got != want {
			t.Errorf("ExactApp(%q) = %q, want %q", n, got, want)
		}
	}
	for n, want := range map[string]string{"Firefox 132.0b5.dmg": "132.0b5", "Firefox 131.0.dmg": "131.0", "Slack-4.41.105-macOS.dmg": "4.41.105",
		"Xcode_16.1.xip": "16.1", "Docker-arm64.dmg": "", "Firefox 131.dmg": "131", "Harbor Setup 3.pkg": "3", "v2.0-tool.dmg": "2.0"} {
		if got := InstallerVersion(n); got != want {
			t.Errorf("InstallerVersion(%q) = %q, want %q", n, got, want)
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"4.41.105", "4.42", -1}, {"131.0", "131", 0}, {"132.0", "131.0.3", 1}, {"beta", "1.0", VersionsIncomparable}} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if got := installedAppFor("LumenSync-1.2.dmg", []string{"Lumen", "Go", "LumenSync"}); got != "LumenSync" {
		t.Errorf("installedAppFor = %q", got)
	}
}

func TestCronAndPath(t *testing.T) {
	cron := cronEntries("SHELL=/bin/sh\n# x\n*/10 * * * * /usr/local/bin/sync --all\n@daily backup.sh\n1 2 3\n0\t4\t*\t*\t*\t/opt/x/run\n")
	var schedules, programs []string
	for _, e := range cron {
		schedules, programs = append(schedules, e.schedule), append(programs, e.program)
	}
	if !reflect.DeepEqual(schedules, []string{"*/10 * * * *", "@daily", "0 4 * * *"}) || !reflect.DeepEqual(programs, []string{"/usr/local/bin/sync", "", "/opt/x/run"}) {
		t.Errorf("cronEntries: %v %v", schedules, programs)
	}
	p := pathEntries("export PATH='/a/b:~/c':$PATH\nfoo; PATH=/d $cmd\npath=(/e $path)\nPATH=.:$PATH\n", "/Users/x")
	var dirs []string
	var lines []int
	for _, e := range p {
		dirs, lines = append(dirs, e.dir), append(lines, e.line)
	}
	if !reflect.DeepEqual(dirs, []string{"/a/b", "/Users/x/c", "/d", "/e", "."}) || !reflect.DeepEqual(lines, []int{1, 1, 2, 3, 4}) {
		t.Errorf("pathEntries: %v %v", dirs, lines)
	}
}

func TestLaunchctlText(t *testing.T) {
	list := "gui/501 = {\n\ttype = login\n\tservices = {\n\t\t501\t0\tio.example.a\n\t\t-\t0\tio.example.b\n\t}\n\tother = 1\n}\n"
	if got := serviceMap(list); !reflect.DeepEqual(got, map[string]string{"io.example.a": "501", "io.example.b": "-"}) {
		t.Errorf("serviceMap = %v", got)
	}
	job := ParseSessionJob("io.example", "io.example = {\n\tpath = /x/y.plist\n\tparent bundle identifier = io.example.app\n\tinherited environment = {\n\t\tpath = /no\n\t}\n}\n")
	if job != (SessionJob{Label: "io.example", Path: "/x/y.plist", ParentBundle: "io.example.app"}) {
		t.Errorf("ParseSessionJob = %+v", job)
	}
	items := sessionItems([]SessionJob{{Label: "com.apple.x", Path: "/System/Library/LaunchAgents/x.plist"},
		{Label: "io.example.byhand", Path: "/tmp/byhand.plist", Program: "/bin/sh"}, {Label: "io.example.registered", ParentBundle: "io.example.ex"},
		{Label: "io.example.sys", Program: "/usr/bin/true"}},
		func(id string) string {
			if id == "io.example.ex" {
				return "/Applications/Ex.app"
			}
			return ""
		})
	if len(items) != 2 || items[0].source != "io.example.byhand" || items[1].name != "Ex" || items[1].program != "/Applications/Ex.app" ||
		items[1].app != "Ex" || items[0].app != "" || items[0].submitted || items[1].submitted {
		t.Errorf("sessionItems = %+v", items)
	}
}

// A job a running app handed to launchd (SMJobSubmit, `launchctl submit`): launchctl names the process that submitted
// it in place of a plist. It belongs to that app; one submitted by hand from a terminal names no one.
func TestSubmittedJob(t *testing.T) {
	job := ParseSessionJob("io.example-progress", "io.example-progress = {\n\tactive count = 1\n\tpath = (submitted by Example App[56907])\n\ttype = Submitted\n\tprogram = /Users/x/Library/Caches/io.example/Updater.app/Contents/MacOS/Updater\n\tresource coalition = {\n\t\ttype = resource\n\t}\n}\n")
	want := SessionJob{Label: "io.example-progress", Path: "(submitted by Example App[56907])", SubmittedBy: "Example App",
		Program: "/Users/x/Library/Caches/io.example/Updater.app/Contents/MacOS/Updater"}
	if job != want {
		t.Errorf("ParseSessionJob = %+v", job)
	}
	byHand := ParseSessionJob("x", "x = {\n\tpath = (submitted by launchctl[1])\n\tprogram = /Users/x/bin/x\n}\n")
	items := sessionItems([]SessionJob{job, byHand}, func(string) string { return "" })
	if len(items) != 2 || items[0].app != "Example App" || !items[0].submitted || items[0].name != "io.example-progress" ||
		items[1].app != "" || !items[1].submitted {
		t.Errorf("sessionItems = %+v", items)
	}
}

func TestCommandProgram(t *testing.T) {
	for cmd, want := range map[string]string{"/usr/local/bin/start --token abc": "start", "TOKEN=abc123 env X=1 helper-cli --serve": "helper-cli",
		"env -i": "?"} {
		if got := commandProgram(cmd); got != want {
			t.Errorf("commandProgram(%q) = %q, want %q", cmd, got, want)
		}
	}
}
