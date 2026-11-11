package core

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

// AutoKind is one of the four kinds that may go without a click, then be put back from the Trash (ADR 0016, 10-27).
type AutoKind string

const (
	// AutoCache is a cache its tool rebuilds (KnownCaches).
	AutoCache AutoKind = "cache"
	// AutoInstaller is an installer, two weeks in Downloads, of an app installed at that version or newer.
	AutoInstaller AutoKind = "installer"
	// AutoDuplicate is a copy in Downloads of a file also kept outside Downloads.
	AutoDuplicate AutoKind = "duplicate"
	// AutoTemp is a throwaway folder a known tool leaves in the temp folder (browser profiles of test runs).
	AutoTemp AutoKind = "temp"
)

// AutoKinds in the order they are told.
var AutoKinds = []AutoKind{AutoCache, AutoInstaller, AutoDuplicate, AutoTemp}

// Label is what the user reads.
func (k AutoKind) Label() string {
	switch k {
	case AutoCache:
		return "会重建的缓存"
	case AutoInstaller:
		return "装好了的应用的安装包"
	case AutoDuplicate:
		return "下载文件夹里的重复文件"
	case AutoTemp:
		return "测试工具留下的临时文件夹"
	}
	return string(k)
}

// AutoHow is how an AutoItem goes.
type AutoHow string

const (
	// HowTool: a cache whose tool has a clean command of its own and is installed. Only told as such: the folder is
	// deleted by this program all the same (running the tool's command would run whatever is found under that name).
	HowTool AutoHow = "tool"
	// HowRemove: deleted (a cache folder; its tool rebuilds it).
	HowRemove AutoHow = "remove"
	// HowTrash: moved to the Trash, from where it can be put back.
	HowTrash AutoHow = "trash"
)

// AutoItem is one thing automatic cleaning would take: exactly this file or folder.
type AutoItem struct {
	Bytes     int64    `json:"bytes"`
	FindingID string   `json:"findingID"`
	How       AutoHow  `json:"how"`
	Kind      AutoKind `json:"kind"`
	Path      string   `json:"path"`
	Rule      string   `json:"rule"`
}

// AutoPick picks, from a round's findings, what may be cleaned without asking: only the four kinds, only by rules (no
// model), and for each only what is surely not needed. A finding that could be wrong about any of its targets gives
// none of them. Measured by the cleanup eval: automatic cleaning is on only while no case there is picked wrongly.
type AutoPick struct {
	Home string
	Tmp  string // "" none
	Now  time.Time
	// Running are the names of the programs running now: a cache in use is left for the next round.
	Running map[string]bool
	// Off are kinds the user turned off, or put something back from.
	Off map[AutoKind]bool
	// Ignored are ids of findings the user said "以后别提" to.
	Ignored map[string]bool
	// DuplicateQuiet: a copy in Downloads younger than this stays.
	DuplicateQuiet time.Duration
	// TempQuiet: a temp folder written to within this stays.
	TempQuiet time.Duration
	// MinFree: below this a copy frees too little to take.
	MinFree int64
	// Added is when a file came into its folder, else when it was made.
	Added func(string) (time.Time, bool)
	// CommandLines are this user's processes' command lines, lowercased; nil when they could not be read (then no temp
	// folder is taken). A temp folder named in one is in use.
	CommandLines *[]string
	// Installed says whether a tool's clean command is installed (marks the cache HowTool).
	Installed func(command, home string) bool
}

// AutoWaitForTool are prefixes whose folders wait while any process of their tool runs.
var AutoWaitForTool = map[string]bool{"playwright-artifacts": true}

// AutoKnownTemp are temp folder prefixes of tools that make a throwaway folder per run, and the tool
// (rules/temp-folders.json). Going without a click is autoTemp's.
var AutoKnownTemp map[string]string

// autoCaches are the caches (KnownCaches' ids) automatic cleaning may take, and autoTemp the temp folder prefixes
// (AutoKnownTemp): each reviewed by the project, with cases in the cleanup eval (evals/cleanup/) and none of them
// picked wrongly there. One only added to rules/ is reported and goes when the user clicks.
var (
	autoCaches = spaceSet("pip", "swiftpm", "go-build", "xcode-deriveddata", "cargo-registry-cache", "cargo-registry-src", "bun",
		"uv", "npm", "homebrew", "yarn", "cocoapods", "gradle-caches", "gradle-wrapper", "poetry-cache", "poetry-artifacts",
		"node-gyp", "composer", "xcode-documentation", "coresimulator-caches", "xctest-devices", "xcode-cache", "corepack")
	autoTemp = spaceSet("puppeteer_dev_chrome_profile", "puppeteer_dev_firefox_profile", "playwright_chromiumdev_profile",
		"playwright_firefoxdev_profile", "playwright-artifacts", "lighthouse")
)

// NewAutoPick is a picker with the defaults; running has no default (a caller that forgot it would clean caches in use).
func NewAutoPick(home, tmp string, now time.Time, running map[string]bool) AutoPick {
	empty := []string{}
	return AutoPick{Home: home, Tmp: tmp, Now: now, Running: running, Off: map[AutoKind]bool{}, Ignored: map[string]bool{},
		DuplicateQuiet: 7 * 24 * time.Hour, TempQuiet: 3 * 24 * time.Hour, MinFree: 1 << 20, Added: DateAdded,
		CommandLines: &empty, Installed: CommandExists}
}

// Pick is what may go, in the findings' order.
func (p AutoPick) Pick(findings []Finding) []AutoItem {
	var out []AutoItem
	seen := map[string]bool{} // one file can be in two findings
	for _, f := range findings {
		if p.Ignored[f.ID()] {
			continue
		}
		var items []AutoItem
		switch {
		case strings.HasPrefix(f.Rule, "cache.rebuildable."):
			items = p.cache(f)
		case f.Rule == "leftover.installer":
			items = p.installer(f)
		case f.Rule == "space.duplicates":
			items = p.duplicates(f)
		case f.Rule == "leak.temp-prefix":
			items = p.temp(f)
		}
		for _, it := range items {
			c := Canonical(it.Path)
			if p.Off[it.Kind] || seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, it)
		}
	}
	return out
}

func knownCache(rule string) (RebuildableCache, bool) {
	for _, c := range KnownCaches {
		if "cache.rebuildable."+c.ID == rule {
			return c, true
		}
	}
	return RebuildableCache{}, false
}

func (p AutoPick) cache(f Finding) []AutoItem {
	c, ok := knownCache(f.Rule)
	if f.Category != CatCache || f.Verdict != Safe || !ok || !autoCaches[c.ID] {
		return nil
	}
	at := filepath.Join(p.Home, c.Path)
	if f.Path != at || !Plain(at, "dir") || !CacheIdle(c.ID, p.Running) {
		return nil
	}
	if _, mounted := MountInside(at); mounted {
		return nil
	}
	how := HowRemove
	if c.Command != "" && p.Installed(c.Command, p.Home) {
		how = HowTool
	}
	bytes := AllocatedSize(at)
	if f.Bytes != nil {
		bytes = *f.Bytes
	}
	return []AutoItem{{Kind: AutoCache, Rule: f.Rule, FindingID: f.ID(), Path: at, Bytes: bytes, How: how}}
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// installer: only one from the internet (downloaded and signed) whose name is exactly an installed app's, and only
// when that app is at the installer's version or newer. A pre-release ("132.0b5") is not compared.
func (p AutoPick) installer(f Finding) []AutoItem {
	_, exact := f.Evidence["exact"]
	days, err := strconv.Atoi(f.Evidence["days"])
	if !exact || f.Evidence["downloaded"] != "1" || f.Evidence["signed"] != "1" || err != nil || days < 14 || !Plain(f.Path, "file") {
		return nil
	}
	if iv, has := f.Evidence["installer_version"]; has {
		av, hasApp := f.Evidence["app_version"]
		if !hasApp || hasLetter(iv) || hasLetter(av) {
			return nil
		}
		if c := CompareVersions(iv, av); c == VersionsIncomparable || c > 0 {
			return nil
		}
	}
	var bytes int64
	if f.Bytes != nil {
		bytes = *f.Bytes
	}
	return []AutoItem{{Kind: AutoInstaller, Rule: f.Rule, FindingID: f.ID(), Path: f.Path, Bytes: bytes, How: HowTrash}}
}

// duplicates: the copies in Downloads of a file kept outside Downloads; none when the kept one is in Downloads too or
// in a folder a build makes again, and not a copy that came or changed within DuplicateQuiet, or that is part of a
// project in Downloads.
func (p AutoPick) duplicates(f Finding) []AutoItem {
	downloads := Canonical(filepath.Join(p.Home, "Downloads"))
	inDownloads := func(x string) bool { return strings.HasPrefix(Canonical(x), downloads+"/") }
	if inDownloads(f.Path) || !Plain(f.Path, "file") || !Local(f.Path) || Regenerated(HomeRelative(f.Path, p.Home)) {
		return nil
	}
	quiet := p.Now.Add(-p.DuplicateQuiet)
	var out []AutoItem
	for _, t := range strings.Split(f.Evidence["targets"], "\n") {
		if t == "" || !inDownloads(t) || !Plain(t, "file") {
			continue
		}
		came, ok := p.Added(t)
		if !ok || came.After(quiet) {
			continue
		}
		m, ok := Modified(t)
		if !ok || m.After(quiet) || InProject(t, downloads) {
			continue
		}
		free, _ := PrivateBytes(t)
		if free < p.MinFree {
			continue
		}
		out = append(out, AutoItem{Kind: AutoDuplicate, Rule: f.Rule, FindingID: f.ID(), Path: t, Bytes: free, How: HowTrash})
	}
	return out
}

// temp: the folders of a known tool's prefix that nothing wrote to within TempQuiet, each on its own.
func (p AutoPick) temp(f Finding) []AutoItem {
	prefix, has := f.Evidence["prefix"]
	tool, known := AutoKnownTemp[prefix]
	if p.Tmp == "" || !has || !known || !autoTemp[prefix] || p.CommandLines == nil {
		return nil
	}
	lines := *p.CommandLines
	if AutoWaitForTool[prefix] {
		for _, l := range lines {
			if strings.Contains(l, strings.ToLower(tool)) {
				return nil
			}
		}
	}
	since := p.Now.Add(-p.TempQuiet)
	children := Children(p.Tmp)
	sort.Strings(children)
	var out []AutoItem
	for _, u := range children {
		named := []string{strings.ToLower(u), strings.ToLower(Canonical(u))}
		if pr, ok := TempLeakPrefix(filepath.Base(u)); !ok || pr != prefix {
			continue
		}
		if !Plain(u, "") || !Mine(u) || Changed(u, since, p.Now) || BrowserRunning(u) {
			continue
		}
		if _, mounted := MountInside(u); mounted {
			continue
		}
		used := false
		for _, l := range lines {
			for _, n := range named {
				if strings.Contains(l, n) {
					used = true
				}
			}
		}
		if used {
			continue
		}
		out = append(out, AutoItem{Kind: AutoTemp, Rule: f.Rule, FindingID: f.ID(), Path: u, Bytes: AllocatedSize(u), How: HowTrash})
	}
	return out
}

// regeneratedNames are folder names a build or a tool makes again.
var regeneratedNames = map[string]bool{"build": true, "builds": true, "dist": true, "out": true, "target": true, "tmp": true,
	"temp": true, "cache": true, "caches": true, ".build": true, "deriveddata": true, "node_modules": true, "__pycache__": true,
	".next": true, ".nuxt": true, "pods": true, "vendor": true, ".venv": true, "venv": true, "site-packages": true, ".gradle": true}

// Regenerated: a folder on the way (not the file itself) is one a build makes again.
func Regenerated(homeRelative string) bool {
	parts := strings.Split(homeRelative, "/")
	for _, p := range parts[:len(parts)-1] {
		if p != "" && regeneratedNames[strings.ToLower(p)] {
			return true
		}
	}
	return false
}

var projectMarkers = map[string]bool{".git": true, ".hg": true, ".svn": true, "package.json": true, "Cargo.toml": true,
	"go.mod": true, "pyproject.toml": true, "setup.py": true, "requirements.txt": true, "Package.swift": true, "Gemfile": true,
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "Makefile": true, "CMakeLists.txt": true,
	"composer.json": true, "mix.exs": true, "pubspec.yaml": true, "Podfile": true}

// InProject: a folder between top (not included) and the file holds a project marker or an Xcode project.
func InProject(file, top string) bool {
	d := Canonical(filepath.Dir(file))
	for strings.HasPrefix(d, top+"/") {
		for _, c := range Children(d) {
			name := filepath.Base(c)
			ext := filepath.Ext(name)
			if projectMarkers[name] || ext == ".xcodeproj" || ext == ".xcworkspace" {
				return true
			}
		}
		d = filepath.Dir(d)
	}
	return false
}

// BrowserRunning: a browser still runs on this profile folder. Chrome's SingletonLock and Firefox's lock are links
// to "<host>-<pid>" / "<address>:+<pid>" while it runs, and Firefox holds an fcntl lock on .parentlock. A lock whose
// pid cannot be read counts as running.
func BrowserRunning(dir string) bool {
	if fd, err := syscall.Open(filepath.Join(dir, ".parentlock"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0); err == nil {
		lk := syscall.Flock_t{Type: syscall.F_RDLCK, Whence: 0}
		err := syscall.FcntlFlock(uintptr(fd), syscall.F_GETLK, &lk)
		syscall.Close(fd)
		if err != nil || lk.Type != syscall.F_UNLCK {
			return true
		}
	}
	for _, name := range []string{"SingletonLock", "lock"} {
		to, err := os.Readlink(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		runs := strings.FieldsFunc(to, func(r rune) bool { return !unicode.IsDigit(r) })
		if len(runs) == 0 {
			return true
		}
		pid, err := strconv.Atoi(runs[len(runs)-1])
		if err != nil || pid <= 0 || pid > 1<<31-1 {
			return true
		}
		if e := syscall.Kill(pid, 0); e == nil || e == syscall.EPERM {
			return true
		}
	}
	return false
}

// Plain: there, not a link, and a folder ("dir"), a regular file ("file") or either ("").
func Plain(path, kind string) bool {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil {
		return false
	}
	t := st.Mode & syscall.S_IFMT
	switch kind {
	case "dir":
		return t == syscall.S_IFDIR
	case "file":
		return t == syscall.S_IFREG
	}
	return t == syscall.S_IFDIR || t == syscall.S_IFREG
}

// Local: kept on this Mac (not only in iCloud, where it could be evicted any time).
func Local(path string) bool {
	var st syscall.Stat_t
	return syscall.Lstat(path, &st) == nil && st.Flags&sfDataless == 0
}

// Mine: this user's.
func Mine(path string) bool {
	var st syscall.Stat_t
	return syscall.Lstat(path, &st) == nil && int(st.Uid) == os.Getuid()
}
