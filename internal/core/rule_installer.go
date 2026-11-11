package core

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

// InstallLeftoverRule: what installing and upgrading leave behind besides an app's own data (LeftoverRule):
// installers still in Downloads long after they were used, downloads that never finished, the folders macOS upgrades
// fill in /Users/Shared ("Relocated Items"), and an Intel Homebrew in /usr/local on an Apple silicon Mac.
// Swift: Rules/InstallLeftoverRule.swift.
type InstallLeftoverRule struct {
	// Quiet: an installer that came longer ago than this has done its job.
	Quiet    time.Duration
	MinBytes int64
	// PartialQuiet: a download nothing was written to for this long has stopped.
	PartialQuiet    time.Duration
	MinPartialBytes int64
	Shared          string
	UsrLocal        string
	OptHomebrew     string
	// Trash is the user's Trash, where an Intel Homebrew moved there may still be put back from ("": the home's .Trash).
	Trash string
	// AppleSilicon: this Mac's chip.
	AppleSilicon func() bool
	// Running are the programs running now: one inside the Intel Homebrew keeps it from going.
	Running func() []string
	// Crontab is the user's crontab; ok false when it cannot be read.
	Crontab func() (string, bool)
	// AttachedImages are the disk images attached now, by image path (canonical): an installer that is open is not done with.
	AttachedImages func() map[string]bool
	// Signed: an installer carries a code signature (a disk image) or an installer signature (pkg, xip).
	Signed func(path string) bool
	// Added is when a file came into its folder, else when it was made.
	Added func(path string) (time.Time, bool)
}

func init() { Register("leftover.installer", NewInstallLeftoverRule) }

// NewInstallLeftoverRule is the rule for this Mac (l nil) or a fake home: there nothing of the real Mac's
// /Users/Shared, /usr/local or attached images.
func NewInstallLeftoverRule(l *Layout, f *Fakes) Rule {
	r := &InstallLeftoverRule{Quiet: 14 * 24 * time.Hour, MinBytes: 5 << 20, PartialQuiet: 7 * 24 * time.Hour, MinPartialBytes: 1 << 20,
		Shared: "/Users/Shared", UsrLocal: "/usr/local", OptHomebrew: "/opt/homebrew",
		AppleSilicon: func() bool {
			v, err := syscall.SysctlUint32("hw.optional.arm64")
			return err == nil && v == 1
		},
		Running: runningPrograms, Crontab: ReadCrontab, AttachedImages: attachedImages, Signed: InstallerSigned, Added: DateAdded}
	if l != nil {
		r.Shared = filepath.Join(l.Root, "Shared")
		r.UsrLocal = filepath.Join(l.Root, "usr-local")
		r.OptHomebrew = filepath.Join(l.Root, "opt-homebrew")
		r.Trash = filepath.Join(l.Root, "Trash") // where the service's tests put what goes
		r.AppleSilicon = func() bool { return f.AppleSilicon }
		images := map[string]bool{}
		for _, p := range f.AttachedImages {
			images[p] = true
		}
		r.AttachedImages = func() map[string]bool { return images }
		running := append([]string{}, f.Running...)
		r.Running = func() []string { return running }
		r.Crontab = fakeCrontab(f)
	}
	return r
}

func (r *InstallLeftoverRule) ID() string { return "leftover.installer" }
func (r *InstallLeftoverRule) Emits() []string {
	return []string{"leftover.installer", "leftover.relocated-items", "leftover.intel-homebrew", "leftover.intel-homebrew-links",
		"leftover.partial-download"}
}

// InstallerExtensions are what installers come as.
var InstallerExtensions = map[string]bool{"dmg": true, "pkg": true, "mpkg": true, "xip": true}

// PartialExtensions are what browsers write while downloading: Chrome and Edge .crdownload, Firefox .part, Safari a
// .download folder, Opera .opdownload, others .partial.
var PartialExtensions = map[string]bool{"crdownload": true, "part": true, "partial": true, "download": true, "opdownload": true}

func (r *InstallLeftoverRule) Run(ctx *Context) ([]Finding, error) {
	downloads := ctx.MayLook(filepath.Join(ctx.Home, "Downloads"))
	var out []Finding
	if downloads {
		out = append(r.installers(ctx), r.partialDownloads(ctx)...)
	}
	if f, ok := r.relocated(); ok {
		out = append(out, f)
	}
	out = append(out, r.intelHomebrew(ctx)...)
	if !downloads {
		return nil, Skip(NotLooked("下载文件夹里的安装包和没下完的下载"), out...)
	}
	return out, nil
}

// downloadCandidates are the files in Downloads (and one folder down, not into packages) with one of exts.
func downloadCandidates(home string, exts map[string]bool) []string {
	var out []string
	for _, u := range Children(filepath.Join(home, "Downloads")) {
		if exts[strings.ToLower(PathExtension(u))] {
			out = append(out, u)
			continue
		}
		if e, ok := Item(u); ok && e.IsDir && !IsPackage(u) {
			for _, c := range Children(u) {
				if exts[strings.ToLower(PathExtension(c))] {
					out = append(out, c)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// installers in Downloads (and one folder down) that came at least Quiet ago and are not attached.
func (r *InstallLeftoverRule) installers(ctx *Context) []Finding {
	candidates := downloadCandidates(ctx.Home, InstallerExtensions)
	if len(candidates) == 0 {
		return nil
	}
	apps := AppList(ctx.AppDirs)
	names := make([]string, len(apps))
	for i, a := range apps {
		names[i] = a.Name
	}
	var attached map[string]bool
	var out []Finding
	for _, u := range candidates {
		e, ok := Item(u)
		if !ok || e.IsLink {
			continue
		}
		came, ok := r.Added(u)
		if !ok || ctx.Now.Sub(came) < r.Quiet {
			continue
		}
		bytes := AllocatedSize(u)
		if bytes < r.MinBytes {
			continue
		}
		if strings.ToLower(PathExtension(u)) == "dmg" {
			if attached == nil {
				attached = r.AttachedImages()
			}
			if attached[Canonical(u)] {
				continue
			}
		}
		name := filepath.Base(u)
		app := installedAppFor(name, names)
		days := strconv.Itoa(int(ctx.Now.Sub(came).Seconds() / 86400))
		ev := map[string]string{"added": ISODay(came), "days": days, "how": "装好了就用不到安装包了；想留着这个版本以后重装的，就留着"}
		if app != "" {
			ev["installed"] = app
		}
		// What automatic cleaning goes by (AutoPick): the name is exactly that app's, the versions, and that it is an
		// installer from the internet (downloaded, signed) rather than a disk image of the user's.
		if exact, ok := ExactApp(name, apps); ok {
			ev["exact"] = exact.Name
			if exact.Version != "" {
				ev["app_version"] = exact.Version
			}
		}
		if v := InstallerVersion(name); v != "" {
			ev["installer_version"] = v
		}
		if Quarantined(u) {
			ev["downloaded"] = "1"
			ev["signed"] = "0"
			if r.Signed(u) {
				ev["signed"] = "1"
			}
		}
		title := "下载文件夹里 " + days + " 天前的安装包 " + DisplayName(u)
		if app != "" {
			title += "（" + app + " 已经装好了）"
		}
		out = append(out, Finding{Rule: "leftover.installer", Category: CatLeftover, Severity: Low, Verdict: Confirm, Path: u,
			Bytes: Size(bytes), Title: title, Evidence: ev})
	}
	return out
}

// distantPastUnix is Foundation's Date.distantPast, for a walk that saw no time up to now.
const distantPastUnix = -62135769600

// partialDownloads that never finished, in Downloads (and one folder down), not written to for PartialQuiet.
func (r *InstallLeftoverRule) partialDownloads(ctx *Context) []Finding {
	since := ctx.Now.Add(-r.PartialQuiet)
	var out []Finding
	for _, u := range downloadCandidates(ctx.Home, PartialExtensions) {
		e, ok := Item(u)
		if !ok || e.IsLink {
			continue
		}
		bytes, ok := SizeUnlessChanged(u, since, ctx.Now)
		if !ok || bytes < r.MinPartialBytes {
			continue
		}
		facts, _ := WalkFacts(u, ctx.Now, nil)
		last := facts.Newest
		if last.IsZero() {
			last = time.Unix(distantPastUnix, 0)
		}
		days := int(float64(ctx.Now.Unix()-last.Unix()) / 86400)
		name := NameWithoutExtension(u)
		if name == "" {
			name = filepath.Base(u)
		}
		name = DisplayName(name)
		out = append(out, Finding{Rule: "leftover.partial-download", Category: CatLeftover, Severity: Low, Verdict: Confirm, Path: u,
			Bytes: Size(bytes), Title: "没下完的下载 " + name + "（" + FormatBytes(bytes) + "），" + strconv.Itoa(days) + " 天没动了",
			Evidence: map[string]string{"how": "浏览器下到一半停了（暂停或失败）；还要的话重新下载，不要就删掉", "last_changed": ISODay(last)}})
	}
	return out
}

// InstalledApp is an app with what its Info.plist says.
type InstalledApp struct {
	Name, Path, BundleID, Version string
	// WebShim: a web page made into an app (Safari's "Add to Dock", a Chrome or Edge web app): not installed from anything.
	WebShim bool
}

// AppList are the apps in dirs (and one folder down).
func AppList(dirs []string) []InstalledApp {
	var urls []string
	for _, d := range dirs {
		for _, u := range Children(d) {
			if PathExtension(u) == "app" {
				urls = append(urls, u)
				continue
			}
			for _, c := range Children(u) {
				if PathExtension(c) == "app" {
					urls = append(urls, c)
				}
			}
		}
	}
	out := make([]InstalledApp, 0, len(urls))
	for _, u := range urls {
		info := ReadPlistDict(filepath.Join(u, "Contents/Info.plist"))
		id, hasID := info["CFBundleIdentifier"].(string)
		_, shortcut := info["CrAppModeShortcutID"]
		version, ok := info["CFBundleShortVersionString"].(string)
		if !ok {
			version, _ = info["CFBundleVersion"].(string)
		}
		out = append(out, InstalledApp{Name: NameWithoutExtension(u), Path: u, BundleID: id, Version: version,
			WebShim: shortcut || (hasID && strings.HasPrefix(id, "com.apple.Safari.WebApp"))})
	}
	return out
}

// installerWords are words an installer's name may carry besides the app's name: chips, systems, "setup".
var installerWords = map[string]bool{"arm64": true, "aarch64": true, "x64": true, "x86": true, "amd64": true, "intel": true,
	"universal": true, "apple": true, "silicon": true, "applesilicon": true, "mac": true, "macos": true, "osx": true, "darwin": true,
	"setup": true, "installer": true, "install": true, "latest": true, "stable": true, "release": true, "signed": true}

var versionPiece = regexp.MustCompile(`^v?[0-9]+[a-z]*[0-9]*$`)

// stripPathExtension is NSString.deletingPathExtension of a file name.
func stripPathExtension(name string) string {
	if e := PathExtension(name); e != "" {
		return name[:len(name)-len(e)-1]
	}
	return name
}

// ExactApp is the installed app an installer is exactly for: its name is the app's name and nothing more than a
// version, a chip, a system or "setup" ("Firefox 131.0", "googlechrome", "Docker-arm64", "Slack-4.41.105-macOS").
// Names of four letters or more only. Not Apple's apps (except from a .xip, how Xcode comes), not web pages made into apps.
func ExactApp(installer string, apps []InstalledApp) (InstalledApp, bool) {
	base := strings.ToLower(stripPathExtension(installer))
	words := strings.FieldsFunc(base, func(r rune) bool { return !(unicode.IsLetter(r) || unicode.IsNumber(r)) })
	var kept []string
	for _, w := range words {
		if !installerWords[w] && !versionPiece.MatchString(w) {
			kept = append(kept, w)
		}
	}
	name := strings.Join(kept, "")
	if appsRuneCount(lettersOf(name)) < 4 {
		return InstalledApp{}, false
	}
	xip := strings.ToLower(PathExtension(installer)) == "xip"
	for _, a := range apps {
		if !strings.HasPrefix(a.Path, "/System/") && !a.WebShim && (xip || !strings.HasPrefix(a.BundleID, "com.apple.")) &&
			lettersOf(a.Name) == lettersOf(name) && name == lettersOf(name) {
			return a, true
		}
	}
	return InstalledApp{}, false
}

func appsRuneCount(s string) int { return len([]rune(s)) }

// InstallerSigned: a disk image with a code signature (codesign -d), or a pkg or xip with an installer signature
// (pkgutil --check-signature).
func InstallerSigned(path string) bool {
	if strings.ToLower(PathExtension(path)) == "dmg" {
		return Run("/usr/bin/codesign", []string{"-d", path}, RunOpts{Timeout: 20 * time.Second}).Status == 0
	}
	return Run("/usr/sbin/pkgutil", []string{"--check-signature", path}, RunOpts{Timeout: 20 * time.Second}).Status == 0
}

var (
	installerVersionRE = regexp.MustCompile(`^v?([0-9]+(?:[._][0-9]+)+[A-Za-z]*[0-9]*)`)
	digitRun           = regexp.MustCompile(`^[0-9]+`)
)

func installerAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// InstallerVersion is the version in an installer's name: "Firefox 131.0" → 131.0, "Slack-4.41.105-macOS" → 4.41.105;
// else a lone number ("Firefox 131"). Not the digits of a chip ("arm64"); a pre-release keeps its letters ("132.0b5").
func InstallerVersion(installer string) string {
	base := stripPathExtension(installer)
	clean := func(s string) string { return strings.ReplaceAll(strings.Trim(s, "vV"), "_", ".") }
	// (?<![A-Za-z0-9])v?([0-9]+(?:[._][0-9]+)+[A-Za-z]*[0-9]*)
	for i := 0; i < len(base); i++ {
		if i > 0 && installerAlnum(base[i-1]) {
			continue
		}
		if m := installerVersionRE.FindString(base[i:]); m != "" {
			return clean(m)
		}
	}
	// (?<![A-Za-z0-9.])([0-9]+)(?![A-Za-z0-9.])
	for i := 0; i < len(base); i++ {
		if i > 0 && (installerAlnum(base[i-1]) || base[i-1] == '.') {
			continue
		}
		m := digitRun.FindString(base[i:])
		if m == "" {
			continue
		}
		if j := i + len(m); j < len(base) && (installerAlnum(base[j]) || base[j] == '.') {
			continue
		}
		return clean(m)
	}
	return ""
}

// VersionsIncomparable is what CompareVersions answers when either has no number (Swift's nil): neither -1 nor ≤ 0.
const VersionsIncomparable = 2

// CompareVersions compares dotted versions number by number ("4.41.105" < "4.42"): -1, 0 or 1, or
// VersionsIncomparable when either has no number.
func CompareVersions(a, b string) int {
	nums := func(s string) []int {
		var out []int
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsNumber(r) }) {
			if n, err := strconv.Atoi(p); err == nil {
				out = append(out, n)
			}
		}
		return out
	}
	x, y := nums(a), nums(b)
	if len(x) == 0 || len(y) == 0 {
		return VersionsIncomparable
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		p, q := 0, 0
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			if p < q {
				return -1
			}
			return 1
		}
	}
	return 0
}

// installedAppFor is the installed app an installer is for, by name: "Firefox 131.0.dmg", "googlechrome.dmg". Only
// names of four letters or more; the longest that the installer's name starts with.
func installedAppFor(installer string, apps []string) string {
	name := lettersOf(stripPathExtension(installer))
	best, bestLen := "", -1
	for _, a := range apps {
		l := lettersOf(a)
		if n := appsRuneCount(l); n >= 4 && strings.HasPrefix(name, l) && n > bestLen {
			best, bestLen = a, n
		}
	}
	return best
}

// relocated: "Relocated Items" and "Previously Relocated Items…", what a macOS upgrade moved aside because it did not
// recognise it. Owned by root, so only reported.
func (r *InstallLeftoverRule) relocated() (Finding, bool) {
	var dirs []string
	for _, u := range Children(r.Shared) {
		n := filepath.Base(u)
		if e, ok := Item(u); ok && e.IsDir && (n == "Relocated Items" || strings.HasPrefix(n, "Previously Relocated Items")) {
			dirs = append(dirs, u)
		}
	}
	if len(dirs) == 0 {
		return Finding{}, false
	}
	sort.Slice(dirs, func(i, j int) bool { return filepath.Base(dirs[i]) < filepath.Base(dirs[j]) })
	var bytes int64
	var oldest time.Time
	names := []string{}
	for i, d := range dirs {
		bytes += AllocatedSize(d)
		if m, ok := Modified(d); ok && (oldest.IsZero() || m.Before(oldest)) {
			oldest = m
		}
		if i < 20 {
			names = append(names, filepath.Base(d))
		}
	}
	old := ""
	if !oldest.IsZero() {
		old = ISODay(oldest)
	}
	return Finding{Rule: "leftover.relocated-items", Category: CatLeftover, Severity: Low, Verdict: Info, Path: r.Shared, Bytes: Size(bytes),
		Title: "macOS 升级时挪出来的旧配置：" + strconv.Itoa(len(dirs)) + " 个文件夹（" + FormatBytes(bytes) + "）",
		Evidence: map[string]string{"folders": strings.Join(names, "；"), "oldest": old,
			"why": "升级时 macOS 把认不出的旧配置文件挪到这里，升级以后系统不再用它们",
			"how": "看过里面没有你要的，在访达里把这些文件夹移到废纸篓（要管理员密码）"}}, true
}

// Homebrew is the judgement for this rule's settings (UsrLocal, OptHomebrew), for this home (its shell set-up, its
// Trash) and system Library (registered JDKs; "": the home's own Library, nothing of the real Mac).
func (r *InstallLeftoverRule) Homebrew(home, library string) IntelHomebrew {
	b := NewIntelHomebrew(home)
	b.UsrLocal, b.OptHomebrew, b.Trash = r.UsrLocal, r.OptHomebrew, r.Trash
	if library == "" {
		library = filepath.Join(home, "Library")
	}
	b.JavaVMs = filepath.Join(library, "Java/JavaVirtualMachines")
	return b
}

// Scheduled is what launchd jobs (LaunchdPaths) and the crontab name: a use of the Intel Homebrew there keeps it. ok
// false when the crontab cannot be read: then whether it is used there is not known.
func (r *InstallLeftoverRule) Scheduled(home, library string) ([]string, bool) {
	cron, ok := r.Crontab()
	if !ok {
		return nil, false
	}
	if library == "" {
		library = filepath.Join(home, "Library")
	}
	paths, _ := LaunchdPaths(library, home, false)
	return append(paths, appsSplit(cron, "\n")...), true
}

// intelHomebrew: an Intel Homebrew in /usr/local on an Apple silicon Mac. Beside an Apple silicon one, unused and the
// user's: offered to the Trash with the password. Once it is gone, the links that pointed into it.
func (r *InstallLeftoverRule) intelHomebrew(ctx *Context) []Finding {
	if !r.AppleSilicon() {
		return nil
	}
	brew := r.Homebrew(ctx.Home, ctx.SystemLibrary)
	brew.Stop = ctx.IsCancelled
	repo := filepath.Join(r.UsrLocal, "Homebrew")
	if !brew.Installed() && !Exists(filepath.Join(r.UsrLocal, "bin/brew")) {
		if f, ok := r.danglingLinks(brew, ctx); ok {
			return []Finding{f}
		}
		return nil
	}
	programs, cronOK := r.Scheduled(ctx.Home, ctx.SystemLibrary)
	running := r.Running()
	var fit bool
	var bytes int64
	if cronOK {
		_, bytes, fit = brew.Removable(programs, running, uint32(os.Getuid()), ctx.Now)
	}
	if !fit {
		bytes = 0
		for _, f := range IntelHomebrewFolders {
			bytes += AllocatedSize(filepath.Join(r.UsrLocal, f))
		}
	}
	both := brew.Other()
	title := "Homebrew 是 Intel 版的，靠 Rosetta 运行（" + FormatBytes(bytes) + "）"
	ev := map[string]string{"why": "Intel 版的工具要经 Rosetta 转译，慢；苹果已经说过以后的 macOS 会收回 Rosetta", "both": "0"}
	var only []string
	if both {
		title = "/usr/local 里还留着一套 Intel 版的 Homebrew（" + FormatBytes(bytes) + "）"
		ev["both"] = "1"
		only = brew.OnlyHere()
	}
	if len(only) > 0 {
		shown := only
		if len(shown) > 20 {
			shown = shown[:20]
		}
		ev["only_here"] = strings.Join(shown, "、")
		if len(only) > 20 {
			ev["only_here"] += " 等 " + strconv.Itoa(len(only)) + " 个"
		}
	}
	verdict := Info
	if fit {
		verdict = Confirm
		ev["system"] = "1"
		ev["password"] = "/usr/local 归系统，要输入 Mac 的密码才能移走"
		how := "Cellar、Caskroom 和 Homebrew 本身一起移进废纸篓；/usr/local 里指向它们的链接先留着，放回以后还是原来那套；倒掉废纸篓以后再删那些链接。"
		if len(only) > 0 {
			how += "Apple 芯片版里还没有的要先装过去。"
		}
		ev["how"] = how + "放回：在访达里把它们从废纸篓拖回 /usr/local（会要密码）"
	} else {
		if both {
			ev["how"] = "先确认 /opt/homebrew 里装齐了你要的工具，再用 Homebrew 官方的卸载脚本（加 --path=/usr/local）删掉旧的这套"
		} else {
			ev["how"] = "装一套 Apple 芯片版的 Homebrew（在 /opt/homebrew），把工具装过去，再用官方卸载脚本（加 --path=/usr/local）删掉这套"
		}
		if both && !cronOK {
			ev["not_now"] = "读不出你的 crontab，没法确认没有定时任务在用它"
		} else if why := brew.Blocker(programs, running); both && why != "" {
			ev["not_now"] = why
		} else if both {
			ev["not_now"] = "最近一个月还在用（包括 brew update），或者里面有别的账户的东西"
		}
	}
	return []Finding{{Rule: "leftover.intel-homebrew", Category: CatLeftover, Severity: Low, Verdict: verdict, Path: repo,
		Bytes: Size(bytes), Title: title, Evidence: ev}}
}

// danglingLinks: links into an Intel Homebrew that is gone (moved to the Trash and emptied from it). Only links, so
// they take no space; offered for deleting.
func (r *InstallLeftoverRule) danglingLinks(brew IntelHomebrew, ctx *Context) (Finding, bool) {
	links, ok := brew.DanglingLinks()
	if !ok || len(links) == 0 {
		return Finding{}, false
	}
	var names []string
	for i, l := range links {
		if i == 5 {
			break
		}
		names = append(names, HomeRelative(l, ctx.Home))
	}
	n := strconv.Itoa(len(links))
	return Finding{Rule: "leftover.intel-homebrew-links", Category: CatLeftover, Severity: Low, Verdict: Confirm, Path: r.UsrLocal,
		Title: "/usr/local 里还有 " + n + " 个指向旧 Intel 版 Homebrew 的链接，已经失效",
		Evidence: map[string]string{"count": n, "examples": strings.Join(names, "；"),
			"how": "它指向的 Homebrew 已经不在了（移进废纸篓后倒掉了）；删掉只是去掉这些链接，不占空间"}}, true
}

// attachedImages are the disk images attached now (hdiutil info), by image path, canonical.
func attachedImages() map[string]bool {
	out := map[string]bool{}
	res := Run("/usr/bin/hdiutil", []string{"info", "-plist"}, RunOpts{Timeout: 20 * time.Second})
	if res.Status != 0 {
		return out
	}
	v, err := DecodePlist([]byte(res.Stdout))
	d, ok := v.(map[string]any)
	if err != nil || !ok {
		return out
	}
	images, _ := d["images"].([]any)
	for _, im := range images {
		if m, ok := im.(map[string]any); ok {
			if p, ok := m["image-path"].(string); ok {
				out[Canonical(p)] = true
			}
		}
	}
	return out
}

// runningPrograms are the programs running now, by path (Swift: ProcInfo.snapshot().map(\.path)).
func runningPrograms() []string {
	var out []string
	for _, p := range ProcSnapshot() {
		out = append(out, p.Path)
	}
	return out
}

// AttachedImagesNow are the disk images attached now (hdiutil info), by image path, canonical.
func AttachedImagesNow() map[string]bool { return attachedImages() }
