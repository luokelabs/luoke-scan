package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// LeftoverRule: data an app left behind after it was removed (leftover.app-data). Folders and files named after a
// bundle id that no installed app covers, and that nothing has written to for a month (something still writing is in
// use). In the home and, on this Mac, in the system's Library (Context.SystemLibrary), where deleting takes the
// user's password. Swift: Rules/LeftoverRule.swift.
//
// In the home, what it found about each item (in use until when, or its size) is kept with the journal event it holds
// up to, as for old projects: an item nothing was written in since is not walked again. The system's Library is looked
// at every round (the password step judges it again anyway).
type LeftoverRule struct {
	Quiet    time.Duration
	Journal  JournalSource
	MinBytes int64
	// IgnorePrefixes are never reported: system and runtime ids that are not apps.
	IgnorePrefixes []string
	// LaunchServices: also ask macOS where apps are (off for a fake home).
	LaunchServices bool
	// Sensitive names suggest keys, wallets, password vaults, one-time codes or VPN set-ups: possibly the only copy,
	// never offered for deletion.
	Sensitive []string
	// SystemOwner is who what is taken from the system's Library must belong to: root (a fake home: its user).
	SystemOwner uint32
}

func init() { Register("leftover.app-data", NewLeftoverRule) }

// NewLeftoverRule is the rule for this Mac (l nil) or a fake home.
func NewLeftoverRule(l *Layout, f *Fakes) Rule {
	r := &LeftoverRule{Quiet: 30 * 24 * time.Hour, Journal: NewJournalSource(), MinBytes: 1 << 20,
		IgnorePrefixes: []string{"com.apple.", "group.com.apple.", "com.microsoft.VSCode.", "org.python.", "org.swift.", "com.github.Electron"},
		LaunchServices: true,
		Sensitive: []string{"wallet", "ethereum", "bitcoin", "parity", "electrum", "ledger", "metamask", "onepassword", "1password",
			"keepass", "bitwarden", "lastpass", "dashlane", "enpass", "keychain", "gpg", "vault", "ssh",
			"authy", "authenticator", "wireguard", "tailscale", "openvpn", "tunnelblick", "vpn", "clash",
			"shadowsocks", "v2ray", "surge", "mullvad"}}
	if l != nil {
		r.LaunchServices = false
		r.SystemOwner = uint32(os.Getuid()) // the fake system Library is the test user's
	}
	return r
}

func (r *LeftoverRule) ID() string      { return "leftover.app-data" }
func (r *LeftoverRule) Emits() []string { return []string{"leftover.app-data"} }

// LeftoverHomeFolders are the folders of the home an app's data is looked for in.
var LeftoverHomeFolders = []string{"Library/Application Support", "Library/Caches", "Library/Containers", "Library/Preferences",
	"Library/Saved Application State", "Library/HTTPStorages", "Library/Logs", "Library/WebKit", "Library/Group Containers"}

// LeftoverBundleID is the bundle id an item of those folders is named after, or "".
func LeftoverBundleID(name string) string {
	n := name
	for _, suffix := range []string{".plist", ".savedState", ".binarycookies"} {
		n = strings.TrimSuffix(n, suffix)
	}
	n = StripTeamID(n)
	// Group Containers: `group.net.whatsapp.WhatsApp.shared` belongs to `net.whatsapp.WhatsApp`.
	if strings.HasPrefix(strings.ToLower(n), "group.") {
		n = n[len("group."):]
	}
	if LooksLikeBundleID(n) {
		return n
	}
	return ""
}

// LeftoverPlaces is where an app's data is under home (the folders the rule reports for that bundle id), found again
// from the folders themselves. mayLook: which places may be listed (nil: all).
func LeftoverPlaces(id, home string, mayLook func(string) bool) []string {
	var out []string
	for _, p := range LeftoverHomeFolders {
		dir := filepath.Join(home, p)
		if mayLook != nil && !mayLook(dir) {
			continue
		}
		for _, u := range Children(dir) {
			if LeftoverBundleID(filepath.Base(u)) == id {
				out = append(out, u)
			}
		}
	}
	return out
}

// LeftoverSystemFolders are the folders of the system's Library an app's own data can be left in. Not Preferences in
// this first version (a system component's settings there look like an app's), not launchd jobs, helper tools or
// extensions (those are what starts by itself, reported as such).
var LeftoverSystemFolders = []string{"Application Support", "Caches", "Logs"}

// systemIgnorePrefixes: what comes with macOS and keeps things in the system's Library under ids that do not start
// with com.apple.
var systemIgnorePrefixes = []string{"org.cups.", "org.ntp.", "org.postfix.", "org.openldap.", "org.openssh.", "com.openssh.",
	"org.apache.", "org.isc.", "org.samba.", "org.xquartz.", "org.libusb.", "org.sudo-project."}

// LeftoverSystemPlaces is where an app's data is in the system's Library: direct children of LeftoverSystemFolders
// named after id.
func LeftoverSystemPlaces(id, library string) []string {
	var out []string
	for _, p := range LeftoverSystemFolders {
		for _, u := range Children(filepath.Join(library, p)) {
			if LeftoverBundleID(filepath.Base(u)) == id {
				out = append(out, u)
			}
		}
	}
	return out
}

// InstalledComponents is what is installed besides apps, lowercased: names of package receipts, launchd jobs and
// helper tools, and the names and bundle ids of kernel and system extensions, audio plug-ins, printer drivers, file
// systems, preference panes, input methods, frameworks and other plug-ins. A vendor with any of these still installed
// has not been removed. receipts, home "": not looked at.
func InstalledComponents(library, receipts, home string) []string {
	var out []string
	// Apps an installer put inside its own folder in Application Support (updaters, agents).
	for _, d := range Children(filepath.Join(library, "Application Support")) {
		for _, u := range Children(d) {
			if PathExtension(u) == "app" {
				out = append(out, strings.ToLower(filepath.Base(u)))
				if id := BundleIdentifier(u); id != "" {
					out = append(out, strings.ToLower(id))
				}
			}
		}
	}
	names := func(dir string) {
		for _, u := range Children(dir) {
			out = append(out, strings.ToLower(filepath.Base(u)))
		}
	}
	var bundles func(dir string, depth int)
	bundles = func(dir string, depth int) {
		for _, u := range Children(dir) {
			out = append(out, strings.ToLower(filepath.Base(u)))
			if id := BundleIdentifier(u); id != "" {
				out = append(out, strings.ToLower(id))
			} else if depth > 0 {
				bundles(u, depth-1)
			}
		}
	}
	if receipts != "" {
		names(receipts)
	}
	for _, d := range []string{"LaunchDaemons", "LaunchAgents", "PrivilegedHelperTools"} {
		names(filepath.Join(library, d))
	}
	if home != "" {
		names(filepath.Join(home, "Library/LaunchAgents"))
	}
	for _, d := range []string{"Extensions", "Filesystems", "PreferencePanes", "Input Methods", "Frameworks", "Printers", "Internet Plug-Ins",
		"QuickLook", "Spotlight", "Screen Savers", "Services", "Contextual Menu Items", "Image Capture", "DriverExtensions"} {
		bundles(filepath.Join(library, d), 1)
	}
	bundles(filepath.Join(library, "SystemExtensions"), 1) // <UUID>/<id>.systemextension
	bundles(filepath.Join(library, "Audio/Plug-Ins"), 1)   // HAL/, Components/
	for _, d := range []string{"Audio/MIDI Drivers", "Security/SecurityAgentPlugins", "CoreMediaIO/Plug-Ins/DAL"} {
		bundles(filepath.Join(library, d), 1)
	}
	return out
}

// appsPlistStrings is an array of strings (all of them strings), or nil.
func appsPlistStrings(v any) []string {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

// LaunchdPaths is every path the system's and the user's launchd jobs name -- the program and all its arguments, the
// working folder, the log files, the watched folders -- each as written and with its links resolved, lowercased (APFS
// folds case). Data a job uses is in use. strict (the password step, as root): ok false when a job file could not be
// read. Otherwise one that cannot be read is passed over. home "": not looked at.
func LaunchdPaths(library, home string, strict bool) ([]string, bool) {
	dirs := []string{filepath.Join(library, "LaunchDaemons"), filepath.Join(library, "LaunchAgents")}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, "Library/LaunchAgents"))
	}
	var out []string
	for _, d := range dirs {
		for _, u := range Children(d) {
			if PathExtension(u) != "plist" {
				continue
			}
			data, err := os.ReadFile(u)
			if err != nil {
				if strict {
					return nil, false
				}
				continue
			}
			v, err := DecodePlist(data)
			p, ok := v.(map[string]any)
			if err != nil || !ok {
				continue
			}
			var named []string
			for _, k := range []string{"Program", "WorkingDirectory", "StandardOutPath", "StandardErrorPath"} {
				if s, ok := p[k].(string); ok {
					named = append(named, s)
				}
			}
			for _, k := range []string{"ProgramArguments", "WatchPaths", "QueueDirectories"} {
				named = append(named, appsPlistStrings(p[k])...)
			}
			for _, s := range named {
				if !strings.HasPrefix(s, "/") {
					continue
				}
				out = append(out, strings.ToLower(s))
				if r, err := filepath.EvalSymlinks(s); err == nil {
					out = append(out, strings.ToLower(r))
				}
			}
		}
	}
	return out, true
}

// VendorInstalled says whether something of id's vendor is among components (InstalledComponents).
func VendorInstalled(id string, components []string) bool {
	parts := appsSplit(strings.ToLower(id), ".")
	if len(parts) < 2 {
		return true
	}
	vendor := parts[0] + "." + parts[1] + "."
	for _, c := range components {
		if strings.HasPrefix(c, vendor) {
			return true
		}
	}
	return false
}

// SystemLeftovers is what of id in the system's Library is left over now: the one judgement the round that offers it
// and the password step that moves it both make. Nothing when the id is macOS's own or names keys or a vault, when
// an app in appDirs or a component of the vendor is installed; then each item must be SystemOwner's, not a link, and
// not written to within Quiet, and together hold at least MinBytes.
func (r *LeftoverRule) SystemLeftovers(id, library string, appDirs, components, programs []string, now time.Time) []string {
	low := strings.ToLower(id)
	for _, p := range append(append([]string{}, r.IgnorePrefixes...), systemIgnorePrefixes...) {
		if strings.HasPrefix(low, strings.ToLower(p)) {
			return nil
		}
	}
	for _, s := range r.Sensitive {
		if strings.Contains(low, s) {
			return nil
		}
	}
	if VendorInstalled(id, components) {
		return nil
	}
	apps := NewInstalledApps(appDirs, false)
	if apps.Covers(id) || apps.CoversVendor(id) {
		return nil
	}
	since := now.Add(-r.Quiet)
	var total int64
	var items []string
	for _, u := range LeftoverSystemPlaces(id, library) {
		var st syscall.Stat_t
		if syscall.Lstat(u, &st) != nil || st.Uid != r.SystemOwner || st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			continue
		}
		names := []string{strings.ToLower(Canonical(u)), strings.ToLower(u)}
		for _, prog := range programs {
			for _, n := range names {
				if prog == n || strings.HasPrefix(prog, n+"/") {
					return nil
				}
			}
		}
		size, ok := SizeUnlessChanged(u, since, now)
		if !ok {
			return nil // in use
		}
		total += size
		items = append(items, u)
	}
	if len(items) == 0 || total < r.MinBytes {
		return nil
	}
	return items
}

// LeftoverSeen is what an item in the home was found to be, as kept between rounds.
type LeftoverSeen struct {
	// InUseUntil: written to lately, in use until then; nothing else is kept then.
	InUseUntil *time.Time `json:"inUseUntil,omitempty"`
	Bytes      int64      `json:"bytes"`
}

// LeftoverRow is a LeftoverSeen with the journal event it holds up to.
type LeftoverRow struct {
	EventID    uint64       `json:"eventID"`
	Inode      uint64       `json:"inode"`
	MeasuredAt time.Time    `json:"measuredAt"`
	Seen       LeftoverSeen `json:"seen"`
}

// LeftoverStateTable keeps LeftoverRow by canonical path.
func LeftoverStateTable(s *Store) Table[LeftoverRow] {
	return NewTable[LeftoverRow](s, "leftover_state", 1)
}

func (r *LeftoverRule) Run(ctx *Context) ([]Finding, error) {
	apps := NewInstalledApps(ctx.AppDirs, r.LaunchServices)
	since := ctx.Now.Add(-r.Quiet)
	var table Table[LeftoverRow]
	known := map[string]LeftoverRow{}
	if ctx.Store != nil {
		table = LeftoverStateTable(ctx.Store)
		known = table.Load()
	}
	var roots []string
	for _, p := range LeftoverHomeFolders {
		if u := filepath.Join(ctx.Home, p); ctx.MayLook(u) && Exists(u) {
			roots = append(roots, u)
		}
	}
	// From the oldest row that may still be reused: one older is walked again anyway, and an item that keeps being
	// passed over (another of its app's is in use) must not hold the replay at its old event for months.
	var usable []uint64
	for _, k := range known {
		if r.Journal.Reusable(k.MeasuredAt, ctx.Now) {
			usable = append(usable, k.EventID)
		}
	}
	inc, err := BeginIncrement(ctx, "fsevents.journal.leftovers", roots, minEventID(usable), r.Journal, func() error {
		known = map[string]LeftoverRow{}
		if ctx.Store == nil {
			return nil
		}
		return table.Apply(nil, nil, true)
	})
	if err != nil {
		return nil, err
	}
	rows, present := map[string]LeftoverRow{}, map[string]bool{}
	write := func(forget []string) {
		if ctx.Store != nil {
			table.Apply(rows, forget, false)
		}
	}
	// One walk per item for both: written to lately (in use) or else its size. Folders only are remembered: the
	// journal reports a change to a plain file (a preferences file, a log) on the folder it is in, never on the file,
	// and looking at a file again is one stat. The system's Library each round.
	look := func(u string, system bool) LeftoverSeen {
		walk := func() LeftoverSeen {
			c, b := FirstChange(u, since, ctx.Now, true)
			if c.IsZero() {
				return LeftoverSeen{Bytes: b}
			}
			until := c.Add(r.Quiet)
			return LeftoverSeen{InUseUntil: &until}
		}
		if e, ok := Item(u); system || !ok || !e.IsDir {
			return walk()
		}
		key, ino := Canonical(u), Inode(u)
		if k, ok := known[key]; ok && k.Inode == ino && r.Journal.Reusable(k.MeasuredAt, ctx.Now) && !inc.Changes.Touched(key, k.EventID) &&
			(k.Seen.InUseUntil == nil || ctx.Now.Before(*k.Seen.InUseUntil)) {
			return k.Seen
		}
		v := walk()
		rows[key] = LeftoverRow{EventID: inc.Start, Inode: ino, MeasuredAt: ctx.Now, Seen: v}
		return v
	}
	byID := map[string][]string{}
	// Other apps' containers and group containers: not listed without Full Disk Access (macOS asks the user first).
	var left []string
	for _, p := range LeftoverHomeFolders {
		if !ctx.MayLook(filepath.Join(ctx.Home, p)) {
			left = append(left, p)
			continue
		}
		for _, u := range Children(filepath.Join(ctx.Home, p)) {
			id := LeftoverBundleID(filepath.Base(u))
			if id == "" || r.ignored(id) {
				continue
			}
			byID[id] = append(byID[id], u)
		}
	}
	// The system's Library: what SystemLeftovers takes, the same judgement the password step makes again.
	system, systemItems := map[string]bool{}, map[string]bool{}
	var vendorComponents []string
	if lib := ctx.SystemLibrary; lib != "" {
		// What else of a vendor is installed system-wide: its data in the home may be a component's. Not the user's
		// own launchd jobs: one a removed app left behind must not keep that app's data from being offered.
		vendorComponents = InstalledComponents(lib, ctx.Receipts, "")
		components := InstalledComponents(lib, ctx.Receipts, ctx.Home)
		programs, _ := LaunchdPaths(lib, ctx.Home, false)
		idSet := map[string]bool{}
		for _, p := range LeftoverSystemFolders {
			for _, u := range Children(filepath.Join(lib, p)) {
				if id := LeftoverBundleID(filepath.Base(u)); id != "" {
					idSet[id] = true
				}
			}
		}
		for _, id := range appsSortedKeys(idSet) {
			items := r.SystemLeftovers(id, lib, ctx.AppDirs, components, programs, ctx.Now)
			if items == nil {
				continue
			}
			byID[id] = append(byID[id], items...)
			for _, u := range items {
				systemItems[u] = true
			}
			system[id] = true
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Finding
	for _, id := range ids {
		items := byID[id]
		if ctx.IsCancelled() {
			write(nil) // keep what was looked at
			return nil, Skip(Interrupted)
		}
		if apps.Covers(id) {
			continue
		}
		// What is not walked after one in use keeps what was found about it.
		for _, u := range items {
			if !systemItems[u] {
				present[Canonical(u)] = true
			}
		}
		var size int64
		inUse := false
		for _, u := range items {
			seen := look(u, systemItems[u])
			if seen.InUseUntil != nil {
				inUse = true
				break
			}
			size += seen.Bytes
		}
		if inUse || size < r.MinBytes {
			continue
		}
		var last time.Time
		for _, u := range items {
			if m, ok := Modified(u); ok && !m.After(ctx.Now) && m.After(last) {
				last = m
			}
		}
		low := strings.ToLower(id)
		sensitive := false
		for _, s := range r.Sensitive {
			sensitive = sensitive || strings.Contains(low, s)
		}
		sameVendor := apps.CoversVendor(id) || VendorInstalled(id, vendorComponents)
		shown := make([]string, len(items))
		for i, u := range items {
			shown[i] = HomeRelative(u, ctx.Home)
		}
		lastDay := "?"
		if !last.IsZero() {
			lastDay = ISODay(last)
		}
		ev := map[string]string{"bundle_id": id, "places": strings.Join(shown, "；"), "size": FormatBytes(size), "last_changed": lastDay,
			"hint": "有的应用把文档、本地数据库放在这里；删之前确认里面没有你还要的东西，或者新版本已经导入过"}
		title := id + " 的数据还在，但这台 Mac 上没有这个应用"
		if system[id] {
			ev["system"] = "1"
			ev["password"] = "系统目录里的要输入 Mac 的密码才能移走"
		}
		if sensitive {
			ev["hint"] = "名字像钱包、密码库、密钥或 VPN 配置：里面可能是唯一的一份，别直接删；确认已经迁移或备份过"
			title += "（可能有密钥或密码库）"
		} else if sameVendor {
			ev["hint"] = "同一家开发商的应用或组件（安装包、后台程序、扩展）还装着，这可能是它的组件或旧版本留下的"
		}
		verdict := Confirm
		if sensitive || sameVendor {
			verdict = Info
		}
		out = append(out, Finding{Rule: r.ID(), Category: CatLeftover, Severity: Low, Verdict: verdict, Path: items[0], Bytes: Size(size),
			Title: title, Evidence: ev, Key: id}) // the app, wherever its data is
	}
	// Rows of what is in a guarded folder not looked at this round are kept.
	var forget []string
	for k := range known {
		if !present[k] && ctx.MayLook(k) {
			forget = append(forget, k)
		}
	}
	sort.Strings(forget)
	write(forget)
	if len(left) > 0 {
		return nil, Skip(NotLooked("别的应用的容器里留下的数据"), out...)
	}
	return out, nil
}

func (r *LeftoverRule) ignored(id string) bool {
	low := strings.ToLower(id)
	for _, p := range r.IgnorePrefixes {
		if strings.HasPrefix(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func appsSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
