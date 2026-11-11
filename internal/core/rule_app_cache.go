package core

import (
	"path/filepath"
	"sort"
	"strings"
)

func init() { Register("cache.app", NewAppCacheRule) }

// AppCacheProtected: a cache, log or app folder whose name (lower case) contains one of these is never offered.
// Account, keychain and sign-in helpers; password managers, wallets, keys and VPNs (as LeftoverRule.Sensitive);
// input methods; security and device-management agents; and caches whose loss shows (offline music, cloud drives'
// local state, mail, photos, the Spotlight index).
var AppCacheProtected = []string{
	"account", "icloud", "cloudkit", "keychain", "authkit", "authenticat", "authy", "passkit", "password", "screentime",
	"familycircle", "identityservices", "inputmethod",
	"wallet", "ethereum", "bitcoin", "ledger", "metamask", "1password", "onepassword", "keepass", "bitwarden", "lastpass",
	"dashlane", "enpass", "gpg", "vault", "ssh", "wireguard", "tailscale", "openvpn", "tunnelblick", "vpn", "clash",
	"shadowsocks", "v2ray", "surge", "mullvad",
	"crowdstrike", "falcon", "sentinel", "jamf", "kandji", "mosyle", "addigy", "com.eset", "paloalto", "globalprotect",
	"cisco", "sophos", "wdav", "defender", "santa", "osquery",
	"spotify", "dropbox", "drivefs", "googledrive", "onedrive", "box.desktop", "mail", "photos", "music", "spotlight",
}

// AppCacheIsProtected: the name is Apple's own (the system's caches and logs) or has a protected word in it.
func AppCacheIsProtected(name string) bool {
	low := strings.ToLower(name)
	if strings.HasPrefix(low, "com.apple.") || strings.HasPrefix(low, "group.com.apple.") {
		return true
	}
	for _, w := range AppCacheProtected {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// ChromiumCacheFolders are the folders a Chromium-based app (Electron apps, browsers) keeps its caches in, next to its
// `Local State`. Never Service Worker (sites' offline data and push registrations), Local Storage, IndexedDB or the
// profile itself: those are the user's data.
var ChromiumCacheFolders = []string{"Cache", "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache", "DawnCache",
	"DawnGraphiteCache", "DawnWebGPUCache", "CachedData"}

// AppCacheRule reports what installed apps keep that they make again: their caches in ~/Library/Caches (a folder named
// after the app's bundle id), the caches of Chromium-based apps in Application Support, and the logs in ~/Library/Logs.
// Never safe and never cleaned automatically: an app may be using it, so it is confirmed, moved to the Trash, and looked
// at again before (anything written to since the round is left).
type AppCacheRule struct {
	MinBytes    int64
	MinLogBytes int64
	// MaxItems of each kind, the biggest first.
	MaxItems int
}

// NewAppCacheRule makes the rule; the same for a fake home (its apps are in its AppDirs).
func NewAppCacheRule(l *Layout, f *Fakes) Rule {
	return &AppCacheRule{MinBytes: 200 * 1_048_576, MinLogBytes: 100 * 1_048_576, MaxItems: 8}
}

func (r *AppCacheRule) ID() string      { return "cache.app" }
func (r *AppCacheRule) Emits() []string { return []string{"cache.app", "cache.electron", "cache.logs"} }

// installedAppNames: the apps in the app folders (and one level down), bundle id (lower case) to the app's name.
func installedAppNames(dirs []string) map[string]string {
	out := map[string]string{}
	var scan func(dir string, depth int)
	scan = func(dir string, depth int) {
		for _, u := range Children(dir) {
			if PathExtension(u) == "app" {
				if id := BundleIdentifier(u); id != "" {
					out[strings.ToLower(id)] = strings.TrimSuffix(filepath.Base(u), ".app")
				}
			} else if depth > 0 {
				if e, ok := Item(u); ok && e.IsDir {
					scan(u, depth-1)
				}
			}
		}
	}
	for _, d := range dirs {
		scan(d, 1)
	}
	return out
}

// realFolder: there, a folder, not a link.
func realFolder(path string) bool {
	e, ok := acItem(path)
	return ok && e.IsDir && !e.IsLink
}

// What this rule reads the disk with; the test swaps them to see that nothing is read where the round may not look
// (TestAppCacheRuleNeverLooksWhereItMayNot).
var (
	acChildren = Children
	acItem     = Item
	acExists   = Exists
)

// ChromiumRoot: the folder a Chromium-based app keeps its state in (it has the browser's `Local State`).
func ChromiumRoot(dir string) bool {
	return acExists(filepath.Join(dir, "Local State")) || acExists(filepath.Join(dir, "Network Persistent State"))
}

// ChromiumCaches are the cache folders of a Chromium root, each a real folder; `Cache` only when it looks like
// Chromium's disk cache (Cache_Data, or index and data_0), not some other folder an app named Cache.
func ChromiumCaches(root string) []string {
	var out []string
	for _, name := range ChromiumCacheFolders {
		p := filepath.Join(root, name)
		if !realFolder(p) {
			continue
		}
		if name == "Cache" && !acExists(filepath.Join(p, "Cache_Data")) &&
			!(acExists(filepath.Join(p, "index")) && acExists(filepath.Join(p, "data_0"))) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (r *AppCacheRule) cap(fs []Finding) []Finding {
	sort.SliceStable(fs, func(i, j int) bool { return bytesOf(fs[i]) > bytesOf(fs[j]) })
	if r.MaxItems > 0 && len(fs) > r.MaxItems {
		fs = fs[:r.MaxItems]
	}
	return fs
}

func (r *AppCacheRule) Run(ctx *Context) ([]Finding, error) {
	apps := installedAppNames(ctx.AppDirs)
	// Caches another rule owns (the tools' rebuildable caches, the AI models) are left to it.
	owned := map[string]bool{"huggingface": true}
	for _, c := range KnownCaches {
		if rest, ok := strings.CutPrefix(c.Path, "Library/Caches/"); ok {
			owned[strings.ToLower(strings.SplitN(rest, "/", 2)[0])] = true
		}
	}

	// ~/Library/Caches/<bundle id> of an installed app. One named after an app that is gone is a leftover (its rule).
	// Where the round may not look is not so much as listed or stat'ed: MayLook comes first, every level down.
	var caches []Finding
	for _, u := range lookable(ctx, filepath.Join(ctx.Home, "Library/Caches")) {
		if !realFolder(u) {
			continue
		}
		id := strings.ToLower(filepath.Base(u))
		app, installed := apps[id]
		if !installed || owned[id] || AppCacheIsProtected(id) || AppCacheIsProtected(app) {
			continue
		}
		size := AllocatedSize(u)
		if size < r.MinBytes {
			continue
		}
		caches = append(caches, Finding{Rule: "cache.app", Category: CatCache, Severity: Low, Verdict: Confirm, Path: u,
			Bytes: Size(size), Title: "「" + app + "」的缓存",
			Evidence: map[string]string{"app": app, "app_id": filepath.Base(u), "size": FormatBytes(size),
				"how": "删了不影响使用，" + app + " 用到时会重新生成；先退出它再清"}})
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, caches...)
		}
	}

	// Chromium-based apps (Electron apps: editors, chat apps…) in Application Support and one level down
	// (<vendor>/<app>): their caches, together, as one item; the rest of the folder is the app's data and stays.
	var electron []Finding
	support := filepath.Join(ctx.Home, "Library/Application Support")
	var roots []string
	for _, u := range lookable(ctx, support) {
		if !realFolder(u) {
			continue
		}
		if ChromiumRoot(u) {
			roots = append(roots, u)
			continue
		}
		for _, v := range lookable(ctx, u) {
			if realFolder(v) && ChromiumRoot(v) {
				roots = append(roots, v)
			}
		}
	}
	for _, root := range roots {
		name := filepath.Base(root)
		rel, _ := filepath.Rel(support, root)
		if AppCacheIsProtected(rel) || !ctx.MayLook(root) {
			continue
		}
		// Named after an app that is gone: all of it is a leftover (its rule), not just the caches.
		if id := LeftoverBundleID(name); id != "" {
			if _, installed := apps[strings.ToLower(id)]; !installed {
				continue
			}
			if app := apps[strings.ToLower(id)]; app != "" {
				name = app
			}
		}
		targets := ChromiumCaches(root)
		var size int64
		for _, t := range targets {
			size += AllocatedSize(t)
		}
		if size < r.MinBytes {
			continue
		}
		electron = append(electron, Finding{Rule: "cache.electron", Category: CatCache, Severity: Low, Verdict: Confirm,
			Path: root, Bytes: Size(size), Title: "「" + name + "」的缓存",
			Evidence: map[string]string{"app": name, "targets": strings.Join(targets, "\n"), "size": FormatBytes(size),
				"how": "只清它的缓存文件夹，设置、登录和数据都不动；" + name + " 用到时会重新生成，先退出它再清"}})
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, append(r.cap(caches), electron...)...)
		}
	}

	// ~/Library/Logs: each app's logs, and the crash reports. They are only for finding out what went wrong.
	var logs []Finding
	for _, u := range lookable(ctx, filepath.Join(ctx.Home, "Library/Logs")) {
		e, ok := acItem(u)
		if !ok || e.IsLink {
			continue
		}
		low := strings.ToLower(e.Name)
		crash := e.Name == "DiagnosticReports"
		if !crash && AppCacheIsProtected(low) {
			continue
		}
		size := e.Bytes
		if e.IsDir {
			size = AllocatedSize(u)
		}
		if size < r.MinLogBytes {
			continue
		}
		label, title := e.Name, "「"+e.Name+"」的日志"
		if app, ok := apps[low]; ok {
			label, title = app, "「"+app+"」的日志"
		}
		if crash {
			label, title = "崩溃报告", "应用的崩溃报告"
		}
		logs = append(logs, Finding{Rule: "cache.logs", Category: CatCache, Severity: Low, Verdict: Confirm, Path: u,
			Bytes: Size(size), Title: title,
			Evidence: map[string]string{"app": label, "size": FormatBytes(size),
				"how": "日志只在查问题时用得上；不用了可以移到废纸篓，应用会重新写"}})
	}

	out := append(r.cap(caches), r.cap(electron)...)
	return append(out, r.cap(logs)...), nil
}

// lookable: what is in dir that the round may look at; nothing when it may not look in dir itself. Neither dir nor a
// child it may not look at is so much as stat'ed (Application Support holds the folders macOS asks about, AddressBook,
// CallHistoryDB…, and with access switched off those stay unread).
func lookable(ctx *Context, dir string) []string {
	if !ctx.MayLook(dir) {
		return nil
	}
	var out []string
	for _, u := range acChildren(dir) {
		if ctx.MayLook(u) {
			out = append(out, u)
		}
	}
	return out
}
