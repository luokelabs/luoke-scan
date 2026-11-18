package core

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// Which apps are on this Mac, by bundle id: what tells leftovers and stale grants from live ones. Swift: Apps.swift.

// InstalledApps are the apps in some folders (and one level down), by bundle id, lowercased.
type InstalledApps struct {
	IDs map[string]bool
	// LaunchServices: an id not found in the folders is also looked for wherever macOS knows apps to be (Spotlight's
	// index, `mdfind`). Off for a fake home and for the password step (no session to ask).
	LaunchServices bool
}

// NewInstalledApps reads the bundle ids of the apps in dirs and one folder down (/Applications/Utilities).
func NewInstalledApps(dirs []string, launchServices bool) InstalledApps {
	ids := map[string]bool{}
	var scan func(dir string, depth int)
	scan = func(dir string, depth int) {
		for _, u := range Children(dir) {
			if PathExtension(u) == "app" {
				if id := BundleIdentifier(u); id != "" {
					ids[strings.ToLower(id)] = true
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
	return InstalledApps{IDs: ids, LaunchServices: launchServices}
}

// Covers: installed, or a helper, extension or cache of something installed (`com.google.Chrome.helper` → Chrome).
func (a InstalledApps) Covers(id string) bool {
	id = strings.ToLower(id)
	if a.IDs[id] {
		return true
	}
	for k := range a.IDs {
		if strings.HasPrefix(id, k+".") {
			return true
		}
	}
	return a.LaunchServices && len(AppsWithBundleID(id)) > 0
}

// AppVendor is the developer part of a bundle id: `com.agilebits.onepassword7` → `com.agilebits`.
func AppVendor(id string) string {
	parts := appsSplit(strings.ToLower(id), ".")
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, ".")
}

// CoversVendor: another app of the same developer is installed (the data may be one of its components').
func (a InstalledApps) CoversVendor(id string) bool {
	v := AppVendor(id)
	for k := range a.IDs {
		if AppVendor(k) == v {
			return true
		}
	}
	return false
}

var teamIDPrefix = regexp.MustCompile(`^[A-Z0-9]{10}\.`)

// StripTeamID: `2BUA8C4S2C.com.agilebits.x` → `com.agilebits.x` (the Team ID before shared containers' names).
func StripTeamID(s string) string {
	if loc := teamIDPrefix.FindStringIndex(s); loc != nil {
		return s[loc[1]:]
	}
	return s
}

var bundleIDShape = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+){2,}$`)

// LooksLikeBundleID: `io.example.App` style, at least three dot-separated parts of letters, digits and hyphens.
func LooksLikeBundleID(s string) bool { return bundleIDShape.MatchString(s) }

func appsSplit(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// PathExtension is a path's extension without the dot, as Foundation's URL.pathExtension has it: "" for none, and for a
// name that only starts with a dot (".profile").
func PathExtension(p string) string {
	name := filepath.Base(p)
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return ""
	}
	return name[i+1:]
}

// NameWithoutExtension is the last component without its extension ("Lumen" for /Applications/Lumen.app).
func NameWithoutExtension(p string) string {
	name := filepath.Base(p)
	if e := PathExtension(p); e != "" {
		return name[:len(name)-len(e)-1]
	}
	return name
}

// BundleInfo is a bundle's Info.plist as Foundation's Bundle finds it: Contents/Info.plist when the bundle has a
// Contents folder, else Resources/Info.plist, else Info.plist at the top. nil when there is none (or it is not a dictionary).
func BundleInfo(bundle string) map[string]any {
	if e, ok := Item(filepath.Join(bundle, "Contents")); ok && e.IsDir {
		return ReadPlistDict(filepath.Join(bundle, "Contents/Info.plist"))
	}
	if e, ok := Item(filepath.Join(bundle, "Resources")); ok && e.IsDir {
		return ReadPlistDict(filepath.Join(bundle, "Resources/Info.plist"))
	}
	return ReadPlistDict(filepath.Join(bundle, "Info.plist"))
}

// BundleIdentifier is a bundle's CFBundleIdentifier, or "".
func BundleIdentifier(bundle string) string {
	if st, err := appsIsDir(bundle); err != nil || !st {
		return ""
	}
	return PlistString(BundleInfo(bundle), "CFBundleIdentifier")
}

// appsIsDir says whether path is a folder (following a link).
func appsIsDir(path string) (bool, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false, err
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFDIR, nil
}

var (
	lsMu    sync.Mutex
	lsCache = map[string][]string{}
)

// AppsWithBundleID are the apps macOS knows by this bundle id (any case), wherever they are: Spotlight's index
// (`mdfind`), then the usual app folders. Asked once per id in a process.
func AppsWithBundleID(id string) []string {
	key := strings.ToLower(id)
	lsMu.Lock()
	if v, ok := lsCache[key]; ok {
		lsMu.Unlock()
		return v
	}
	lsMu.Unlock()
	var out []string
	if all, ok := spotlightAppsFor(); ok {
		out = append(out, all[key]...)
	} else {
		q := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(id)
		r := Run("/usr/bin/mdfind", []string{"kMDItemCFBundleIdentifier == '" + q + "'c"}, RunOpts{Timeout: 10 * time.Second})
		if r.Status == 0 {
			for _, line := range strings.Split(r.Stdout, "\n") {
				if strings.HasPrefix(line, "/") && PathExtension(line) == "app" && Exists(line) {
					out = append(out, line)
				}
			}
		}
	}
	// Spotlight may be off or still indexing: the app folders as well.
	if p := FindAppIn(id, []string{"/Applications", "/System/Applications", filepath.Join(appsUserHome(), "Applications")}); p != "" {
		have := false
		for _, o := range out {
			have = have || o == p
		}
		if !have {
			out = append(out, p)
		}
	}
	// The usual folders first, as Launch Services prefers them.
	sort.SliceStable(out, func(i, j int) bool { return appsRank(out[i]) < appsRank(out[j]) })
	lsMu.Lock()
	lsCache[key] = out
	lsMu.Unlock()
	return out
}

func appsRank(p string) int {
	for i, d := range []string{"/Applications/", "/System/Applications/"} {
		if strings.HasPrefix(p, d) {
			return i
		}
	}
	return 2
}

func appsUserHome() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/var/empty"
}

// FindAppIn is the app with bundle id (any case) in dirs or one folder down, as the fake home's Launch Services; "" none.
// During a round (withAppIndex) each list of folders is read once and every later id is looked up in that.
func FindAppIn(id string, dirs []string) string {
	low := strings.ToLower(id)
	if idx := appIndexFor(dirs); idx != nil {
		return idx[low]
	}
	return appIndex(dirs, low)[low]
}

// AppIndexIn: every app in dirs and one folder down by lowercased bundle id (the 「状态」 page names folders
// with it: one read of the app folders, not one Spotlight query per id).
func AppIndexIn(dirs []string) map[string]string { return appIndex(dirs, "") }

// appIndex: the apps in dirs and one folder down by lowercased bundle id, the first found for each, in the order
// FindAppIn looks (each folder's own entries, then those one level down). only: just that id ("" every id).
func appIndex(dirs []string, only string) map[string]string {
	out := map[string]string{}
	for _, d := range dirs {
		top := Children(d)
		cands := append([]string{}, top...)
		for _, u := range top {
			if PathExtension(u) != "app" {
				cands = append(cands, Children(u)...)
			}
		}
		for _, u := range cands {
			if PathExtension(u) != "app" {
				continue
			}
			id := strings.ToLower(BundleIdentifier(u))
			if id == "" || (only != "" && id != only) {
				continue
			}
			if _, have := out[id]; !have {
				out[id] = u
				if only != "" {
					return out
				}
			}
		}
	}
	return out
}

var (
	appIndexMu     sync.Mutex
	appIndexRounds int                              // rounds running; the indexes live only while one is
	appIndexes     = map[string]map[string]string{} // by the folders, joined with NUL
)

// withAppIndex runs f with FindAppIn reading each list of folders once: a round asks of hundreds of ids (every
// leftover folder's), and each used to read every app's Info.plist again. Only for the length of a round, so an app
// installed between rounds is seen by the next one.
func withAppIndex(f func()) {
	appIndexMu.Lock()
	appIndexRounds++
	appIndexMu.Unlock()
	defer func() {
		appIndexMu.Lock()
		if appIndexRounds--; appIndexRounds == 0 {
			appIndexes = map[string]map[string]string{}
			spotlightApps, spotlightAppsDone = nil, false
		}
		appIndexMu.Unlock()
	}()
	f()
}

// spotlightApps: during a round, every app Spotlight knows by lowercased bundle id (read from each app's Info.plist),
// from one mdfind instead of one per id; ok false outside a round or when Spotlight does not answer (then each id is
// asked as before).
var (
	spotlightApps     map[string][]string
	spotlightAppsDone bool
)

func spotlightAppsFor() (map[string][]string, bool) {
	appIndexMu.Lock()
	defer appIndexMu.Unlock()
	if appIndexRounds == 0 {
		return nil, false
	}
	if !spotlightAppsDone {
		spotlightAppsDone = true
		spotlightApps = nil
		r := Run("/usr/bin/mdfind", []string{"-0", "kMDItemCFBundleIdentifier == '*'"}, RunOpts{Timeout: 20 * time.Second})
		if r.Status == 0 {
			m := map[string][]string{}
			for _, line := range strings.Split(r.Stdout, "\x00") {
				if !strings.HasPrefix(line, "/") || PathExtension(line) != "app" || !Exists(line) {
					continue
				}
				if id := strings.ToLower(BundleIdentifier(line)); id != "" {
					m[id] = append(m[id], line)
				}
			}
			spotlightApps = m
		}
	}
	return spotlightApps, spotlightApps != nil
}

func appIndexFor(dirs []string) map[string]string {
	appIndexMu.Lock()
	defer appIndexMu.Unlock()
	if appIndexRounds == 0 {
		return nil
	}
	key := strings.Join(dirs, "\x00")
	if idx, ok := appIndexes[key]; ok {
		return idx
	}
	idx := appIndex(dirs, "")
	appIndexes[key] = idx
	return idx
}

// QuarantineAgent is the program that downloaded something, from its Gatekeeper mark ("0083;68f1c2a3;Safari;…" →
// "Safari"); "" when the mark names none; ok false when there is no mark.
func QuarantineAgent(path string) (string, bool) {
	b, ok := Xattr(path, "com.apple.quarantine", 511)
	if !ok || len(b) == 0 {
		return "", false
	}
	fields := strings.Split(strings.ToValidUTF8(string(b), "�"), ";")
	if len(fields) > 2 {
		return fields[2], true
	}
	return "", true
}

// QuarantineTime is when the quarantine record says the file was downloaded (its second field, seconds since 1970 in
// hex); ok false without a record or a time in it.
func QuarantineTime(path string) (time.Time, bool) {
	b, ok := Xattr(path, "com.apple.quarantine", 511)
	if !ok {
		return time.Time{}, false
	}
	return parseQuarantineTime(string(b))
}

func parseQuarantineTime(record string) (time.Time, bool) {
	fields := strings.Split(record, ";")
	if len(fields) < 2 {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(fields[1]), 16, 64)
	if err != nil || sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// Quarantined: the browser (or whatever downloaded it) marked it for Gatekeeper.
func Quarantined(path string) bool {
	_, ok := Xattr(path, "com.apple.quarantine", 0)
	return ok
}

// packageExtensions are folders the Finder shows as one file.
var packageExtensions = map[string]bool{"app": true, "bundle": true, "framework": true, "plugin": true, "kext": true, "appex": true,
	"xpc": true, "pkg": true, "mpkg": true, "rtfd": true, "prefpane": true, "qlgenerator": true, "mdimporter": true, "saver": true,
	"wdgt": true, "systemextension": true, "dext": true, "photoslibrary": true, "musiclibrary": true, "tvlibrary": true,
	"photolibrary": true, "aplibrary": true, "fcpbundle": true, "logicx": true, "band": true, "xcodeproj": true,
	"xcworkspace": true, "playground": true, "xcarchive": true, "docarchive": true, "sparsebundle": true, "imovielibrary": true,
	"theater": true, "pages": true, "numbers": true, "key": true, "download": true, "scptd": true, "workflow": true,
	"action": true, "component": true, "vst": true, "vst3": true, "lproj": false}

// IsPackage: a folder the Finder shows as one file (an app, a bundle, a library), by its extension.
func IsPackage(path string) bool {
	e, ok := Item(path)
	return ok && e.IsDir && packageExtensions[strings.ToLower(PathExtension(path))]
}

// lettersOf is the letters of s, lowercased (Foundation's CharacterSet.letters: letters and marks).
func lettersOf(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsMark(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
