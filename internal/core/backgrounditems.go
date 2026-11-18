package core

import (
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// What System Settings → General → Login Items & Extensions lists (macOS 13 and later: 「登录时打开」 and 「允许在后台」)
// is kept in one NSKeyedArchiver archive per format version, BackgroundItems-v<N>.btm. Some macOS versions let every
// user read it; others list its folder only with Full Disk Access (then it is said to be unread). Its
// shape, as the public tools that read it describe it (objective-see's DumpBTM, plaso, bgiparser): $top's "store" is a
// Storage object whose itemsByUserIdentifier maps each user's generated UID to a list of ItemRecord objects, each with
// name, identifier, container (the identifier of the item it belongs to), url, bundleIdentifier,
// associatedBundleIdentifiers, type and disposition. Only reading; nothing is changed or registered.

// BackgroundItemsDir is where the archives are on this Mac.
const BackgroundItemsDir = "/private/var/db/com.apple.backgroundtaskmanagement"

// RootUserUUID is root's generated UID: the system's launchd daemons are listed under it.
const RootUserUUID = "FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"

// An item's type and disposition bits (as DumpBTM names them).
const (
	btmApp       int64 = 0x2
	btmLoginItem int64 = 0x4
	btmAgent     int64 = 0x8
	btmDaemon    int64 = 0x10
	btmLegacy    int64 = 0x10000
	btmHidden    int64 = 0x4 // disposition: not shown in System Settings
)

// BackgroundItem is one record of the archive.
type BackgroundItem struct {
	User                        string // the generated UID of the user it is listed under
	Name, Identifier, Container string
	URL                         string // as written: a file URL, or one relative to the app it is in
	BundleID                    string
	Associated                  []string
	Type, Disposition           int64
}

var btmName = regexp.MustCompile(`^BackgroundItems-v([0-9]{1,4})\.btm$`)

// newestBackgroundItems is the archive of the highest format version in dir ("" none).
func newestBackgroundItems(dir string) string {
	best, at := -1, ""
	for _, p := range Children(dir) {
		m := btmName.FindStringSubmatch(filepath.Base(p))
		if m == nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil && n > best {
			best, at = n, p
		}
	}
	return at
}

// ReadBackgroundItems reads the newest archive in dir. No archive (an older macOS, dir "") is no items and no why;
// why says what went wrong when there is one and it could not be read, or not as expected (a later macOS may write
// it differently): then nothing of it is used.
func ReadBackgroundItems(dir string) ([]BackgroundItem, string) {
	if dir == "" {
		return nil, ""
	}
	// Without Full Disk Access some macOS versions do not let the folder be listed: not read, not 「none」.
	if _, err := os.ReadDir(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ""
		}
		return nil, "读不了「登录项与扩展」的记录"
	}
	path := newestBackgroundItems(dir)
	if path == "" {
		return nil, ""
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ""
		}
		return nil, "读不了「登录项与扩展」的记录"
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > 16<<20 {
		return nil, "读不了「登录项与扩展」的记录"
	}
	data, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return nil, "读不了「登录项与扩展」的记录"
	}
	v, err := DecodePlist(data)
	if err != nil {
		return nil, "「登录项与扩展」的记录读不懂"
	}
	items, ok := backgroundItems(v)
	if !ok {
		return nil, "「登录项与扩展」的记录读不懂"
	}
	return items, ""
}

// backgroundItems are the records in a decoded archive; ok false when it is not shaped as expected.
func backgroundItems(v any) ([]BackgroundItem, bool) {
	a, top, ok := readKeyedArchive(v)
	if !ok {
		return nil, false
	}
	store, ok := a.object(top["store"])
	if !ok {
		return nil, false
	}
	users, ok := a.dict(store["itemsByUserIdentifier"])
	if !ok {
		return nil, false
	}
	var out []BackgroundItem
	for user, list := range users {
		records, ok := a.list(list)
		if !ok {
			return nil, false
		}
		for _, r := range records {
			o, ok := r.(map[string]any)
			if !ok {
				continue
			}
			typ, ok1 := a.num(o["type"])
			disp, ok2 := a.num(o["disposition"])
			if !ok1 || !ok2 {
				continue // not a record as known: left out rather than guessed at
			}
			out = append(out, BackgroundItem{User: strings.ToUpper(user), Name: a.str(o["name"]),
				Identifier: a.str(o["identifier"]), Container: a.str(o["container"]), URL: a.url(o["url"]),
				BundleID: a.str(o["bundleIdentifier"]), Associated: a.strings(o["associatedBundleIdentifiers"]),
				Type: typ, Disposition: disp})
		}
	}
	return out, true
}

// fileURLPath is the path of an absolute file URL ("" for anything else: a relative one, another scheme).
func fileURLPath(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "file" || (u.Host != "" && u.Host != "localhost") || !strings.HasPrefix(u.Path, "/") {
		return ""
	}
	return strings.TrimSuffix(u.Path, "/")
}

// CurrentUserUUID is this user's generated UID, the key of their items in the archive ("" not known).
func CurrentUserUUID() string {
	res := Run("/usr/bin/dsmemberutil", []string{"getuuid", "-u", strconv.Itoa(os.Getuid())}, RunOpts{Timeout: 5 * time.Second})
	s := strings.ToUpper(strings.TrimSpace(res.Stdout))
	if res.Status != 0 || !uuidShape.MatchString(s) {
		return ""
	}
	return s
}

var uuidShape = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`)

// leftBehind is what an app no longer on this Mac left in Login Items & Extensions, by the app.
type leftBehind struct {
	client string   // the app's bundle id
	name   string   // as Login Items & Extensions shows it ("" not known)
	items  []string // what is there: the items' names, the launchd jobs' plists
	// starts: one of them is a launchd job whose program is still there, so it goes on starting; an item only in the
	// archive had its program in the app that was deleted, and only its switch is left in System Settings.
	starts bool
	daemon bool // one of those still starting is a launchd daemon (runs as root)
}

// appGone: an app's bundle at path is not there, where that can be told: an absolute path, not on another volume
// (it may be unplugged), not in another user's home (not ours to look at), not where this round does not look.
func appGone(ctx *Context, path string) bool {
	if !strings.HasPrefix(path, "/") || !strings.HasSuffix(strings.ToLower(path), ".app") || strings.HasPrefix(path, "/Volumes/") {
		return false
	}
	if strings.HasPrefix(path, "/Users/") && !inHome(ctx, path) {
		return false
	}
	if !ctx.MayLook(path) {
		return false
	}
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// inHome: path is in the round's home, however the home is spelled.
func inHome(ctx *Context, path string) bool {
	p := strings.ToLower(Standardized(path))
	for _, h := range ctx.spellings() {
		if strings.HasPrefix(p, h+"/") {
			return true
		}
	}
	return false
}

// backgroundLeftovers are the archive's items of apps no longer on this Mac, for user (and the system's; "" every
// user's): the app's own item, and those in it (container). Only items System Settings shows; not the launchd jobs
// written as files (legacy: launchdLeftovers reads those files), not the developers' groups or other kinds. An app
// counts as gone only when its bundle is not where the item says and none of its bundle ids is installed anywhere.
func backgroundLeftovers(ctx *Context, items []BackgroundItem, user string, apps InstalledApps) map[string]*leftBehind {
	byID := map[string]BackgroundItem{}
	for _, it := range items {
		if it.Identifier != "" {
			byID[it.User+"\x00"+it.Identifier] = it
		}
	}
	out := map[string]*leftBehind{}
	for _, it := range items {
		if user != "" && it.User != user && it.User != RootUserUUID {
			continue
		}
		if it.Disposition&btmHidden != 0 || it.Type&btmLegacy != 0 || it.Type&(btmApp|btmLoginItem|btmAgent|btmDaemon) == 0 {
			continue
		}
		owner := it
		if it.Container != "" {
			p, ok := byID[it.User+"\x00"+it.Container]
			if !ok {
				continue
			}
			owner = p
		}
		path := fileURLPath(owner.URL)
		if path == "" || !appGone(ctx, path) {
			continue
		}
		ids := uniqueStrings(append(append([]string{owner.BundleID, it.BundleID}, owner.Associated...), it.Associated...))
		if len(ids) == 0 {
			continue
		}
		covered := false
		for _, id := range ids {
			covered = covered || strings.HasPrefix(strings.ToLower(id), "com.apple.") || apps.Covers(id)
		}
		if covered {
			continue
		}
		client := ids[0]
		l := out[strings.ToLower(client)]
		if l == nil {
			l = &leftBehind{client: client}
			out[strings.ToLower(client)] = l
		}
		if l.name == "" {
			l.name = owner.Name
			if l.name == "" {
				l.name = NameWithoutExtension(path)
			}
		}
		name := it.Name
		if name == "" {
			name = NameWithoutExtension(path)
		}
		l.items = uniqueStrings(append(l.items, name)) // its program was in the deleted app: nothing starts
	}
	return out
}

// launchdLeftovers are the launchd jobs that name the apps they belong to (AssociatedBundleIdentifiers, macOS 13 and
// later; Login Items & Extensions lists them under that app) when none of those apps is on this Mac any more and the
// job's program still is: it goes on starting. A job whose program is gone is the persistence rule's
// (persistence.daemon-missing, persistence.launchagent-missing); a disabled one does not start.
func launchdLeftovers(ctx *Context, apps InstalledApps) map[string]*leftBehind {
	type dir struct {
		path   string
		daemon bool
	}
	dirs := []dir{{filepath.Join(ctx.Home, "Library/LaunchAgents"), false}}
	if ctx.SystemLibrary != "" {
		dirs = append(dirs, dir{filepath.Join(ctx.SystemLibrary, "LaunchAgents"), false}, dir{filepath.Join(ctx.SystemLibrary, "LaunchDaemons"), true})
	}
	out := map[string]*leftBehind{}
	for _, d := range dirs {
		for _, f := range Children(d.path) {
			if PathExtension(f) != "plist" {
				continue
			}
			plist, ok := readJobPlist(f)
			if !ok {
				continue
			}
			if off, _ := plist["Disabled"].(bool); off {
				continue
			}
			ids := uniqueStrings(appsPlistStrings(plist["AssociatedBundleIdentifiers"]))
			if s, ok := plist["AssociatedBundleIdentifiers"].(string); ok {
				ids = uniqueStrings(append(ids, s))
			}
			if len(ids) == 0 {
				continue
			}
			program, ok := jobProgram(plist)
			if !ok || !strings.HasPrefix(program, "/") || !ctx.MayLook(program) || !Exists(program) {
				continue
			}
			covered := false
			for _, id := range ids {
				covered = covered || strings.HasPrefix(strings.ToLower(id), "com.apple.") || apps.Covers(id)
			}
			if covered {
				continue
			}
			client := ids[0]
			l := out[strings.ToLower(client)]
			if l == nil {
				l = &leftBehind{client: client}
				out[strings.ToLower(client)] = l
			}
			l.items = uniqueStrings(append(l.items, f))
			l.starts = true
			l.daemon = l.daemon || d.daemon
		}
	}
	return out
}

// uniqueStrings: the non-empty ones, each once, in order.
func uniqueStrings(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
