package core

import (
	"path/filepath"
	"strings"
	"time"
)

// Context is where a round looks and what "now" is. Tests point everything at a fake home and fix the clock.
type Context struct {
	Home         string
	Tmp          string   // the per-user temp folder; "" none
	ProjectRoots []string // folders whose direct children are projects
	Now          time.Time
	StaleAfter   time.Duration // how long untouched before something counts as stale (182 days)
	Store        *Store        // nil: rules that need history skip
	Tools        Tools
	TCCDatabases []string
	AppDirs      []string
	// SystemLibrary is the system's /Library ("" not looked at); Receipts, /var/db/receipts.
	SystemLibrary, Receipts string
	// FullDiskAccess: nil not known (tests, a fixture: everything is looked at); false: the folders macOS asks about
	// are left alone and said to be.
	FullDiskAccess *bool
	// AccessOff: the user switched Full Disk Access off for this app (FullDiskAccess is false then), and macOS may
	// still allow it. What only macOS would have stopped is stopped here: PrivacyPlaces, the TCC databases.
	AccessOff bool
	Cancelled func() bool
	// Replays are the journal replays made this round, shared by the rules that ask (space and temp both replay the
	// temp folder). RunRound gives every round a new one; nil: each replays on its own.
	Replays       *JournalCache
	homeSpellings []string
}

// NewContext fills the defaults: the user's and the system's TCC databases, the usual app folders, 182 days.
func NewContext(home string) Context {
	c := Context{Home: home, Now: time.Now(), StaleAfter: 182 * 24 * time.Hour,
		TCCDatabases: []string{filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db"), "/Library/Application Support/com.apple.TCC/TCC.db"},
		AppDirs:      []string{"/Applications", filepath.Join(home, "Applications"), "/System/Applications"},
		Cancelled:    func() bool { return false }}
	return c
}

// Guarded are the folders under the home macOS asks about before an app looks inside (without Full Disk Access).
var Guarded = []string{"Desktop", "Documents", "Downloads", "Music", "Movies/TV", "Library/Photos", "Library/Mobile Documents",
	"Library/CloudStorage", "Library/Containers", "Library/Daemon Containers", "Library/Group Containers"}

// PrivacyPlaces are the folders under the home macOS refuses without Full Disk Access, with no dialog: no check has to
// stay out of them, macOS keeps it out. With access switched off (AccessOff) MayLook keeps it out instead.
var PrivacyPlaces = []string{"Library/Mail", "Library/Messages", "Library/Safari", "Library/Cookies", "Library/Calendars",
	"Library/Reminders", "Library/HomeKit", "Library/Metadata", "Library/IdentityServices", "Library/Suggestions",
	"Library/Biome", "Library/Accounts", "Library/PersonalizationPortrait", "Library/Application Support/AddressBook",
	"Library/Application Support/com.apple.TCC", "Library/Application Support/CallHistoryDB",
	"Library/Application Support/Knowledge", "Library/Application Support/com.apple.sharedfilelist"}

var switchedOffPlaces = append(append([]string(nil), Guarded...), PrivacyPlaces...)

// NoAccessMark starts every reason a check left something out for want of Full Disk Access.
const NoAccessMark = "没有完全磁盘访问"

// NotLooked is the reason for what was left out without Full Disk Access.
func NotLooked(what string) string {
	return NoAccessMark + "，" + what + "没看（看了 macOS 会弹框问你）"
}

func (c *Context) spellings() []string {
	if c.homeSpellings == nil {
		seen := map[string]bool{}
		for _, h := range []string{Standardized(c.Home), Canonical(c.Home)} {
			for _, s := range []string{h, "/System/Volumes/Data" + h} {
				seen[strings.ToLower(s)] = true
			}
		}
		for s := range seen {
			c.homeSpellings = append(c.homeSpellings, s)
		}
	}
	return c.homeSpellings
}

// MayLook says whether this round may look at path: anywhere with Full Disk Access (or not knowing), else nowhere at
// or inside a guarded folder, or a privacy place when access is switched off (compared as spelled from the home,
// ignoring case). The path is Standardized, as the Swift version's standardizedFileURL: a deleted program under
// /private/var/… is looked at (the goldens record it).
func (c *Context) MayLook(path string) bool {
	if c.FullDiskAccess == nil || *c.FullDiskAccess {
		return true
	}
	places := Guarded
	if c.AccessOff {
		places = switchedOffPlaces
	}
	p := strings.ToLower(Standardized(path))
	if strings.Contains(p, ".photoslibrary") { // wherever it was put: macOS asks about Photos, not this folder
		return false
	}
	for _, h := range c.spellings() {
		for _, g := range places {
			base := h + "/" + strings.ToLower(g)
			if p == base || strings.HasPrefix(p, base+"/") {
				return false
			}
		}
	}
	return true
}

// Shown is a path as the user sees it: ~/… resolved, except one this round may not look at, shown as spelled.
func (c *Context) Shown(path string) string {
	if c.MayLook(path) {
		return HomeRelative(path, c.Home)
	}
	p, h := Standardized(path), Standardized(c.Home)
	if strings.HasPrefix(p, h+"/") {
		return "~" + p[len(h):]
	}
	return p
}

// IsCancelled says whether the round should stop.
func (c *Context) IsCancelled() bool { return c.Cancelled != nil && c.Cancelled() }
