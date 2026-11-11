package core

import (
	"path/filepath"
	"strings"
)

func init() { Register("cache.rebuildable", NewCacheRule) }

// RebuildableCache is a cache its tool rebuilds on demand. Deleting it loses no user data, so it is the only kind of
// finding that may be safe (and, once the user agrees, cleaned automatically: ADR 0016 revision 10-20).
type RebuildableCache struct {
	ID string
	// Path is relative to the home.
	Path string
	Tool string
	// Clean is how the tool itself clears it, shown to the user and preferred over deleting the folder.
	Clean string
	// Command is the command Clean needs; "" when Clean is just deleting the folder.
	Command string
	// Env is what points the command at this cache (values relative to the home), so its clean empties the folder
	// that was reported: not one the tool is configured elsewhere for, not the real account's when home is a fake one.
	Env map[string]string
}

// CacheUsers are the programs that use each cache (rules/caches.json: users). While one of them runs, automatic
// cleaning leaves that cache for the next round. Every entry of KnownCaches needs one: one without is never cleaned
// automatically (CacheIdle).
var CacheUsers map[string][]string

// KnownCaches are the caches looked for (rules/caches.json; why each is there, and the places that look like caches
// but are not, are written beside them). Being here makes a cache reported and cleaned when the user clicks; going
// without a click is autoCaches'.
var KnownCaches []RebuildableCache

// CacheIdle says whether nothing that uses cache id is running, so automatic cleaning may take it now. A cache whose
// users are not written down is never idle: not knowing what uses it, nothing says it is not in use.
func CacheIdle(id string, running map[string]bool) bool {
	users := CacheUsers[id]
	if len(users) == 0 {
		return false
	}
	for _, u := range users {
		if running[u] {
			return false
		}
	}
	return true
}

// CommandExists says whether a command is installed in the usual places (launchd jobs get a minimal PATH, so PATH
// alone would miss most of them).
func CommandExists(command, home string) bool { return CommandPath(command, home) != "" }

// CommandPath is where a command is installed, or "".
func CommandPath(command, home string) string {
	dirs := []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/usr/local/go/bin"}
	for _, d := range []string{".local/bin", ".cargo/bin", ".bun/bin", "go/bin"} {
		dirs = append(dirs, filepath.Join(home, d))
	}
	for _, v := range Children(filepath.Join(home, ".nvm/versions/node")) {
		dirs = append(dirs, filepath.Join(v, "bin"))
	}
	for _, d := range dirs {
		if p := filepath.Join(d, command); IsExecutable(p) {
			return p
		}
	}
	return ""
}

// CacheRule reports the rebuildable caches big enough to mention.
type CacheRule struct {
	Caches []RebuildableCache
	// MinBytes: below this a cache is not worth mentioning.
	MinBytes int64
	// Installed says whether a command is installed (when the tool is gone, its cache is cleaned by deleting the
	// folder). nil: CommandExists.
	Installed func(command, home string) bool
}

// NewCacheRule makes the rule; for a fake home the installed commands are its fakes'.
func NewCacheRule(l *Layout, f *Fakes) Rule {
	r := &CacheRule{Caches: KnownCaches, MinBytes: 50 * 1_048_576}
	if l != nil {
		installed := spaceSet(f.InstalledCommands...)
		r.Installed = func(command, _ string) bool { return installed[command] }
	}
	return r
}

func (r *CacheRule) ID() string      { return "cache.rebuildable" }
func (r *CacheRule) Emits() []string { return []string{"cache.rebuildable"} }

func (r *CacheRule) Run(ctx *Context) ([]Finding, error) {
	if cachesErr != nil {
		return nil, rulesMissing("caches.json")
	}
	installed := r.Installed
	if installed == nil {
		installed = CommandExists
	}
	var found []Finding
	var left []string
	for _, c := range r.Caches {
		path := filepath.Join(ctx.Home, c.Path)
		// Where macOS asks the user first (another app's container, without Full Disk Access): not even whether it is there.
		if !ctx.MayLook(path) {
			seen := false
			for _, t := range left {
				seen = seen || t == c.Tool
			}
			if !seen {
				left = append(left, c.Tool)
			}
			continue
		}
		if !Exists(path) {
			continue
		}
		size := AllocatedSize(path)
		if size < r.MinBytes {
			continue
		}
		clean := c.Clean
		if c.Command != "" && !installed(c.Command, ctx.Home) {
			clean = "删除这个文件夹（" + c.Tool + " 已经不在这台 Mac 上了）"
		}
		found = append(found, Finding{Rule: "cache.rebuildable." + c.ID, Category: CatCache, Severity: Low, Verdict: Safe, Path: path,
			Bytes: Size(size), Title: c.Tool + " 的缓存，删了会自动重建",
			Evidence: map[string]string{"tool": c.Tool, "clean": clean, "size": FormatBytes(size)}})
	}
	if len(left) > 0 {
		return nil, Skip(NotLooked(strings.Join(left, "、")+" 的缓存"), found...)
	}
	return found, nil
}
