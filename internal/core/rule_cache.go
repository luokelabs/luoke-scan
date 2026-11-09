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

// CacheUsers are the programs that use each cache. While one of them runs, automatic cleaning leaves that cache for
// the next round. Every entry of KnownCaches needs one: one without is never cleaned automatically (CacheIdle).
var CacheUsers = map[string][]string{
	"pip": {"pip", "pip3"}, "swiftpm": {"swift-build", "swift-package", "swift-test", "swift-run", "xcodebuild", "Xcode"},
	"go-build": {"go", "gopls"}, "xcode-deriveddata": {"Xcode", "xcodebuild", "SourceKitService"},
	"cargo-registry-cache": {"cargo", "rustc"}, "cargo-registry-src": {"cargo", "rustc", "rust-analyzer"},
	"bun": {"bun"}, "uv": {"uv"}, "npm": {"npm", "npx"},
	// brew runs as bash, then Homebrew's own ruby. Homebrew's yarn runs as yarn.js.
	"homebrew": {"brew", "ruby"}, "yarn": {"yarn", "yarn.js"}, "cocoapods": {"pod"},
	"gradle-caches": {"gradle", "gradlew", "java"}, "gradle-wrapper": {"gradle", "gradlew", "java"},
	"poetry-cache": {"poetry"}, "poetry-artifacts": {"poetry"}, "node-gyp": {"node-gyp", "npm", "npx"},
	"composer": {"composer"}, "xcode-documentation": {"Xcode"},
	"coresimulator-caches": {"Simulator", "simctl", "com.apple.CoreSimulator.CoreSimulatorService", "launchd_sim", "Xcode", "xcodebuild"},
}

// KnownCaches are the caches looked for.
var KnownCaches = []RebuildableCache{
	// Not `pip cache purge`: an older pip (e.g. the system one) leaves a newer pip's http-v2 cache behind.
	{ID: "pip", Path: "Library/Caches/pip", Tool: "pip", Clean: "删除这个文件夹"},
	{ID: "swiftpm", Path: "Library/Caches/org.swift.swiftpm", Tool: "SwiftPM", Clean: "删除这个文件夹"},
	{ID: "go-build", Path: "Library/Caches/go-build", Tool: "Go", Clean: "go clean -cache", Command: "go",
		Env: map[string]string{"GOCACHE": "Library/Caches/go-build"}},
	{ID: "xcode-deriveddata", Path: "Library/Developer/Xcode/DerivedData", Tool: "Xcode", Clean: "删除这个文件夹（Xcode 没开着时）"},
	{ID: "cargo-registry-cache", Path: ".cargo/registry/cache", Tool: "Cargo", Clean: "删除这个文件夹"},
	{ID: "cargo-registry-src", Path: ".cargo/registry/src", Tool: "Cargo", Clean: "删除这个文件夹"},
	{ID: "bun", Path: ".bun/install/cache", Tool: "Bun", Clean: "删除这个文件夹"},
	{ID: "uv", Path: ".cache/uv", Tool: "uv", Clean: "uv cache clean", Command: "uv", Env: map[string]string{"UV_CACHE_DIR": ".cache/uv"}},
	// npm's own cache only; ~/.npm/_npx holds packages that running tools (e.g. MCP servers) use.
	{ID: "npm", Path: ".npm/_cacache", Tool: "npm", Clean: "npm cache clean --force", Command: "npm",
		Env: map[string]string{"npm_config_cache": ".npm"}},
	// Downloaded bottles, sources and the formula list; not `brew cleanup`, which also removes old installed versions.
	{ID: "homebrew", Path: "Library/Caches/Homebrew", Tool: "Homebrew", Clean: "删除这个文件夹"},
	// Yarn 1's download cache. Not Yarn 2+'s global cache (~/.yarn/berry/cache): Plug'n'Play projects load their
	// packages straight from it, and nothing fetches them again until an install.
	{ID: "yarn", Path: "Library/Caches/Yarn", Tool: "Yarn", Clean: "删除这个文件夹"},
	{ID: "cocoapods", Path: "Library/Caches/CocoaPods", Tool: "CocoaPods", Clean: "删除这个文件夹"},
	{ID: "gradle-caches", Path: ".gradle/caches", Tool: "Gradle", Clean: "删除这个文件夹（Gradle 没在跑时）"},
	{ID: "gradle-wrapper", Path: ".gradle/wrapper/dists", Tool: "Gradle", Clean: "删除这个文件夹（各项目的 gradlew 用到时会重新下载）"},
	// Not all of pypoetry: its virtualenvs (the projects' environments) live there too.
	{ID: "poetry-cache", Path: "Library/Caches/pypoetry/cache", Tool: "Poetry", Clean: "删除这个文件夹"},
	{ID: "poetry-artifacts", Path: "Library/Caches/pypoetry/artifacts", Tool: "Poetry", Clean: "删除这个文件夹"},
	// Not Deno's folder (its location_data holds apps' local databases), not pre-commit's (it keeps the unstaged
	// changes it set aside while hooks run there, as patches).
	{ID: "node-gyp", Path: "Library/Caches/node-gyp", Tool: "node-gyp", Clean: "删除这个文件夹"},
	{ID: "composer", Path: "Library/Caches/composer", Tool: "Composer", Clean: "删除这个文件夹"},
	{ID: "xcode-documentation", Path: "Library/Developer/Xcode/DocumentationCache", Tool: "Xcode", Clean: "删除这个文件夹（Xcode 没开着时）"},
	// Shared caches the simulators build on first boot; not Devices (the simulators and the apps' data in them).
	{ID: "coresimulator-caches", Path: "Library/Developer/CoreSimulator/Caches", Tool: "模拟器", Clean: "删除这个文件夹（模拟器没开着时）"},
}

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
