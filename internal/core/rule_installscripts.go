package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// InstallScriptsRule: package managers that let the packages they install run scripts of their own while installing
// (npm's preinstall/install/postinstall, pip building a source package with its setup.py). Only a tool that is used
// here (its user config, cache or folder is there), and only when this Mac's copy of it runs those scripts: a version
// that does so by default (found on disk, never guessed) and the user's own config not turning it off, or the user's
// config turning it on. Only the user's own config files are read, never a project's. One finding per tool, to
// confirm; the fix offered appends one line to that user config (internal/service), only when one line does it.
type InstallScriptsRule struct {
	// UsrLocal, OptHomebrew are /usr/local and /opt/homebrew (a fake home's own folders).
	UsrLocal, OptHomebrew string
	// MaxProjects, MaxManifests bound the look at the known projects' installed packages.
	MaxProjects, MaxManifests int
}

// InstallScriptsRuleID is the rule's name and its findings' rule.
const InstallScriptsRuleID = "pkg.install-scripts"

func init() { Register(InstallScriptsRuleID, NewInstallScriptsRule) }

// NewInstallScriptsRule reads only files: for a fake home, its usr-local/ and opt-homebrew/ stand for the system's.
func NewInstallScriptsRule(l *Layout, f *Fakes) Rule {
	r := &InstallScriptsRule{UsrLocal: "/usr/local", OptHomebrew: "/opt/homebrew", MaxProjects: 100, MaxManifests: 4000}
	if l != nil {
		r.UsrLocal, r.OptHomebrew = filepath.Join(l.Root, "usr-local"), filepath.Join(l.Root, "opt-homebrew")
	}
	return r
}

func (r *InstallScriptsRule) ID() string      { return InstallScriptsRuleID }
func (r *InstallScriptsRule) Emits() []string { return []string{InstallScriptsRuleID} }

// ScriptsTool is one package manager: where its user config is, and the line that turns the scripts off there.
type ScriptsTool struct {
	ID, Name string
	// Line is what "改成不跑" appends; NewFile what it writes when there is no such file yet ("" Line).
	Line, NewFile string
}

// ScriptsTools are the tools the fix knows, by id.
var ScriptsTools = map[string]ScriptsTool{
	"npm":  {ID: "npm", Name: "npm", Line: "ignore-scripts=true", NewFile: "ignore-scripts=true\n"},
	"yarn": {ID: "yarn", Name: "Yarn", Line: "enableScripts: false", NewFile: "enableScripts: false\n"},
	"pip":  {ID: "pip", Name: "pip", Line: "only-binary = :all:", NewFile: "[global]\nonly-binary = :all:\n"},
	"uv":   {ID: "uv", Name: "uv", Line: "no-build = true", NewFile: "no-build = true\n"},
	"pnpm": {ID: "pnpm", Name: "pnpm"},
}

// maxConfigBytes: a user config bigger than this is not read (nor changed).
const maxConfigBytes = 256 << 10

// ScriptsConfigPath is the user config of a tool the fix writes to, under home; "" none.
func ScriptsConfigPath(tool, home string) string {
	switch tool {
	case "npm":
		return filepath.Join(home, ".npmrc")
	case "yarn":
		return filepath.Join(home, ".yarnrc.yml")
	case "uv":
		return filepath.Join(home, ".config/uv/uv.toml")
	case "pip":
		// pip on macOS: this one when its folder is there, else the XDG one. Not followed: a link there is not looked
		// through (it may lead into a guarded folder), and the fix does not write through it (LinkOnPath).
		if _, err := os.Lstat(filepath.Join(home, "Library/Application Support/pip")); err == nil {
			return filepath.Join(home, "Library/Application Support/pip/pip.conf")
		}
		return filepath.Join(home, ".config/pip/pip.conf")
	}
	return ""
}

// pipConfigs are the user pip.conf files pip reads, in the order it reads them (a later one wins).
func pipConfigs(home string) []string {
	return []string{filepath.Join(home, ".pip/pip.conf"), filepath.Join(home, ".config/pip/pip.conf"),
		filepath.Join(home, "Library/Application Support/pip/pip.conf")}
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// lexists: something is at p, a link counted as itself (not followed).
func lexists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// readConfig reads a user config: its text, whether it is there, and whether it is a link, symbolic or hard (another
// name shares the file): read through it, never changed. Too big, or not a file: not there.
func readConfig(p string) (text string, there, link bool) {
	st, err := os.Lstat(p)
	if err != nil {
		return "", false, false
	}
	link = st.Mode()&os.ModeSymlink != 0
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink > 1 {
		link = true
	}
	if st.Mode()&os.ModeSymlink != 0 {
		if st, err = os.Stat(p); err != nil {
			return "", false, true
		}
	}
	if !st.Mode().IsRegular() || st.Size() > maxConfigBytes {
		return "", false, link
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false, link
	}
	return string(b), true, link
}

// ---------------------------------------------------------------- the config formats, just enough of each

// configLines are a file's lines.
func configLines(text string) []string {
	return strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
}

// unquote takes the quotes off a value written "x" or 'x'.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// cutComment drops a comment after an unquoted value (" #…", " ;…" for INI; " #…" for YAML and TOML).
func cutComment(v, marks string) string {
	v = strings.TrimSpace(v)
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		if i := strings.IndexByte(v[1:], v[0]); i >= 0 {
			return v[:i+2]
		}
		return v
	}
	for i := 0; i < len(v); i++ {
		if strings.IndexByte(marks, v[i]) >= 0 && (i == 0 || v[i-1] == ' ' || v[i-1] == '\t') {
			return strings.TrimSpace(v[:i])
		}
	}
	return v
}

// iniValues: every value of key in an INI file (npmrc, pnpm's rc, pip.conf), in order, with the section it is in
// ("" before any). Names compare with _ as - (pip's spelling rule). Comment lines start with # or ;.
func iniValues(text, key string) (values []string, sections []string) {
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "_", "-")) }
	section := ""
	for _, raw := range configLines(text) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			if i := strings.IndexByte(line, ']'); i > 0 {
				section = strings.ToLower(strings.TrimSpace(line[1:i]))
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			k, v, ok = strings.Cut(line, ":") // configparser takes both
			if !ok {
				continue
			}
		}
		if norm(k) == norm(key) {
			values = append(values, unquote(cutComment(v, "#;")))
			sections = append(sections, section)
		}
	}
	return values, sections
}

// iniSections are the section names an INI file has, in order.
func iniSections(text string) []string {
	var out []string
	for _, raw := range configLines(text) {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			if i := strings.IndexByte(line, ']'); i > 0 {
				out = append(out, strings.ToLower(strings.TrimSpace(line[1:i])))
			}
		}
	}
	return out
}

// topValues: every value of a top-level key in a YAML (sep ":") or TOML (sep "=") file: not indented, and for TOML
// before the first [table]. tables: the TOML file has a table (a line appended at its end would land in it).
func topValues(text, key, sep string) (values []string, tables bool) {
	for _, raw := range configLines(text) {
		if raw == "" || raw[0] == ' ' || raw[0] == '\t' || raw[0] == '#' {
			continue
		}
		line := strings.TrimSpace(raw)
		if sep == "=" && strings.HasPrefix(line, "[") {
			tables = true
			continue
		}
		if tables {
			continue
		}
		k, v, ok := strings.Cut(line, sep)
		if ok && unquote(strings.TrimSpace(k)) == key {
			values = append(values, unquote(cutComment(v, "#")))
		}
	}
	return values, tables
}

func last(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[len(xs)-1]
}

// ---------------------------------------------------------------- versions found on disk

type foundVersion struct {
	major, minor int
	text, where  string
}

// parseToolVersion reads "11.6.2" (a leading v allowed); ok false for anything else.
func parseToolVersion(s, where string) (foundVersion, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return foundVersion{}, false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || ma < 0 || mi < 0 {
		return foundVersion{}, false
	}
	return foundVersion{ma, mi, s, where}, true
}

func (v foundVersion) before(major, minor int) bool {
	return v.major < major || (v.major == major && v.minor < minor)
}

// manifest is the part of a package.json this rule reads.
type manifest struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	Scripts        map[string]any    `json:"scripts"`
	PackageManager string            `json:"packageManager"`
	Deps           map[string]string `json:"dependencies"`
}

func readManifest(ctx *Context, p string) (manifest, bool) {
	var m manifest
	if !ctx.MayFollow(p) {
		return m, false
	}
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return m, false
	}
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &m) != nil {
		return m, false
	}
	return m, true
}

// nodeLibs are the lib/node_modules folders of the Node.js installs looked at: Homebrew's, the Node.js installer's,
// and the version managers' under the home (nvm, fnm, Volta, mise, asdf).
func (r *InstallScriptsRule) nodeLibs(ctx *Context) []string {
	home := ctx.Home
	out := []string{filepath.Join(r.OptHomebrew, "lib/node_modules"), filepath.Join(r.UsrLocal, "lib/node_modules")}
	for _, pattern := range []string{".nvm/versions/node/*/lib/node_modules", "Library/Application Support/fnm/node-versions/*/installation/lib/node_modules",
		".local/share/fnm/node-versions/*/installation/lib/node_modules", ".volta/tools/image/node/*/lib/node_modules",
		".local/share/mise/installs/node/*/lib/node_modules", ".asdf/installs/nodejs/*/lib/node_modules"} {
		// Listed only when no link on the way to the first wildcard leads into a guarded folder.
		if !ctx.MayFollow(filepath.Join(home, pattern[:strings.Index(pattern, "*")])) {
			continue
		}
		m, _ := filepath.Glob(filepath.Join(home, pattern))
		sort.Strings(m)
		out = append(out, m...)
	}
	return out
}

// globalVersions: the versions of a package installed globally in any of the Node.js installs (npm itself, pnpm).
func (r *InstallScriptsRule) globalVersions(ctx *Context, pkg string) []foundVersion {
	var out []foundVersion
	for _, lib := range r.nodeLibs(ctx) {
		p := filepath.Join(lib, pkg, "package.json")
		if m, ok := readManifest(ctx, p); ok {
			if v, ok := parseToolVersion(m.Version, filepath.Join(lib, pkg)); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- the known projects' installed packages

// scriptedPackages: per tool, the packages installed in the known projects that run a script when installed
// (preinstall, install, postinstall; or a binding.gyp, which npm builds with node-gyp). Which tool installed a
// project's packages is told by its lock file. Bounded: at most MaxProjects projects and MaxManifests package.json.
func (r *InstallScriptsRule) scriptedPackages(ctx *Context) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	read, projects := 0, 0
	add := func(tool, name string) {
		if out[tool] == nil {
			out[tool] = map[string]bool{}
		}
		out[tool][name] = true
	}
	scripted := func(dir string) (string, bool) {
		if read >= r.MaxManifests {
			return "", false
		}
		read++
		m, ok := readManifest(ctx, filepath.Join(dir, "package.json"))
		if !ok || m.Name == "" {
			return "", false
		}
		for _, k := range []string{"preinstall", "install", "postinstall"} {
			if s, ok := m.Scripts[k].(string); ok && strings.TrimSpace(s) != "" {
				return m.Name, true
			}
		}
		if st, err := os.Lstat(filepath.Join(dir, "binding.gyp")); err == nil && st.Mode().IsRegular() {
			return m.Name, true
		}
		return "", false
	}
	// packages: the packages in a node_modules (scoped ones one level down); pnpm's are in .pnpm/<id>/node_modules.
	var packages func(nm string, depth int) []string
	packages = func(nm string, depth int) []string {
		var dirs []string
		for _, c := range Children(nm) {
			name := filepath.Base(c)
			switch {
			case !ctx.MayFollow(c):
				// a link into a guarded folder: not looked through
			case name == ".pnpm" && depth == 0:
				for _, id := range Children(c) {
					dirs = append(dirs, packages(filepath.Join(id, "node_modules"), 1)...)
				}
			case strings.HasPrefix(name, "@"):
				dirs = append(dirs, Children(c)...)
			case !strings.HasPrefix(name, "."):
				dirs = append(dirs, c)
			}
		}
		return dirs
	}
	for _, root := range ctx.ProjectRoots {
		if !ctx.MayFollow(root) { // the root itself may be a link into a guarded folder (~/code → ~/Documents/code)
			continue
		}
		for _, p := range Children(root) {
			if projects >= r.MaxProjects || read >= r.MaxManifests || ctx.IsCancelled() {
				break
			}
			// A project that is a link into a guarded folder is not looked at: following it would make macOS ask.
			if !ctx.MayFollow(p) {
				continue
			}
			nm := filepath.Join(p, "node_modules")
			if st, err := os.Lstat(nm); err != nil || !st.IsDir() {
				continue
			}
			projects++
			tool := "npm"
			switch {
			case lexists(filepath.Join(p, "pnpm-lock.yaml")):
				tool = "pnpm"
			case lexists(filepath.Join(p, "bun.lock")) || lexists(filepath.Join(p, "bun.lockb")):
				tool = "bun"
			case lexists(filepath.Join(p, "yarn.lock")) && lexists(filepath.Join(p, ".yarnrc.yml")):
				tool = "yarn"
			}
			for _, d := range packages(nm, 0) {
				if st, err := os.Lstat(d); err != nil || !st.IsDir() {
					continue // a link (a workspace's own package) is the project's, not a dependency
				}
				if name, ok := scripted(d); ok {
					add(tool, name)
				}
			}
		}
	}
	return out
}

// yarnVersions: the Yarn 2+ versions the known projects ask for (packageManager, a yarnPath release): the ones they
// really run. A version only in corepack's cache is not one anything is known to use.
func (r *InstallScriptsRule) yarnVersions(ctx *Context) []foundVersion {
	var out []foundVersion
	n := 0
	for _, root := range ctx.ProjectRoots {
		if !ctx.MayFollow(root) { // the root itself may be a link into a guarded folder (~/code → ~/Documents/code)
			continue
		}
		for _, p := range Children(root) {
			if n >= r.MaxProjects {
				break
			}
			if !ctx.MayFollow(p) {
				continue // a link into a guarded folder
			}
			n++
			if m, ok := readManifest(ctx, filepath.Join(p, "package.json")); ok && strings.HasPrefix(m.PackageManager, "yarn@") {
				v := strings.SplitN(strings.TrimPrefix(m.PackageManager, "yarn@"), "+", 2)[0]
				if fv, ok := parseToolVersion(v, HomeRelative(p, ctx.Home)); ok && fv.major >= 2 {
					out = append(out, fv)
				}
			}
			releases := filepath.Join(p, ".yarn/releases")
			if !ctx.MayFollow(releases) {
				continue
			}
			for _, rel := range Children(releases) {
				b := filepath.Base(rel)
				if strings.HasPrefix(b, "yarn-") && strings.HasSuffix(b, ".cjs") {
					if fv, ok := parseToolVersion(strings.TrimSuffix(strings.TrimPrefix(b, "yarn-"), ".cjs"), HomeRelative(p, ctx.Home)); ok && fv.major >= 2 {
						out = append(out, fv)
					}
				}
			}
		}
	}
	return out
}

// builtPythonPackages: the packages pip (its cache's locally built wheels) or uv (its cache's source builds) built
// from source here: each build ran the package's own build script.
func builtPythonPackages(ctx *Context, tool string) []string {
	home := ctx.Home
	seen := map[string]bool{}
	budget := 5000
	switch tool {
	case "pip":
		if !ctx.MayFollow(filepath.Join(home, "Library/Caches/pip/wheels")) {
			break
		}
		Tree(filepath.Join(home, "Library/Caches/pip/wheels"), func(Entry) bool { return true }, func(e Entry) bool {
			budget--
			if b := filepath.Base(e.Path); strings.HasSuffix(b, ".whl") {
				if name, _, ok := strings.Cut(b, "-"); ok && name != "" {
					seen[strings.ToLower(strings.ReplaceAll(name, "_", "-"))] = true
				}
			}
			return budget > 0
		})
	case "uv":
		if !ctx.MayFollow(filepath.Join(home, ".cache/uv")) {
			break
		}
		for _, d := range Children(filepath.Join(home, ".cache/uv")) {
			if !strings.HasPrefix(filepath.Base(d), "sdists-v") || !ctx.MayFollow(d) {
				continue
			}
			for _, name := range Children(filepath.Join(d, "pypi")) {
				seen[strings.ToLower(filepath.Base(name))] = true
			}
			for _, index := range Children(filepath.Join(d, "index")) {
				for _, name := range Children(index) {
					seen[strings.ToLower(filepath.Base(name))] = true
				}
			}
		}
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- the rule

// usedBy: the first of the places (relative to home) that is there; "" none. Lstat does not follow the place itself,
// but it does follow links on the way to it (~/.config linked into ~/Documents): those are checked first, so nothing
// in a guarded folder is touched to find out.
func usedBy(ctx *Context, home string, places ...string) string {
	for _, p := range places {
		full := filepath.Join(home, p)
		if !ctx.MayFollow(filepath.Dir(full)) || !ctx.MayLook(full) {
			continue
		}
		if _, err := os.Lstat(full); err == nil {
			return "~/" + p
		}
	}
	return ""
}

// nameList: up to 6 names, then how many more.
func nameList(names []string, sep string) string {
	if len(names) <= 6 {
		return strings.Join(names, sep)
	}
	return strings.Join(names[:6], sep) + " 等 " + strconv.Itoa(len(names)) + " 个"
}

// LinkOnPath: a folder between home and path (path's own folders below the home) is a link or not a folder. One not
// there yet is not (it is made, one folder at a time, when the file is written).
func LinkOnPath(home, path string) bool {
	rel, err := filepath.Rel(home, filepath.Dir(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return true
	}
	if rel == "." {
		return false
	}
	cur := home
	for _, part := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if err != nil {
			return false
		}
		if !st.IsDir() {
			return true
		}
	}
	return false
}

// newest is the newest of the versions found; ok false when none. Several installs side by side (an old Node.js under
// nvm, a new one from Homebrew): which one runs is not known, so only the newest is taken.
func newest(vs []foundVersion) (foundVersion, bool) {
	var best foundVersion
	found := false
	for _, v := range vs {
		if !found || best.before(v.major, v.minor) {
			best, found = v, true
		}
	}
	return best, found
}

func (r *InstallScriptsRule) Run(ctx *Context) ([]Finding, error) {
	home := ctx.Home
	shown := func(p string) string { return HomeRelative(p, home) }
	// userConfig reads a user config, through a link only when no link on the way leads into a folder macOS asks
	// about (without Full Disk Access a round must not make it ask). Not read: ok false, and said in the report;
	// that tool's setting is not known, so it is not judged.
	var left []string
	userConfig := func(p string) (text string, there, link, ok bool) {
		if !ctx.MayFollow(p) {
			left = append(left, shown(p)+" 链到的文件")
			return "", false, true, false
		}
		text, there, link = readConfig(p)
		return text, there, link, true
	}
	dirAt := func(p string) bool { return ctx.MayFollow(p) && isDir(p) }
	var scripted map[string]map[string]bool
	needs := func(tool string) []string {
		if scripted == nil {
			scripted = r.scriptedPackages(ctx)
		}
		return sortedKeys(scripted[tool])
	}
	var out []Finding
	// finding: one tool's, as a setting's state (nothing is wrong with a file: Path is empty). Evidence carries facts
	// and codes only, no sentences: who shows it writes the words in its reader's language, and a script reads the
	// codes. The title is in English, as this command line's output for people is to be.
	//   reason       why it is said: default-on, setting-on, allow-all-builds, old-store, built-from-source
	//   config       the user config the setting goes in ("" none), config_exists 1 or 0
	//   line         the line that turns it off; append: the same when appending it is enough (scan_apply scripts-off)
	//   manual       why appending is not enough or not done: link, link-on-path, change-value, add-at-top,
	//                add-in-global, remove-setting, upgrade
	//   packages     installed dependencies that need their script; built: packages built from source here
	//   allow        the command (or the snippet, in allow_in) that lets one package through afterwards
	//   cost         what turning it off breaks: own-scripts-off, no-wheel-fails, no-wheel-deps-fail
	//   delay        the setting that makes new versions wait a day (delay_since: from which version);
	//   fixed_in     the version whose default is off
	finding := func(tool, reason, config string, fix bool, manual string, more map[string]string) {
		t := ScriptsTools[tool]
		ev := map[string]string{"tool": tool, "name": t.Name, "risk": "third-party-code-at-install", "reason": reason}
		if config != "" {
			ev["config"], ev["config_exists"] = config, "0"
			if _, err := os.Lstat(config); err == nil {
				ev["config_exists"] = "1"
			}
			ev["line"] = t.Line
		}
		if fix {
			ev["append"] = t.Line
		} else if manual != "" {
			ev["manual"] = manual
		}
		for k, v := range more {
			if v != "" {
				ev[k] = v
			}
		}
		title := t.Name + " runs the install scripts that packages bring with them"
		switch reason {
		case "allow-all-builds":
			title = t.Name + " lets every dependency run scripts when it is installed"
		case "built-from-source":
			title = t.Name + " runs a package's own build script when it installs from source"
		}
		out = append(out, Finding{Rule: InstallScriptsRuleID, Category: CatPosture, Severity: Low, Verdict: Info,
			Title: title, Evidence: ev, Key: tool})
	}
	// blockedBy: why the file is not changed from here when a link is in the way; "" none.
	blockedBy := func(config string, link bool) string {
		switch {
		case link:
			return "link"
		case LinkOnPath(home, config):
			return "link-on-path"
		}
		return ""
	}
	list := func(xs []string) string { return strings.Join(xs, ", ") }

	// npm: dependency scripts run by default before npm 12; ignore-scripts=true in ~/.npmrc turns them off.
	if used := usedBy(ctx, home, ".npmrc", ".npm"); used != "" {
		cfg := ScriptsConfigPath("npm", home)
		text, _, link, read := userConfig(cfg)
		values, sections := iniValues(text, "ignore-scripts")
		// npm reads only the keys before any [section] of its config as settings.
		var top []string
		for i, v := range values {
			if sections[i] == "" {
				top = append(top, v)
			}
		}
		off := strings.EqualFold(last(top), "true")
		if v, ok := newest(r.globalVersions(ctx, "npm")); read && ok && v.before(12, 0) && !off {
			names := needs("npm")
			more := map[string]string{"used": used, "version": v.text, "where": shown(v.where), "packages": list(names),
				"allow": "npm rebuild " + strings.Join(firstN(names, 6, "<package>"), " ") + " --ignore-scripts=false",
				// the line also stops the project's own prepare and pre/post scripts (husky's git hooks): npm run <script>
				"cost": "own-scripts-off", "fixed_in": "npm 12"}
			if !v.before(11, 10) {
				more["delay"], more["delay_since"] = "min-release-age=1", "npm 11.10"
			}
			manual := blockedBy(cfg, link)
			fix := manual == "" && len(values) == 0 && len(iniSections(text)) == 0
			switch {
			case manual != "":
			case len(top) > 0:
				manual = "change-value"
			case !fix:
				manual = "add-at-top"
			}
			finding("npm", "default-on", cfg, fix, manual, more)
		}
	}

	// pnpm: off by default since 10. Older stores (v3) or an old global pnpm: on; dangerouslyAllowAllBuilds: on.
	if used := usedBy(ctx, home, "Library/pnpm", "Library/Preferences/pnpm", ".config/pnpm", ".local/share/pnpm", "Library/Caches/pnpm"); used != "" {
		reason, more := "", map[string]string{"used": used, "fixed_in": "pnpm 10",
			"allow": "allowBuilds", "allow_in": "pnpm-workspace.yaml"}
		vs := r.globalVersions(ctx, "pnpm")
		if v, ok := newest(vs); ok && v.before(10, 0) {
			reason, more["version"], more["where"] = "default-on", v.text, shown(v.where)
		} else if len(vs) == 0 {
			for _, store := range []string{"Library/pnpm/store", ".local/share/pnpm/store"} {
				if dirAt(filepath.Join(home, store, "v3")) && !dirAt(filepath.Join(home, store, "v10")) && !dirAt(filepath.Join(home, store, "v11")) {
					reason, more["store"] = "old-store", "~/"+store+"/v3"
					break
				}
			}
		}
		var all []string
		for _, c := range []string{"Library/Preferences/pnpm/config.yaml", ".config/pnpm/config.yaml"} {
			text, _, _, _ := userConfig(filepath.Join(home, c))
			if v, _ := topValues(text, "dangerouslyAllowAllBuilds", ":"); strings.EqualFold(last(v), "true") {
				all = append(all, "~/"+c)
			}
		}
		for _, c := range []string{"Library/Preferences/pnpm/rc", ".config/pnpm/rc"} {
			text, _, _, _ := userConfig(filepath.Join(home, c))
			if v, _ := iniValues(text, "dangerously-allow-all-builds"); strings.EqualFold(last(v), "true") {
				all = append(all, "~/"+c)
			}
		}
		more["packages"] = ""
		switch {
		case len(all) > 0:
			more["packages"], more["files"], more["setting"] = list(needs("pnpm")), list(all), "dangerouslyAllowAllBuilds"
			delete(more, "version")
			delete(more, "where")
			delete(more, "store")
			delete(more, "fixed_in")
			finding("pnpm", "allow-all-builds", "", false, "remove-setting", more)
		case reason != "":
			more["packages"] = list(needs("pnpm"))
			finding("pnpm", reason, "", false, "upgrade", more)
		}
	}

	// Yarn 2+: enableScripts is true by default before 4.14; ~/.yarnrc.yml applies to every project under the home.
	if used := usedBy(ctx, home, ".yarnrc.yml", ".yarn/berry"); used != "" {
		cfg := ScriptsConfigPath("yarn", home)
		text, _, link, read := userConfig(cfg)
		values, _ := topValues(text, "enableScripts", ":")
		setting := strings.ToLower(last(values))
		reason, more := "", map[string]string{"used": used, "fixed_in": "Yarn 4.14",
			"allow": `"dependenciesMeta": {"<package>": {"built": true}}`, "allow_in": "package.json",
			"delay": `npmMinimalAgeGate: "1d"`, "delay_since": "Yarn 4.10"}
		if setting == "true" {
			reason, more["setting"] = "setting-on", "enableScripts: true"
		} else if v, ok := newest(r.yarnVersions(ctx)); ok && v.before(4, 14) && setting != "false" {
			reason, more["version"], more["where"] = "default-on", v.text, shown(v.where)
		}
		if reason != "" && read {
			manual := blockedBy(cfg, link)
			fix := manual == "" && len(values) == 0
			if manual == "" && len(values) > 0 {
				manual = "change-value"
			}
			more["packages"] = list(needs("yarn"))
			finding("yarn", reason, cfg, fix, manual, more)
		}
	}

	// pip: a package with no ready-made wheel is built from source, running its setup.py. Said when pip has done so
	// here (its cache keeps the wheels it built) and no user pip.conf has only-binary = :all:.
	if built := builtPythonPackages(ctx, "pip"); len(built) > 0 {
		// As pip reads them: a later file over an earlier one, and for pip install its [install] over [global].
		var global, install *string
		anywhere, read := false, true
		for _, c := range pipConfigs(home) {
			text, _, _, ok := userConfig(c)
			read = read && ok
			values, sections := iniValues(text, "only-binary")
			for i := range values {
				anywhere = true
				switch sections[i] {
				case "global":
					global = &values[i]
				case "install":
					install = &values[i]
				}
			}
		}
		effective := global
		if install != nil {
			effective = install
		}
		if read && !pipAllBinary(effective) {
			cfg := ScriptsConfigPath("pip", home)
			text, there, link := readConfig(cfg) // one of pipConfigs: may be followed
			secs := iniSections(text)
			// One line does it when it lands in [global] or [install] (the file's last section is one of them) and no
			// only-binary anywhere in the user's pip configs could win over it.
			manual := blockedBy(cfg, link)
			fix := manual == "" && !anywhere && (!there || (len(secs) > 0 && (last(secs) == "global" || last(secs) == "install")))
			if !fix && manual == "" {
				manual = "add-in-global"
			}
			finding("pip", "built-from-source", cfg, fix, manual, map[string]string{"used": "~/Library/Caches/pip",
				"built": list(built), "runs": "setup.py", "cost": "no-wheel-fails",
				"allow": "pip install --only-binary :none: <package>",
				"delay": "uploaded-prior-to = P1D", "delay_since": "pip 26.1"})
		}
	}

	// uv: the same, from uv's cache of source builds; no-build = true in the user uv.toml turns it off.
	if built := builtPythonPackages(ctx, "uv"); len(built) > 0 {
		cfg := ScriptsConfigPath("uv", home)
		text, _, link, read := userConfig(cfg)
		values, tables := topValues(text, "no-build", "=")
		if read && !strings.EqualFold(last(values), "true") {
			manual := blockedBy(cfg, link)
			fix := manual == "" && len(values) == 0 && !tables
			if !fix && manual == "" {
				manual = "add-at-top"
			}
			// uv cannot let one package through: --no-config for that one install (the user's own project still builds)
			finding("uv", "built-from-source", cfg, fix, manual, map[string]string{"used": "~/.cache/uv",
				"built": list(built), "cost": "no-wheel-deps-fail", "allow": "--no-config",
				"delay": `exclude-newer = "1 day"`})
		}
	}
	if len(left) > 0 {
		return nil, Skip(NotLooked(strings.Join(left, "、")), out...)
	}
	return out, nil
}

func firstN(xs []string, n int, empty string) []string {
	if len(xs) == 0 {
		return []string{empty}
	}
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

// ScriptsOffContent is a user config with the line that turns the scripts off appended, judged again on what is in
// it now (old; there false: no file yet): ok false and why when one appended line would not do it (the key is
// already there, or the line would land in the wrong section or table).
func ScriptsOffContent(tool string, old []byte, there bool) ([]byte, bool, string) {
	t, known := ScriptsTools[tool]
	if !known || t.Line == "" {
		return nil, false, "这一项不能直接改"
	}
	if !there {
		return []byte(t.NewFile), true, ""
	}
	text := string(old)
	switch tool {
	case "npm":
		if v, _ := iniValues(text, "ignore-scripts"); len(v) > 0 {
			return nil, false, "里面已经有 ignore-scripts 了"
		}
		if len(iniSections(text)) > 0 {
			return nil, false, "里面有 [节]，加在末尾会落进节里"
		}
	case "yarn":
		if v, _ := topValues(text, "enableScripts", ":"); len(v) > 0 {
			return nil, false, "里面已经有 enableScripts 了"
		}
	case "uv":
		v, tables := topValues(text, "no-build", "=")
		if len(v) > 0 {
			return nil, false, "里面已经有 no-build 了"
		}
		if tables {
			return nil, false, "里面有 [表]，加在末尾会落进表里"
		}
	case "pip":
		if v, _ := iniValues(text, "only-binary"); len(v) > 0 {
			return nil, false, "里面已经有 only-binary 了"
		}
		secs := iniSections(text)
		if len(secs) == 0 || (last(secs) != "global" && last(secs) != "install") {
			return nil, false, "最后一节不是 [global] 或 [install]"
		}
	}
	out := append([]byte(nil), old...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, []byte(t.Line+"\n")...), true, ""
}

// pipAllBinary: an only-binary value that leaves no package to build from source (:all:, not cleared after by :none:).
func pipAllBinary(v *string) bool {
	if v == nil {
		return false
	}
	i := strings.LastIndex(*v, ":all:")
	return i >= 0 && !strings.Contains((*v)[i:], ":none:")
}
