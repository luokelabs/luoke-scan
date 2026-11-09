package core

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() { Register("supplychain.malicious", NewSupplyChainRule) }

// SupplyChainRule compares the packages projects and this Mac's global installs use with the local list of known
// malicious packages (OSV's MAL- entries, imported with `luoke-scan malicious-import`). It reads names and versions,
// never the packages' code: the lockfiles in the projects the scan knows (ProjectRoots); npm's global folders (the
// package.json of each global package and of every package in its node_modules, npm keeping no lockfile for a global
// install); bun's, pnpm's and yarn's global lockfiles; pipx's and uv's tool environments (the names of their installed
// packages' .dist-info folders); and cargo's record of what it installed. Nothing here is changed and nothing leaves
// this Mac. With no list imported it says nothing at all (until the list can be synced, most Macs have none).
type SupplyChainRule struct {
	// SystemNodeDirs: npm's global folders outside the home (Homebrew's node, the node installer's).
	SystemNodeDirs []string
	// MaxProjects per project folder; Depth: folders down from a project where lockfiles are looked for (monorepos keep
	// one per package); MaxDirs: folders looked into per project.
	MaxProjects, Depth, MaxDirs int
	// MaxLockfiles a round reads, MaxLockBytes each, MaxReadBytes all together; MaxGlobal packages looked at per folder.
	MaxLockfiles               int
	MaxLockBytes, MaxReadBytes int64
	MaxGlobal                  int
	// MaxGlobalDeps: package.json files read in global packages' node_modules, all together.
	MaxGlobalDeps int
	// StaleAfter: a list whose newest entry is older than this is said to be out of date.
	StaleAfter time.Duration
	// MaxPackages: packages on the list given a finding each (each urgent, one card each); the rest are one more.
	MaxPackages int
}

// NewSupplyChainRule: in a fake home, npm's global folders are the fake root's opt-homebrew and usr-local.
func NewSupplyChainRule(l *Layout, f *Fakes) Rule {
	r := &SupplyChainRule{SystemNodeDirs: []string{"/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules"},
		MaxProjects: 1000, Depth: 3, MaxDirs: 400, MaxLockfiles: 2000, MaxLockBytes: 64 << 20, MaxReadBytes: 1 << 30,
		MaxGlobal: 2000, MaxGlobalDeps: 50000, StaleAfter: 30 * 24 * time.Hour, MaxPackages: 10}
	if l != nil {
		r.SystemNodeDirs = []string{filepath.Join(l.Root, "opt-homebrew/lib/node_modules"), filepath.Join(l.Root, "usr-local/lib/node_modules")}
	}
	return r
}

func (r *SupplyChainRule) ID() string { return "supplychain.malicious" }
func (r *SupplyChainRule) Emits() []string {
	return []string{"supplychain.malicious", "supplychain.stale-list", "supplychain.partial"}
}

// scKind is where a package came from, which says how it is named on the card and how it goes away.
type scKind int

const (
	scProject    scKind = iota // a project's lockfile
	scGlobalNpm                // a package in npm's global folder, or one in its node_modules
	scGlobalLock               // bun's, pnpm's or yarn's global lockfile
	scPipx                     // a pipx tool's environment
	scUvTool                   // a uv tool's environment
	scCargo                    // cargo install
)

// scSource is one place packages are read from.
type scSource struct {
	kind scKind
	// label: the project's or the tool's name, a global npm package's name ("" for a global lockfile, cargo).
	label string
	// path: what the finding points at (the lockfile, the package's or the tool's folder, cargo's record).
	path string
	read func() ([]DepPkg, bool)
}

// scSkipDirs are folders not looked into for lockfiles: dependencies and build output (what is in them is someone
// else's lockfile, or a copy), and test data and examples (lockfiles there are samples, never installed).
var scSkipDirs = map[string]bool{"node_modules": true, "vendor": true, "target": true, "venv": true, "__pycache__": true,
	"dist": true, "build": true, "Pods": true, "DerivedData": true, "site-packages": true, "bower_components": true,
	"testdata": true, "fixtures": true, "__fixtures__": true, "__tests__": true, "examples": true, "example": true,
	"samples": true}

func (r *SupplyChainRule) Run(ctx *Context) ([]Finding, error) {
	// No list (none imported yet): nothing to compare with, and nothing said.
	if ctx.Store == nil {
		return []Finding{}, nil
	}
	list, ok := LoadMalList(ctx.Store.Dir)
	if !ok {
		return []Finding{}, nil
	}
	var sources []scSource
	var left []string
	var large []string
	budget := r.MaxReadBytes
	lockfiles := 0
	readLock := func(path string) func() ([]DepPkg, bool) {
		return func() ([]DepPkg, bool) {
			st, ok := aiLstat(path)
			if !ok || !aiStReg(st) || aiDataless(st) {
				return nil, false
			}
			if st.Size > r.MaxLockBytes || st.Size > budget {
				large = append(large, ctx.Shown(path))
				return nil, false
			}
			data, ok := readCapped(path, r.MaxLockBytes)
			if !ok {
				return nil, false
			}
			budget -= int64(len(data))
			deps, err := parseLockfile(filepath.Base(path), data)
			if err == errLockTooLarge {
				large = append(large, ctx.Shown(path))
			}
			return deps, err == nil
		}
	}
	addLock := func(kind scKind, label, path string) {
		if lockfiles >= r.MaxLockfiles {
			large = append(large, ctx.Shown(path))
			return
		}
		lockfiles++
		sources = append(sources, scSource{kind, label, path, readLock(path)})
	}

	// Projects. Looking for lockfiles walks many folders: a round that is called off stops here too.
	for _, root := range ctx.ProjectRoots {
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted)
		}
		if !ctx.MayLook(root) {
			left = append(left, ctx.Shown(root)+" 里项目的锁文件")
			continue
		}
		for _, project := range aiProjectFolders(root, r.MaxProjects) {
			if ctx.IsCancelled() {
				return nil, Skip(Interrupted)
			}
			for _, lf := range r.projectLockfiles(ctx, project) {
				addLock(scProject, filepath.Base(project), lf)
			}
		}
	}

	// A global npm package and everything in its node_modules (npm writes no lockfile for a global install): each
	// package.json's name and version, not through links, not into hidden folders (.bin), up to MaxGlobalDeps in all.
	depsLeft := r.MaxGlobalDeps
	readGlobal := func(pkg string) func() ([]DepPkg, bool) {
		return func() ([]DepPkg, bool) {
			top, n, ok := readPackageJSON(pkg)
			if !ok {
				return nil, false
			}
			budget -= int64(n)
			top.Where = pkg
			out := []DepPkg{top}
			cut := false
			var walk func(nm string, depth int)
			visit := func(dir string, depth int) {
				if cut {
					return
				}
				if depsLeft <= 0 || budget <= 0 || ctx.IsCancelled() {
					cut = true
					return
				}
				depsLeft--
				if d, n, ok := readPackageJSON(dir); ok {
					budget -= int64(n)
					d.Where = dir
					out = append(out, d)
				}
				if depth < 32 {
					walk(filepath.Join(dir, "node_modules"), depth+1)
				}
			}
			walk = func(nm string, depth int) {
				if !aiIsDir(nm) {
					return
				}
				for _, c := range Children(nm) {
					name := filepath.Base(c)
					if strings.HasPrefix(name, ".") || !aiIsDir(c) {
						continue
					}
					if strings.HasPrefix(name, "@") {
						for _, sc := range Children(c) {
							if !strings.HasPrefix(filepath.Base(sc), ".") && aiIsDir(sc) {
								visit(sc, depth)
							}
						}
						continue
					}
					visit(c, depth)
				}
			}
			walk(filepath.Join(pkg, "node_modules"), 0)
			if cut {
				large = append(large, ctx.Shown(pkg))
			}
			return out, true
		}
	}

	// npm's global folders: the home's (a prefix of one's own, nvm, fnm, volta, asdf, mise) and the system's.
	home := ctx.Home
	nodeDirs := append([]string{}, r.SystemNodeDirs...)
	nodeDirs = append(nodeDirs, filepath.Join(home, ".npm-global/lib/node_modules"), filepath.Join(home, ".npm-packages/lib/node_modules"))
	for _, pattern := range []string{".nvm/versions/node/*/lib/node_modules", ".local/share/fnm/node-versions/*/installation/lib/node_modules",
		"Library/Application Support/fnm/node-versions/*/installation/lib/node_modules", ".volta/tools/image/packages/*/lib/node_modules",
		".asdf/installs/nodejs/*/lib/node_modules", ".local/share/mise/installs/node/*/lib/node_modules"} {
		nodeDirs = append(nodeDirs, scGlob(home, pattern)...)
	}
	for _, d := range nodeDirs {
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted)
		}
		if !ctx.MayLook(d) || !aiIsDir(d) {
			continue
		}
		for _, pkg := range r.globalPackages(d) {
			// Its name as npm uninstall -g takes it: the path under the global folder (@scope/name).
			label := filepath.Base(pkg)
			if scope := filepath.Base(filepath.Dir(pkg)); strings.HasPrefix(scope, "@") {
				label = scope + "/" + label
			}
			sources = append(sources, scSource{scGlobalNpm, label, pkg, readGlobal(pkg)})
		}
	}
	// bun's, pnpm's and yarn's global installs keep a lockfile of their own.
	globalLocks := []string{filepath.Join(home, ".bun/install/global/bun.lock"), filepath.Join(home, ".config/yarn/global/yarn.lock")}
	globalLocks = append(globalLocks, scGlob(home, "Library/pnpm/global/*/pnpm-lock.yaml")...)
	for _, lf := range globalLocks {
		if ctx.MayLook(lf) && aiIsReg(lf) {
			addLock(scGlobalLock, "", lf)
		}
	}
	// pipx's and uv's tools, each in an environment of its own.
	for _, venvs := range []struct {
		kind scKind
		dirs []string
	}{
		{scPipx, []string{filepath.Join(home, ".local/pipx/venvs"), filepath.Join(home, ".local/share/pipx/venvs"),
			filepath.Join(home, "Library/Application Support/pipx/venvs")}},
		{scUvTool, []string{filepath.Join(home, ".local/share/uv/tools")}},
	} {
		for _, d := range venvs.dirs {
			if !ctx.MayLook(d) {
				continue
			}
			for _, tool := range Children(d) {
				if !aiIsDir(tool) || strings.HasPrefix(filepath.Base(tool), ".") {
					continue
				}
				sources = append(sources, scSource{venvs.kind, filepath.Base(tool), tool, func() ([]DepPkg, bool) { return venvPackages(tool) }})
			}
		}
	}
	// cargo install's record.
	for _, name := range []string{".cargo/.crates2.json", ".cargo/.crates.toml"} {
		p := filepath.Join(home, name)
		if ctx.MayLook(p) && aiIsReg(p) {
			sources = append(sources, scSource{scCargo, "", p, func() ([]DepPkg, bool) { return readCargoInstalls(p) }})
			break
		}
	}

	listNote := "恶意包名单 " + list.Date + "（OSV 的 MAL- 条目）"
	var out []Finding
	if d, err := time.Parse("2006-01-02", list.Date); err == nil {
		if age := ctx.Now.Sub(d); age > r.StaleAfter {
			out = append(out, Finding{Rule: "supplychain.stale-list", Category: CatSupplyChain, Severity: Medium, Verdict: Info,
				Path:     filepath.Join(ctx.Store.Dir, MaliciousListName),
				Title:    "恶意包名单 " + strconv.Itoa(int(age.Hours()/24)) + " 天没更新，后来出的恶意包比对不出来",
				Evidence: map[string]string{"list": listNote, "how": "拿一份新的 OSV 名单重新导入（luoke-scan malicious-import）"}})
		}
	}
	var hits []scHit
	for _, s := range sources {
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted)
		}
		deps, ok := s.read()
		if !ok {
			continue // not a lockfile it reads (or changed while read): says nothing either way
		}
		for _, d := range deps {
			// A name or version that is not plain is never compared or shown (it would go into a card's title).
			d, ok := CleanDep(d)
			if !ok {
				continue
			}
			if ids := list.Match(d.Eco, d.Name, d.Version); len(ids) > 0 {
				hits = append(hits, scHit{s, d, ids})
			}
		}
	}
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}
	// One finding per package, however many places use it; past MaxPackages the rest are one more.
	groups := r.groupHits(ctx, hits)
	for i, g := range groups {
		if i >= r.MaxPackages && len(groups) > r.MaxPackages+1 {
			out = append(out, r.more(ctx, groups[i:], listNote))
			break
		}
		out = append(out, r.finding(ctx, g, listNote))
	}
	if len(large) > 0 {
		sort.Strings(large)
		out = append(out, Finding{Rule: "supplychain.partial", Category: CatSupplyChain, Severity: Low, Verdict: Info, Path: "",
			Title:    strconv.Itoa(len(large)) + " 处锁文件或全局装的包太大、太多，没和恶意包名单比对完",
			Evidence: map[string]string{"files": strings.Join(aiFirstN(large, 10), "；")}})
	}
	if len(left) > 0 {
		return nil, Skip(NotLooked(strings.Join(left, "、")+" "), out...)
	}
	return out, nil
}

// projectLockfiles are the lockfiles in a project, looked for up to Depth folders down, not in hidden folders, not
// in dependencies or build output, not through links.
func (r *SupplyChainRule) projectLockfiles(ctx *Context, project string) []string {
	type queued struct {
		dir   string
		level int
	}
	var out []string
	queue := []queued{{project, 0}}
	seen := 0
	for len(queue) > 0 && seen < r.MaxDirs && !ctx.IsCancelled() {
		q := queue[0]
		queue = queue[1:]
		seen++
		for _, c := range Children(q.dir) {
			name := filepath.Base(c)
			st, ok := aiLstat(c)
			if !ok {
				continue
			}
			if aiStReg(st) && IsLockfile(name) {
				out = append(out, c)
				continue
			}
			if aiStDir(st) && q.level < r.Depth && !strings.HasPrefix(name, ".") && !scSkipDirs[name] && !aiIsPackage(c) {
				queue = append(queue, queued{c, q.level + 1})
			}
		}
	}
	sort.Strings(out)
	return out
}

// globalPackages are the package folders in one of npm's global folders (@scope/name inside a scope), not links
// (npm link puts a project of one's own there).
func (r *SupplyChainRule) globalPackages(dir string) []string {
	var out []string
	for _, c := range Children(dir) {
		name := filepath.Base(c)
		if strings.HasPrefix(name, ".") || !aiIsDir(c) {
			continue
		}
		if strings.HasPrefix(name, "@") {
			for _, s := range Children(c) {
				if !strings.HasPrefix(filepath.Base(s), ".") && aiIsDir(s) {
					out = append(out, s)
				}
			}
			continue
		}
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) > r.MaxGlobal {
		out = out[:r.MaxGlobal]
	}
	return out
}

func scGlob(home, pattern string) []string {
	m, _ := filepath.Glob(filepath.Join(home, pattern))
	sort.Strings(m)
	return m
}

// readPackageJSON: a package folder's own name and version, and how many bytes were read.
func readPackageJSON(pkg string) (DepPkg, int, bool) {
	data, ok := readCapped(filepath.Join(pkg, "package.json"), 1<<20)
	if !ok {
		return DepPkg{}, 0, false
	}
	var p struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &p) != nil || p.Name == "" || !looksVersion(p.Version) {
		return DepPkg{}, len(data), false
	}
	return DepPkg{Eco: "npm", Name: p.Name, Version: p.Version}, len(data), true
}

// venvPackages: what is installed in a Python environment, from its .dist-info folders' names ("name-1.2.3.dist-info",
// the name with - written _); nothing in them is opened.
func venvPackages(venv string) ([]DepPkg, bool) {
	var out []DepPkg
	found := false
	for _, lib := range scGlob(venv, "lib/python*/site-packages") {
		found = true
		for _, c := range Children(lib) {
			base := filepath.Base(c)
			stem, ok := strings.CutSuffix(base, ".dist-info")
			if !ok || !aiIsDir(c) {
				continue
			}
			name, v, ok := strings.Cut(stem, "-")
			if ok && name != "" && looksVersion(v) {
				out = append(out, DepPkg{Eco: "PyPI", Name: name, Version: v})
			}
		}
	}
	return out, found
}

// readCargoInstalls: cargo's record of `cargo install` (.crates2.json, or the older .crates.toml): keys
// "name version (source)", only from crates.io.
func readCargoInstalls(path string) ([]DepPkg, bool) {
	data, ok := readCapped(path, 8<<20)
	if !ok {
		return nil, false
	}
	var keys []string
	if strings.HasSuffix(path, ".json") {
		var f struct {
			Installs map[string]json.RawMessage `json:"installs"`
		}
		if json.Unmarshal(data, &f) != nil {
			return nil, false
		}
		for k := range f.Installs {
			keys = append(keys, k)
		}
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, `"`) {
				if end := strings.Index(line[1:], `"`); end > 0 {
					keys = append(keys, line[1:1+end])
				}
			}
		}
	}
	var out []DepPkg
	for _, k := range keys {
		parts := strings.SplitN(k, " ", 3)
		if len(parts) != 3 {
			continue
		}
		src := strings.Trim(parts[2], "()")
		if !strings.HasPrefix(src, "registry+https://github.com/rust-lang/crates.io-index") && !strings.HasPrefix(src, "sparse+https://index.crates.io/") {
			continue
		}
		if looksVersion(parts[1]) {
			out = append(out, DepPkg{Eco: "crates.io", Name: parts[0], Version: parts[1]})
		}
	}
	return out, true
}

const scLeaked = "装过就当这台 Mac 上的令牌和钥匙已经泄露：.npmrc 里的令牌、~/.ssh 的钥匙、~/.aws 的密钥、浏览器里存的登录都要换"

// scNotOurs closes what to do about a project: the project is the user's own.
const scNotOurs = "。螺壳扫描不替你删项目里的东西"

// scHit is one place a package on the list is used.
type scHit struct {
	src scSource
	dep DepPkg
	ids []string
}

// scPlace is what one place says about a package on the list.
type scPlace struct {
	// title: the finding's title when this is the only place; label: the place in a list of places.
	title, label string
	// remedy: how to get rid of it here (without the advice about leaked keys); project: a project's (not ours to touch).
	remedy  string
	project bool
	// evKey ("lockfile" or "where") and shown: the evidence pointing at it; path: what the finding points at.
	evKey, shown, path string
}

func (r *SupplyChainRule) place(ctx *Context, s scSource, d DepPkg) scPlace {
	pkg := d.Name + "@" + d.Version
	p := scPlace{path: s.path, evKey: "where"}
	if d.Where != "" {
		p.path = d.Where
	}
	switch s.kind {
	case scProject:
		p.title = "项目 " + s.label + " 用了已知恶意的 " + pkg
		p.label = "项目 " + s.label
		remove := map[string]string{"npm": "删掉这个项目的 node_modules", "PyPI": "删掉这个项目的虚拟环境（.venv 这类）",
			"crates.io": "删掉这个项目的 target"}[d.Eco]
		p.remedy = remove + "，把 " + d.Name + " 改到名单外的版本（或换掉它）再重新装"
		p.project = true
		p.evKey = "lockfile"
	case scGlobalNpm:
		if d.Where != "" && d.Where != s.path {
			p.title = "全局装的 " + s.label + " 用了已知恶意的 " + pkg
			p.remedy = "用 npm uninstall -g " + s.label + " 卸掉它，等它换掉这个依赖再装"
		} else {
			p.title = "全局装的 npm 包 " + pkg + " 是已知恶意的"
			p.remedy = "用 npm uninstall -g " + d.Name + " 卸掉"
		}
		p.label = "全局装的 " + s.label
	case scGlobalLock:
		p.title = "全局装的 npm 包里有已知恶意的 " + pkg
		p.label = "全局装的 npm 包"
		p.remedy = "把用到它的全局包卸掉（bun remove -g、pnpm remove -g、yarn global remove）"
		p.evKey = "lockfile"
	case scPipx:
		p.title = "pipx 装的 " + s.label + " 里有已知恶意的 " + pkg
		p.label = "pipx 装的 " + s.label
		p.remedy = "用 pipx uninstall " + s.label + " 卸掉"
	case scUvTool:
		p.title = "uv tool 装的 " + s.label + " 里有已知恶意的 " + pkg
		p.label = "uv tool 装的 " + s.label
		p.remedy = "用 uv tool uninstall " + s.label + " 卸掉"
	case scCargo:
		p.title = "cargo install 装的 " + pkg + " 是已知恶意的"
		p.label = "cargo install 装的"
		p.remedy = "用 cargo uninstall " + d.Name + " 卸掉"
	}
	if s.kind == scGlobalNpm {
		p.shown = ctx.Shown(p.path)
	} else {
		p.shown = ctx.Shown(s.path)
	}
	return p
}

// scGroup is one package on the list (ecosystem, name as the list compares it, version, registry) and every place
// it is used: one finding however many projects use it.
type scGroup struct {
	key  string
	hits []scHit
}

// scGroupKey: the package as one finding covers it. The same version under two spellings of a PyPI name is one.
func scGroupKey(d DepPkg) string {
	return d.Eco + "\x00" + MalName(d.Eco, d.Name) + "\x00" + malVersion(d.Eco, d.Version) + "\x00" + d.Source
}

// groupHits gathers the hits by package, the packages used in the most places first (then by name), each one's places
// in the order of where they are shown.
func (r *SupplyChainRule) groupHits(ctx *Context, hits []scHit) []scGroup {
	at := map[string]int{}
	var groups []scGroup
	for _, h := range hits {
		k := scGroupKey(h.dep)
		i, ok := at[k]
		if !ok {
			i = len(groups)
			at[k] = i
			groups = append(groups, scGroup{key: k})
		}
		groups[i].hits = append(groups[i].hits, h)
	}
	for _, g := range groups {
		sort.SliceStable(g.hits, func(i, j int) bool {
			a, b := r.place(ctx, g.hits[i].src, g.hits[i].dep), r.place(ctx, g.hits[j].src, g.hits[j].dep)
			if a.shown != b.shown {
				return a.shown < b.shown
			}
			return a.label < b.label
		})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if len(groups[i].hits) != len(groups[j].hits) {
			return len(groups[i].hits) > len(groups[j].hits)
		}
		return groups[i].key < groups[j].key
	})
	return groups
}

// scMaxPlaces: places a finding lists by name; scMaxRemedies: different ways of getting rid of it one finding says.
const (
	scMaxPlaces   = 10
	scMaxRemedies = 5
)

// finding: one package on the list, wherever it is used. Used in one place it reads as that place; in several, it says
// how many and lists them.
func (r *SupplyChainRule) finding(ctx *Context, g scGroup, listNote string) Finding {
	first := g.hits[0]
	d := first.dep
	pkg := d.Name + "@" + d.Version
	ids := map[string]bool{}
	var idList []string
	for _, h := range g.hits {
		for _, id := range h.ids {
			if !ids[id] {
				ids[id] = true
				idList = append(idList, id)
			}
		}
	}
	sort.Strings(idList)
	ev := map[string]string{"ids": strings.Join(idList, "、"), "list": listNote, "ecosystem": d.Eco, "package": pkg,
		"why": "这个版本在公开的恶意包名单上：装的时候它的代码可能已经在这台 Mac 上运行过"}
	var title, how, path, key string
	if len(g.hits) == 1 {
		p := r.place(ctx, first.src, d)
		title, path = p.title, p.path
		how = p.remedy + "；" + scLeaked
		if p.project {
			how += scNotOurs
		}
		ev[p.evKey] = p.shown
		key = Place(path) + "\x00" + d.Eco + "\x00" + pkg
		if d.Source != "" {
			key += "\x00" + d.Source
		}
	} else {
		var places, remedies, keyPlaces []string
		seen := map[string]bool{}
		project := false
		for i, h := range g.hits {
			p := r.place(ctx, h.src, h.dep)
			if i == 0 {
				path = p.path
			}
			keyPlaces = append(keyPlaces, Place(p.path))
			if len(places) < scMaxPlaces {
				places = append(places, p.label+"（"+p.shown+"）")
			}
			remedy := p.remedy
			if p.project {
				project = true
				remedy = "用到它的每个项目都" + strings.Replace(remedy, "这个项目的", "", 1)
			}
			if !seen[remedy] && len(remedies) < scMaxRemedies {
				seen[remedy] = true
				remedies = append(remedies, remedy)
			}
		}
		n := strconv.Itoa(len(g.hits))
		title = n + " 处用了已知恶意的 " + pkg
		list := strings.Join(places, "；")
		if len(g.hits) > len(places) {
			list += "；等 " + n + " 处"
		}
		ev["places"] = list
		ev["count"] = n
		how = strings.Join(remedies, "；") + "；" + scLeaked
		if project {
			how += scNotOurs
		}
		sort.Strings(keyPlaces)
		key = d.Eco + "\x00" + pkg + "\x00" + d.Source + "\x00" + strings.Join(keyPlaces, "\x00")
	}
	// From a registry that is not the public one: the list names the public package; one of the same name from a
	// company's own registry may be theirs. Said, so the user can tell.
	if d.Source != "" {
		title += "（来自 " + d.Source + "）"
		ev["source"] = d.Source
		how = "这个包来自 " + d.Source + "，不是公开的源：如果它是你们自己发布的同名包，名单说的是公开源上的那个，和它无关；" +
			"如果不是，就是装到了冒名的包，照下面做。" + how
	}
	ev["how"] = how
	return Finding{Rule: "supplychain.malicious", Category: CatSupplyChain, Severity: High, Verdict: Confirm, Path: path,
		Title: title, Evidence: ev, Key: key}
}

// scMaxListedPackages: packages named one by one in the finding for those past MaxPackages.
const scMaxListedPackages = 20

// more: the packages past MaxPackages, as one finding (still urgent: each is on the list), named with how many places
// use them.
func (r *SupplyChainRule) more(ctx *Context, groups []scGroup, listNote string) Finding {
	var names, keys []string
	places := 0
	for _, g := range groups {
		d := g.hits[0].dep
		places += len(g.hits)
		keys = append(keys, g.key)
		if len(names) < scMaxListedPackages {
			name := d.Name + "@" + d.Version
			if d.Source != "" {
				name += "（来自 " + d.Source + "）"
			}
			names = append(names, name+"："+strconv.Itoa(len(g.hits))+" 处")
		}
	}
	list := strings.Join(names, "；")
	if len(groups) > len(names) {
		list += "；等 " + strconv.Itoa(len(groups)) + " 个"
	}
	sort.Strings(keys)
	return Finding{Rule: "supplychain.malicious", Category: CatSupplyChain, Severity: High, Verdict: Confirm, Path: "",
		Title: "另外还有 " + strconv.Itoa(len(groups)) + " 个已知恶意的包，在 " + strconv.Itoa(places) + " 处用到",
		Evidence: map[string]string{"list": listNote, "packages": list, "count": strconv.Itoa(len(groups)),
			"why": "这些版本在公开的恶意包名单上：装的时候它们的代码可能已经在这台 Mac 上运行过",
			"how": "项目里用到的：删掉依赖目录（node_modules、.venv、target），改到名单外的版本再重新装；全局装的：卸掉；" + scLeaked +
				"。重新查一遍会逐个列出"},
		Key: "more\x00" + strings.Join(keys, "\x01")}
}
