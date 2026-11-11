package core

import (
	"bytes"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// InstallScriptRule: the install scripts of the dependencies of the projects this scan knows, and of the npm packages
// installed globally, checked by rule (installscript.go) for what an install script has no business doing: reading
// keys and sending them, downloading code and running it, making something start by itself, decoding hidden code
// to run it, finding secrets with a scanner, pushing a workflow into a repository. Only package.json's preinstall,
// install and postinstall and the files they run are read, never the rest of node_modules; and a Python package
// checked out from source into a project's virtual environment (its setup.py), never site-packages. A finding is
// "to confirm", not urgent: a rule can be wrong about a script. Nothing is planned, cleaned or deleted.
//
// A file is read once and not again while it stays the same (its inode, size and time, and the rules' version), as
// the virus scan keeps what it scanned.
type InstallScriptRule struct {
	// GlobalDirs: node_modules folders of globally installed npm packages (and folders holding versions of node,
	// each with its lib/node_modules: nvm's).
	GlobalDirs     []string
	GlobalVersions []string
	Limits         InstallScriptLimits
	// Read is told every file this round read (tests).
	Read func(path string)
}

// InstallScriptLimits bound a round.
type InstallScriptLimits struct {
	// MaxProjects per project folder; MaxSearchDirs: folders looked through in a project for node_modules;
	// MaxDepth: how deep in a project.
	MaxProjects, MaxSearchDirs, MaxDepth int
	// MaxPackages: packages looked at in a round (a package.json each, stat'ed; read when new or changed).
	MaxPackages int
	// MaxPackageBytes: a package.json larger than this is not read; MaxFileBytes: a script likewise.
	MaxPackageBytes, MaxFileBytes int64
	// MaxRoundBytes: what a round reads in all, of files not read before.
	MaxRoundBytes int64
}

// DefaultInstallScriptLimits: 500 projects, 400 folders and 4 levels in each, 40000 packages, 1 MB a package.json,
// 1 MB a script, 16 MB a round (the checks take about 10 seconds a megabyte of minified code and up to about 50 at worst;
// an install script is usually a few kilobytes, and what was read is not read again).
func DefaultInstallScriptLimits() InstallScriptLimits {
	return InstallScriptLimits{MaxProjects: 500, MaxSearchDirs: 400, MaxDepth: 4, MaxPackages: 40000, MaxPackageBytes: 1 << 20,
		MaxFileBytes: 1 << 20, MaxRoundBytes: 16 << 20}
}

func init() { Register("deps.install-script", NewInstallScriptRule) }

// NewInstallScriptRule: on this Mac, Homebrew's and /usr/local's global packages and those in the home; in a fake home,
// its own opt-homebrew/ and usr-local/ and its home's.
func NewInstallScriptRule(l *Layout, f *Fakes) Rule {
	r := &InstallScriptRule{Limits: DefaultInstallScriptLimits()}
	if l != nil {
		r.GlobalDirs = []string{filepath.Join(l.Root, "opt-homebrew/lib/node_modules"), filepath.Join(l.Root, "usr-local/lib/node_modules")}
	} else {
		r.GlobalDirs = []string{"/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules"}
	}
	return r
}

func (r *InstallScriptRule) ID() string      { return "deps.install-script" }
func (r *InstallScriptRule) Emits() []string { return []string{"deps.install-script"} }

// installRulesVersion: bumped when the checks change, so what was read is read again.
const installRulesVersion = "2"

// InstallScan is what was last found in a file: a package.json's hooks and the files they run, or what a script does.
type InstallScan struct {
	Inode    uint64  `json:"inode"`
	Size     int64   `json:"size"`
	Modified float64 `json:"modified"`
	// Changed: the inode's change time (ctime), which setting the modification time back does not hide.
	Changed float64 `json:"changed"`
	Rules   string  `json:"rules"`
	// Native: a script left unread as a program (run by itself, a Mach-O or ELF): read when a hook runs it through
	// an interpreter.
	Native bool `json:"native,omitempty"`
	// Package: for a package.json; nil for a script.
	Package *InstallScanPackage `json:"package,omitempty"`
	Signals []InstallSignal     `json:"signals"`
}

// InstallScanPackage is what a package.json says, as kept: never the commands themselves.
type InstallScanPackage struct {
	// Invalid: not JSON npm would read (npm would not install it); nothing else is kept.
	Invalid bool `json:"invalid,omitempty"`
	// TooDeep: nested deeper than the JSON reader here goes (JSON.parse, and so npm, reads it): its hooks are not
	// known, so it is counted as not checked every round.
	TooDeep bool   `json:"tooDeep,omitempty"`
	Who     string `json:"who"`
	// NameDiffers: the name it claims is not the folder npm put it in.
	NameDiffers bool     `json:"nameDiffers,omitempty"`
	Hooks       []string `json:"hooks"`
	// HookLines: the line of package.json each hook is on.
	HookLines map[string]int  `json:"hookLines"`
	Targets   []InstallTarget `json:"targets"`
}

func installTable(s *Store) Table[InstallScan] {
	return NewTable[InstallScan](s, "install_scripts_scanned", 2)
}

// installPlace is a folder of packages and whose they are.
type installPlace struct {
	modules string
	// project: the project's folder; "" for the global packages.
	project string
}

// installGlobalHomes are the home's own folders of global packages.
func installGlobalHomes(home string) (dirs, versions []string) {
	return []string{filepath.Join(home, ".npm-global/lib/node_modules"), filepath.Join(home, ".npm-packages/lib/node_modules")},
		[]string{filepath.Join(home, ".nvm/versions/node"), filepath.Join(home, ".volta/tools/image/node")}
}

// installModulesIn are the node_modules folders of a project: breadth first up to MaxDepth folders down (a monorepo
// has one per package), not into hidden folders, links or node_modules themselves; at most MaxSearchDirs looked into.
func (r *InstallScriptRule) installModulesIn(project string) (out []string, cut bool) {
	type queued struct {
		dir   string
		level int
	}
	queue := []queued{{project, 0}}
	looked := 0
	for len(queue) > 0 {
		if looked >= r.Limits.MaxSearchDirs {
			return out, true
		}
		q := queue[0]
		queue = queue[1:]
		looked++
		children := Children(q.dir)
		sort.Strings(children)
		for _, c := range children {
			name := filepath.Base(c)
			if !aiIsDir(c) {
				continue
			}
			if name == "node_modules" {
				out = append(out, c)
				continue
			}
			if strings.HasPrefix(name, ".") || q.level+1 >= r.Limits.MaxDepth || aiIsPackage(c) {
				continue
			}
			queue = append(queue, queued{c, q.level + 1})
		}
	}
	return out, false
}

// installPackagesIn are the packages in a node_modules folder: its folders and those in @scope folders, pnpm's
// store (.pnpm/<pkg>@<v>/node_modules/<pkg>), and one level of nested node_modules (npm's for a conflicting version).
// Links are not followed: pnpm's links point into its store, listed here anyway.
func installPackagesIn(modules string, nested bool) []string {
	var out []string
	list := func(dir string) []string {
		c := Children(dir)
		sort.Strings(c)
		return c
	}
	for _, c := range list(modules) {
		name := filepath.Base(c)
		if !aiIsDir(c) {
			continue
		}
		switch {
		case name == ".pnpm":
			for _, v := range list(c) {
				if aiIsDir(v) {
					out = append(out, installPackagesIn(filepath.Join(v, "node_modules"), false)...)
				}
			}
		case strings.HasPrefix(name, "."):
		case strings.HasPrefix(name, "@"):
			for _, p := range list(c) {
				if aiIsDir(p) {
					out = append(out, p)
					if nested {
						out = append(out, installPackagesIn(filepath.Join(p, "node_modules"), false)...)
					}
				}
			}
		default:
			out = append(out, c)
			if nested {
				out = append(out, installPackagesIn(filepath.Join(c, "node_modules"), false)...)
			}
		}
	}
	return out
}

// installSdists are the Python packages checked out from source into a project's virtual environments (pip install
// -e git+…: <venv>/src/<name>), each with a setup.py. Not site-packages: what is installed there ran already, as built
// wheels, and holds no setup.py of its own.
func installSdists(project string) []string {
	var out []string
	for _, venv := range []string{".venv", "venv", "env"} {
		src := filepath.Join(project, venv, "src")
		if !aiIsReg(filepath.Join(project, venv, "pyvenv.cfg")) || !aiIsDir(src) {
			continue
		}
		c := Children(src)
		sort.Strings(c)
		for _, p := range c {
			if aiIsDir(p) && aiIsReg(filepath.Join(p, "setup.py")) {
				out = append(out, p)
			}
		}
	}
	return out
}

// installFinding is one dependency's finding, before the same package elsewhere is folded into it.
type installFinding struct {
	who, kind string // kind: "npm" or "python"
	pkg       string
	project   string
	signals   []installPlaced
	// nameDiffers: its package.json claims another name than the folder it is in.
	nameDiffers bool
}

// installPlaced is a signal with the hook and file it is in.
type installPlaced struct {
	InstallSignal
	hook, file string
}

func (r *InstallScriptRule) Run(ctx *Context) ([]Finding, error) {
	var table Table[InstallScan]
	known := map[string]InstallScan{}
	if ctx.Store != nil {
		table = installTable(ctx.Store)
		known = table.Load()
	}
	rules := installRulesVersion + "+" + RulePackVersion
	seen := map[string]InstallScan{}
	budget := r.Limits.MaxRoundBytes
	var notRead, cutShort, tooDeep int
	cancelled := func() bool { return ctx.IsCancelled() }

	// stat says what a file is now; ok false when it is not a regular file (or not there).
	stat := func(path string) (InstallScan, bool) {
		st, ok := aiLstat(path)
		if !ok || !aiStReg(st) || aiDataless(st) {
			return InstallScan{}, false
		}
		return InstallScan{Inode: st.Ino, Size: st.Size, Modified: float64(st.Mtimespec.Sec) + float64(st.Mtimespec.Nsec)/1e9,
			Changed: float64(st.Ctimespec.Sec) + float64(st.Ctimespec.Nsec)/1e9, Rules: rules, Signals: []InstallSignal{}}, true
	}
	// cached is the last scan of a file still the same.
	cached := func(path string, now InstallScan) (InstallScan, bool) {
		k, ok := known[path]
		if ok && installSame(k, now) {
			return k, true
		}
		return InstallScan{}, false
	}
	read := func(path string, size, limit int64) ([]byte, bool) {
		if size > limit || size > budget {
			notRead++
			return nil, false
		}
		data, ok := aiReadHead(path, int(size))
		if !ok {
			notRead++
			return nil, false
		}
		budget -= int64(len(data))
		if r.Read != nil {
			r.Read(path)
		}
		return data, true
	}
	// scanScript: what a script does (cached, or read now); ok false when it could not be read (or the round was
	// cancelled while it was being checked). direct: the hooks only run it by itself, never through an interpreter.
	scanScript := func(path string, direct bool) ([]InstallSignal, bool) {
		now, ok := stat(path)
		if !ok {
			return nil, false
		}
		if k, ok := cached(path, now); ok && (direct || !k.Native) {
			seen[path] = k
			return k.Signals, true
		}
		data, ok := read(path, now.Size, r.Limits.MaxFileBytes)
		if !ok {
			return nil, false
		}
		if direct && installNative(data) {
			// A program, not a script: nothing a rule here can read, and not tried again while it stays the same
			// and is run by itself.
			now.Native = true
			seen[path] = now
			return nil, true
		}
		signals, ok := InstallFileSignals(path, installLossyText(data), cancelled)
		if !ok {
			return nil, false // not kept: read again next round
		}
		now.Signals = nonNilSignals(signals)
		seen[path] = now
		return now.Signals, true
	}

	var found []installFinding
	packages := 0
	checkPackage := func(pkg, project string) {
		if ctx.IsCancelled() {
			return
		}
		if packages >= r.Limits.MaxPackages {
			cutShort++
			return
		}
		packages++
		manifest := filepath.Join(pkg, "package.json")
		now, ok := stat(manifest)
		if !ok {
			return
		}
		info := (*InstallScanPackage)(nil)
		var hookSignals []InstallSignal
		if k, ok := cached(manifest, now); ok && k.Package != nil {
			seen[manifest] = k
			if k.Package.Invalid {
				return
			}
			if k.Package.TooDeep {
				tooDeep++
				return
			}
			info, hookSignals = k.Package, k.Signals
		} else {
			data, ok := read(manifest, now.Size, r.Limits.MaxPackageBytes)
			if !ok {
				return
			}
			p, ok := ParseInstallPackage(data)
			if !ok {
				deep := installTooDeep(data)
				now.Package = &InstallScanPackage{Invalid: !deep, TooDeep: deep, Hooks: []string{}, HookLines: map[string]int{}, Targets: []InstallTarget{}}
				seen[manifest] = now
				if deep {
					tooDeep++
				}
				return
			}
			info = &InstallScanPackage{Who: installWho(p, pkg), NameDiffers: p.Name != installFolderName(pkg), Hooks: []string{},
				HookLines: map[string]int{}, Targets: []InstallTarget{}}
			for _, h := range InstallHooks {
				if _, ok := p.Hooks[h]; ok {
					info.Hooks = append(info.Hooks, h)
					info.HookLines[h] = p.Lines[h]
				}
			}
			if len(info.Hooks) > 0 {
				info.Targets = InstallPackageTargets(pkg, p)
				hookSignals = InstallHookSignals(p)
			}
			now.Package, now.Signals = info, nonNilSignals(hookSignals)
			seen[manifest] = now
		}
		if len(info.Hooks) == 0 {
			return
		}
		f := installFinding{who: info.Who, kind: "npm", pkg: pkg, project: project, nameDiffers: info.NameDiffers}
		for _, s := range hookSignals {
			hook := info.Hooks[0]
			for _, h := range info.Hooks {
				if len(s.Lines) > 0 && info.HookLines[h] == s.Lines[0] {
					hook = h
				}
			}
			f.signals = append(f.signals, installPlaced{s, hook, "package.json"})
		}
		for _, t := range info.Targets {
			sigs, _ := scanScript(filepath.Join(pkg, t.Path), t.Direct)
			for _, s := range sigs {
				f.signals = append(f.signals, installPlaced{s, t.Hook, t.Path})
			}
		}
		if len(f.signals) > 0 {
			found = append(found, f)
		}
	}

	var left []string
	for _, root := range ctx.ProjectRoots {
		if !ctx.MayLook(root) {
			left = append(left, ctx.Shown(root)+" 里项目的依赖")
			continue
		}
		for _, project := range aiProjectFolders(root, r.Limits.MaxProjects) {
			if ctx.IsCancelled() {
				break
			}
			modules, cut := r.installModulesIn(project)
			if cut {
				cutShort++
			}
			for _, m := range modules {
				for _, pkg := range installPackagesIn(m, true) {
					checkPackage(pkg, project)
				}
			}
			for _, src := range installSdists(project) {
				setup := filepath.Join(src, "setup.py")
				sigs, _ := scanScript(setup, false)
				if len(sigs) == 0 {
					continue
				}
				f := installFinding{who: installPythonName(filepath.Base(src)), kind: "python", pkg: src, project: project}
				for _, s := range sigs {
					f.signals = append(f.signals, installPlaced{s, "setup.py", "setup.py"})
				}
				found = append(found, f)
			}
		}
	}
	homeDirs, homeVersions := installGlobalHomes(ctx.Home)
	globals := append(append([]string{}, r.GlobalDirs...), homeDirs...)
	for _, v := range append(append([]string{}, r.GlobalVersions...), homeVersions...) {
		c := Children(v)
		sort.Strings(c)
		for _, n := range c {
			globals = append(globals, filepath.Join(n, "lib/node_modules"))
		}
	}
	for _, g := range globals {
		if !ctx.MayLook(g) || !aiIsDir(g) || ctx.IsCancelled() {
			continue
		}
		for _, pkg := range installPackagesIn(g, true) {
			checkPackage(pkg, "")
		}
	}

	// What was read is kept; forgotten is what is gone, not what sits where this round may not look (nor what an
	// interrupted round did not get to).
	interrupted := ctx.IsCancelled()
	if ctx.Store != nil {
		var forget []string
		for p := range known {
			if _, ok := seen[p]; !ok && ctx.MayLook(p) && !interrupted {
				forget = append(forget, p)
			}
		}
		sort.Strings(forget)
		changed := map[string]InstallScan{}
		for p, s := range seen {
			if k, ok := known[p]; !ok || !installSame(k, s) {
				changed[p] = s
			}
		}
		if len(changed) > 0 || len(forget) > 0 {
			table.Apply(changed, forget, false)
		}
	}

	if interrupted {
		return nil, Skip(Interrupted)
	}
	out := installFindings(ctx, found)
	if notRead > 0 || cutShort > 0 || tooDeep > 0 {
		var parts []string
		if notRead > 0 {
			parts = append(parts, strconv.Itoa(notRead)+" 个文件太大或读不了")
		}
		if tooDeep > 0 {
			parts = append(parts, strconv.Itoa(tooDeep)+" 个 package.json 嵌套太深、读不出钩子")
		}
		if cutShort > 0 {
			parts = append(parts, "依赖太多，有的项目没看全")
		}
		out = append(out, Finding{Rule: "deps.install-script.partial", Category: CatMalware, Severity: Low, Verdict: Info, Path: "",
			Title:    "依赖的安装脚本有的没查（" + strings.Join(parts, "；") + "）",
			Evidence: map[string]string{"files": strconv.Itoa(notRead + tooDeep), "how": "没查的下一轮再试；文件太大的不会自己变小，不放心就到包的主页看看它的安装脚本做什么"}})
	}
	if len(left) > 0 {
		return nil, Skip(NotLooked(strings.Join(aiSortedUnique(left), "、")+" "), out...)
	}
	return out, nil
}

// installSame: a file is as it was when it was read (and read by the same rules).
func installSame(a, b InstallScan) bool {
	return a.Inode == b.Inode && a.Size == b.Size && a.Modified == b.Modified && a.Changed == b.Changed && a.Rules == b.Rules
}

// installNative: a program (Mach-O, ELF) that no shell runs as a script when it is run by itself. The magic number
// alone is not enough: when the system cannot run a file it is handed to sh, which runs it as a script unless it
// sees a NUL before the first new line in the first 80 bytes (bash's check for a binary file, which a real program's
// header always has and "\xCF\xFA\xED\xFE\ncurl … | sh" does not). Run through an interpreter (sh x, node x), a
// file is read as a script whatever it starts with: the caller does not ask then.
func installNative(data []byte) bool {
	magic := false
	for _, m := range [][]byte{{0xFE, 0xED, 0xFA, 0xCE}, {0xFE, 0xED, 0xFA, 0xCF}, {0xCE, 0xFA, 0xED, 0xFE}, {0xCF, 0xFA, 0xED, 0xFE},
		{0xCA, 0xFE, 0xBA, 0xBE}, {0x7F, 0x45, 0x4C, 0x46}} {
		if bytes.HasPrefix(data, m) {
			magic = true
		}
	}
	if !magic {
		return false
	}
	head := data
	if len(head) > 80 {
		head = head[:80]
	}
	for _, b := range head {
		switch b {
		case '\n':
			return false
		case 0:
			return true
		}
	}
	return false
}

// installTooDeep: JSON nested deeper than Go's reader goes (10000 levels; JSON.parse has no such limit), which is
// why a package.json npm reads could not be read here.
func installTooDeep(data []byte) bool {
	depth := 0
	inString, escaped := false, false
	for _, b := range data {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
		case b == '"':
			inString = true
		case b == '[' || b == '{':
			depth++
			if depth >= 10000 {
				return true
			}
		case b == ']' || b == '}':
			depth--
		}
	}
	return false
}

// installLossyText is a script as text however it is encoded: node and sh run a file with a stray byte or a NUL in
// it, so the checks read it too (each bad byte a replacement character, a NUL a space, a byte order mark dropped).
func installLossyText(data []byte) string {
	s := strings.ReplaceAll(string(bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))), "\x00", " ")
	return strings.ToValidUTF8(s, "\uFFFD")
}

// installPythonName is a source package's folder name as shown, when it is a plain name.
func installPythonName(folder string) string {
	if installPythonRx.has(folder) {
		return folder
	}
	return "一个名字不合规矩的包"
}

var installPythonRx = icuCS(`^[A-Za-z0-9][A-Za-z0-9_-]{0,60}(?:\.[A-Za-z0-9_-]{1,40})?$`)

func nonNilSignals(s []InstallSignal) []InstallSignal {
	if s == nil {
		return []InstallSignal{}
	}
	return s
}

// installHow is what to do, by the most serious kind.
func installHow(kind SignalKind, python bool) string {
	again := "先别在这个项目里再装依赖（装一次它就再跑一次）"
	if python {
		again = "先别再装这个包（装一次它的 setup.py 就再跑一次）"
	}
	base := again + "；到包的主页或代码仓库看看这个版本是不是被人报过，认不出就换掉或删掉这个依赖"
	switch kind {
	case SignalExfil:
		return base + "；装过的话，把它可能读过的令牌和密钥（npm、GitHub、云服务、SSH）换新的"
	case SignalPersistence:
		return base + "；装过的话，看看 ~/Library/LaunchAgents、crontab -l、shell 的启动文件和项目的 .github/workflows 里有没有多出来的东西"
	case SignalDownloadExec:
		return base + "；装过的话，它下载的程序可能已经在跑，看看病毒扫描和开机自己运行的东西"
	}
	return base
}

// installFindings: one finding per package and version with the same signals, the projects that have it listed.
func installFindings(ctx *Context, found []installFinding) []Finding {
	type group struct {
		first  installFinding
		places []string
	}
	var order []string
	groups := map[string]*group{}
	for _, f := range found {
		var labels []string
		for _, s := range f.signals {
			labels = append(labels, s.Label)
		}
		key := f.kind + "|" + f.who + "|" + strings.Join(aiSortedUnique(labels), "|")
		where := "全局装的 npm 包"
		if f.project != "" {
			where = "项目 " + aiClean(filepath.Base(f.project), 40)
		}
		if g, ok := groups[key]; ok {
			g.places = append(g.places, where)
			continue
		}
		order = append(order, key)
		groups[key] = &group{first: f, places: []string{where}}
	}
	out := []Finding{}
	for _, k := range order {
		g := groups[k]
		f := g.first
		signals := append([]installPlaced{}, f.signals...)
		sort.SliceStable(signals, func(i, j int) bool {
			a, b := signals[i], signals[j]
			if a.Severity.Rank() != b.Severity.Rank() {
				return a.Severity.Rank() > b.Severity.Rank()
			}
			return signalRank(a.Kind) < signalRank(b.Kind)
		})
		top := signals[0]
		places := aiSortedUnique(g.places)
		whose := places[0]
		if len(places) > 1 {
			whose += " 等 " + strconv.Itoa(len(places)) + " 处"
		}
		var title string
		if f.kind == "python" {
			title = whose + " 里从源码装的 Python 包 " + f.who + " 装的时候会" + top.Phrase
		} else if f.project == "" && len(places) == 1 {
			title = "全局装的 npm 包 " + f.who + " 安装时会" + top.Phrase
		} else {
			sep := " "
			if len(places) > 1 {
				sep = ""
			}
			title = whose + sep + "的依赖 " + f.who + " 安装时会" + top.Phrase
		}
		labels := map[string]bool{}
		for _, s := range signals {
			labels[s.Label] = true
		}
		if len(labels) > 1 {
			title += "，另有 " + strconv.Itoa(len(labels)-1) + " 处要看"
		}
		var did []string
		var kinds, hooks, files []string
		for i, s := range signals {
			kinds = append(kinds, string(s.Kind))
			hooks = append(hooks, s.hook)
			shown := installShownFile(s.file)
			files = append(files, shown)
			if i < 8 {
				did = append(did, s.Label+"（"+shown+" "+installLinesText(s.Lines)+"）")
			}
		}
		runs := "装这个包时 npm 会自动运行它的 " + strings.Join(aiSortedUnique(hooks), "、") + " 脚本，用的是你的权限"
		if f.kind == "python" {
			runs = "从源码装这个包时 pip 会运行它的 setup.py，用的是你的权限"
		}
		ev := map[string]string{
			"dependency": f.who,
			"where":      strings.Join(places, "、"),
			"hook":       strings.Join(aiSortedUnique(hooks), "、"),
			"files":      strings.Join(aiSortedUnique(files), "、"),
			"kinds":      strings.Join(aiSortedUnique(kinds), ","),
			"why":        aiCut(runs+"。规则查到："+strings.Join(did, "；")+"。规则会看错，所以是要确认，不是急事", 900),
			"how":        installHow(top.Kind, f.kind == "python"),
		}
		if f.nameDiffers {
			ev["name"] = "它的 package.json 里写的名字和 npm 装它的文件夹对不上（冒名的包常这样）；这里写的是文件夹的名字"
		}
		out = append(out, Finding{Rule: "deps.install-script", Category: CatMalware, Severity: Medium, Verdict: Confirm, Path: f.pkg,
			Title: title, Evidence: ev, Key: k})
	}
	return out
}
