package core

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProcessRule finds processes that should not be there: whose program was deleted, that were started with
// DYLD_INSERT_LIBRARIES (another library pushed into them), that loaded code from a temporary folder or Downloads or
// run on libraries since deleted, that pile up under one parent (e.g. a status poll that spawns `lsof` every few
// seconds and never reaps it), or that were left running after their parent went away. Only the current user's
// processes; others are not looked at.
type ProcessRule struct {
	PileUp    int
	OrphanAge time.Duration
	// Snapshot is the process table; nil: this Mac's.
	Snapshot func() []ProcInfo
	// Environment is what a process was started with; ok false when it cannot be read. nil: this Mac's.
	Environment func(pid int32) ([]string, bool)
	// Signature is who vouches for a library file; nil: codesign.
	Signature func(path string) Signature
	// Libraries are the files a process has mapped as code beside its program; ok false when they cannot be read.
	// nil: this Mac's.
	Libraries func(pid int32, program string) ([]LoadedLibrary, bool)
	// SystemTemp: the Mac's shared temporary folders count as temporary (/tmp, /var/tmp, each user's
	// /var/folders/…/T), beside the round's own Tmp; a fake home has only its own.
	SystemTemp bool
	// LaunchdPIDs are the processes launchd runs as jobs (their parent is 1 by design); ok false when launchctl did
	// not answer. nil: `launchctl list`.
	LaunchdPIDs func() (map[int32]bool, bool)
	// DetachedOnPurpose are daemons that detach on purpose.
	DetachedOnPurpose map[string]bool
}

func init() { Register("process", NewProcessRule) }

// NewProcessRule is the rule for this Mac (l nil) or a fake home, its processes and launchd's jobs from f.
func NewProcessRule(l *Layout, f *Fakes) Rule {
	r := &ProcessRule{PileUp: 20, OrphanAge: 6 * time.Hour, DetachedOnPurpose: map[string]bool{"gpg-agent": true, "ssh-agent": true,
		"dirmngr": true, "keybase": true, "tmux": true, "screen": true, "mosh-server": true, "Xquartz": true}, SystemTemp: true}
	if l != nil {
		r.SystemTemp = false
		r.Libraries = func(pid int32, _ string) ([]LoadedLibrary, bool) {
			for _, p := range f.Processes {
				if p.PID == pid && p.Libraries != nil {
					out := make([]LoadedLibrary, 0, len(*p.Libraries))
					for _, l := range *p.Libraries {
						out = append(out, LoadedLibrary{Path: l.Path, Deleted: l.Deleted})
					}
					return out, true
				}
			}
			return nil, false
		}
		procs := make([]ProcInfo, 0, len(f.Processes))
		for _, p := range f.Processes {
			procs = append(procs, ProcInfo{PID: p.PID, PPID: p.PPID, UID: p.UID, Path: p.Path, Started: p.Started})
		}
		r.Snapshot = func() []ProcInfo { return procs }
		r.Environment = func(pid int32) ([]string, bool) {
			for _, p := range f.Processes {
				if p.PID == pid && p.Environment != nil {
					return *p.Environment, true
				}
			}
			return nil, false
		}
		r.Signature = func(p string) Signature {
			if s, ok := f.Codesign[p]; ok {
				return ParseSignature(s)
			}
			return LibrarySignature(p)
		}
		r.LaunchdPIDs = func() (map[int32]bool, bool) {
			if f.LaunchdPIDs == nil {
				return nil, false
			}
			set := map[int32]bool{}
			for _, p := range *f.LaunchdPIDs {
				set[p] = true
			}
			return set, true
		}
	}
	return r
}

func (r *ProcessRule) ID() string      { return "process" }
func (r *ProcessRule) Emits() []string { return []string{"process"} }

// LaunchctlPIDs are the processes `launchctl list` names (its first column); ok false when it did not answer.
func LaunchctlPIDs() (map[int32]bool, bool) {
	res := Run("/bin/launchctl", []string{"list"}, RunOpts{Timeout: 10 * time.Second})
	if res.Status != 0 || res.Stdout == "" {
		return nil, false
	}
	out := map[int32]bool{}
	for i, line := range procSplit(res.Stdout, "\n") {
		if i == 0 {
			continue
		}
		if f := procSplit(line, "\t"); len(f) > 0 {
			if pid, err := strconv.ParseInt(f[0], 10, 32); err == nil {
				out[int32(pid)] = true
			}
		}
	}
	return out, true
}

// procSplit is Swift's split(separator:): the pieces between separators, empty ones left out.
func procSplit(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func procInAppBundle(path string) bool { return strings.Contains(path, ".app/") }

// procSystemManaged: system programs and bundled services. launchd runs XPC services and extensions with parent 1,
// and they are not in `launchctl list` either. Not ours to judge.
func procSystemManaged(path string) bool {
	for _, p := range []string{"/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/Library/Apple/", "/private/var/db/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return strings.Contains(path, ".xpc/") || strings.Contains(path, ".appex/") || procInAppBundle(path)
}

func (r *ProcessRule) Run(ctx *Context) ([]Finding, error) {
	me := uint32(os.Getuid())
	snapshot := r.Snapshot
	if snapshot == nil {
		snapshot = ProcSnapshot
	}
	all := snapshot()
	if len(all) == 0 {
		return nil, Skip("读不到进程列表")
	}
	var mine []ProcInfo
	for _, p := range all {
		if p.UID == me && p.Path != "" {
			mine = append(mine, p)
		}
	}
	var out []Finding

	// One finding per deleted program: an app's helpers come in dozens and all point at the same file.
	gone := map[string][]ProcInfo{}
	for _, p := range mine {
		if ctx.MayLook(p.Path) && !Exists(p.Path) {
			gone[p.Path] = append(gone[p.Path], p)
		}
	}
	paths := make([]string, 0, len(gone))
	for p := range gone {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		ps := append([]ProcInfo{}, gone[path]...)
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].Started.Before(ps[j].Started) })
		name := filepath.Base(path)
		title := strconv.Itoa(len(ps)) + " 个 " + name + " 进程的程序已经被删掉了，还在跑"
		if len(ps) == 1 {
			title = "进程 " + strconv.Itoa(int(ps[0].PID)) + "（" + name + "）的程序已经被删掉了，它还在跑"
		}
		var pids []string
		for i, p := range ps {
			if i == 20 {
				break
			}
			pids = append(pids, strconv.Itoa(int(p.PID)))
		}
		out = append(out, Finding{Rule: "process.deleted-binary", Category: CatProcess, Severity: Medium, Verdict: Confirm, Path: path,
			Title: title, Evidence: map[string]string{"pids": strings.Join(pids, ","), "count": strconv.Itoa(len(ps)),
				"started": ISODay(ps[0].Started)}})
	}

	out = append(out, r.dyldInserted(ctx, mine)...)
	out = append(out, r.libraries(ctx, mine, gone)...)

	// App helpers (browser renderers...) come in dozens by design; pile-ups worth reporting are tools like lsof.
	groups := map[string][]ProcInfo{}
	var order []string
	for _, p := range mine {
		if p.PPID > 1 && !procInAppBundle(p.Path) {
			k := strconv.Itoa(int(p.PPID)) + "\x00" + p.Path
			if _, ok := groups[k]; !ok {
				order = append(order, k)
			}
			groups[k] = append(groups[k], p)
		}
	}
	for _, k := range order {
		g := groups[k]
		if len(g) < r.PileUp {
			continue
		}
		parent := "?"
		for _, p := range all {
			if p.PID == g[0].PPID {
				parent = p.Path
				break
			}
		}
		out = append(out, Finding{Rule: "process.pile-up", Category: CatProcess, Severity: Medium, Verdict: Info, Path: g[0].Path,
			Title: DisplayName(g[0].Path) + " 在同一个父进程下堆了 " + strconv.Itoa(len(g)) + " 个",
			Evidence: map[string]string{"count": strconv.Itoa(len(g)), "parent_pid": strconv.Itoa(int(g[0].PPID)), "parent": parent,
				"hint": "多半是父进程反复启动它、却没等它结束；占内存，也可能拖慢系统"},
			Key: parent + "\x00" + g[0].Path}) // one finding per parent
	}

	// Without launchd's job list every user job with parent 1 would look orphaned.
	launchd := r.LaunchdPIDs
	if launchd == nil {
		launchd = LaunchctlPIDs
	}
	jobs, ok := launchd()
	if !ok {
		out = append(out, Finding{Rule: "process.partial", Category: CatProcess, Severity: Low, Verdict: Info,
			Title: "launchctl 没答复，这一轮没查孤儿进程", Evidence: map[string]string{}})
		return out, nil
	}
	var orphans []ProcInfo
	for _, p := range mine {
		if p.PPID == 1 && !jobs[p.PID] && !procSystemManaged(p.Path) && !r.DetachedOnPurpose[filepath.Base(p.Path)] &&
			ctx.Now.Sub(p.Started) >= r.OrphanAge {
			orphans = append(orphans, p)
		}
	}
	sort.SliceStable(orphans, func(i, j int) bool { return orphans[i].Started.Before(orphans[j].Started) })
	if len(orphans) > 0 {
		// One finding for all of them: a list to look through, not dozens of alerts.
		var list, pids []string
		for i, p := range orphans {
			pids = append(pids, strconv.Itoa(int(p.PID)))
			if i < 10 {
				hours := int(ctx.Now.Sub(p.Started).Seconds() / 3600)
				list = append(list, filepath.Base(p.Path)+"（"+strconv.Itoa(int(p.PID))+"，"+strconv.Itoa(hours)+" 小时）")
			}
		}
		out = append(out, Finding{Rule: "process.orphan", Category: CatProcess, Severity: Low, Verdict: Info,
			Title: strconv.Itoa(len(orphans)) + " 个后台进程的父进程已经退出，还在跑",
			Evidence: map[string]string{"count": strconv.Itoa(len(orphans)), "pids": strings.Join(pids, ","),
				"oldest": strings.Join(list, "；"),
				"hint":   "启动它们的程序已经退出了；不是你自己放在后台的任务的话，多半是没收拾干净"}})
	}
	return out, nil
}

// dyldInserted: processes started with DYLD_INSERT_LIBRARIES, read from what each was started with: one finding per
// library, with the processes that carry it (what a shell starts inherits it). Apple's own libraries are left out:
// the system's (Guard Malloc; told by malwareSystemProgram, however the path is spelled) and Apple-signed ones like
// Xcode's, which it sets when it runs an app to debug. A library someone else signed is medium; one nobody vouches
// for, no longer there, or not checked, high. Who signed it is read for the first procDyldSignatures (the paths are
// anyone's to write, and as many as they like).
func (r *ProcessRule) dyldInserted(ctx *Context, mine []ProcInfo) []Finding {
	environment := r.Environment
	if environment == nil {
		environment = ProcEnvironment
	}
	signature := r.Signature
	if signature == nil {
		signature = LibrarySignature
	}
	by := map[string][]ProcInfo{}
	for _, p := range mine {
		env, ok := environment(p.PID)
		if !ok {
			continue
		}
		for _, e := range env {
			v, found := strings.CutPrefix(e, dyldInjecting+"=")
			if !found {
				continue
			}
			seen := map[string]bool{}
			for _, lib := range strings.Split(v, ":") {
				if lib != "" && !seen[lib] {
					seen[lib] = true
					by[lib] = append(by[lib], p)
				}
			}
			break // the loader reads the first
		}
	}
	libs := make([]string, 0, len(by))
	for lib := range by {
		libs = append(libs, lib)
	}
	sort.Strings(libs)
	sigs := newProcSignatures(ctx, signature, procDyldSignatures)
	var out []Finding
	for _, lib := range libs {
		if malwareSystemProgram(lib) {
			continue
		}
		sig, label := sigs.of(lib)
		if sig.Kind == SigApple {
			continue
		}
		ps := append([]ProcInfo{}, by[lib]...)
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].Started.Before(ps[j].Started) })
		name := filepath.Base(lib)
		title := strconv.Itoa(len(ps)) + " 个进程启动时带着 " + dyldInjecting + "，要先载入 " + name
		if len(ps) == 1 {
			title = "进程 " + strconv.Itoa(int(ps[0].PID)) + "（" + filepath.Base(ps[0].Path) + "）启动时带着 " + dyldInjecting + "，要先载入 " + name
		}
		var pids, programs []string
		seen := map[string]bool{}
		for i, p := range ps {
			if i < 20 {
				pids = append(pids, strconv.Itoa(int(p.PID)))
			}
			if n := filepath.Base(p.Path); !seen[n] && len(programs) < 10 {
				seen[n] = true
				programs = append(programs, n)
			}
		}
		sev := High
		if sig.Kind == SigDeveloper {
			sev = Medium
		}
		out = append(out, Finding{Rule: "process.dyld-insert", Category: CatProcess, Severity: sev, Verdict: Info, Path: lib,
			Title: title, Evidence: map[string]string{"variable": dyldInjecting, "library": lib, "signature": label,
				"pids": strings.Join(pids, ","), "count": strconv.Itoa(len(ps)), "programs": strings.Join(programs, "、"),
				"started": ISODay(ps[0].Started), "why": "恶意软件用它把自己的代码塞进别的程序；开发调试时也有人这样设",
				"how": "是你自己调试时设的，调完退出这些程序就好；不认得的，退出这些程序，再看看是谁设的（后台任务、shell 的启动文件）"},
			Key: lib})
	}
	return out
}

// libraryPlace: where a loaded library sits that a program's code seldom comes from: "临时文件夹" or "下载文件夹"; ""
// elsewhere. Only by place: an app macOS runs from a hidden copy because it was opened where it was downloaded (App
// Translocation, /private/var/folders/…/T/AppTranslocation/<UUID>/d/…) loads its frameworks from the temporary
// folder too, and they are left out as that app's own (libraries), not by the folder's name, which anyone can give.
func (r *ProcessRule) libraryPlace(ctx *Context, lib string) string {
	if r.SystemTemp {
		for _, t := range []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"} {
			if strings.HasPrefix(lib, t) {
				return "临时文件夹"
			}
		}
		// /private/var/folders/<xx>/<id>/T/…: a user's temporary folder (C/ is caches, 0/ the system's)
		rest, ok := strings.CutPrefix(strings.TrimPrefix(lib, "/private"), "/var/folders/")
		if parts := strings.SplitN(rest, "/", 4); ok && len(parts) == 4 && parts[2] == "T" {
			return "临时文件夹"
		}
	}
	// The kernel names /private/var/…, a folder may be given as /var/… (a fake home's): compared without /private
	under := func(dir string) bool {
		return dir != "" && strings.HasPrefix(procNoPrivate(lib), strings.TrimSuffix(procNoPrivate(dir), "/")+"/")
	}
	if under(ctx.Tmp) {
		return "临时文件夹"
	}
	if under(filepath.Join(ctx.Home, "Downloads")) {
		return "下载文件夹"
	}
	return ""
}

// procNoPrivate is a path without the /private in front of /private/var, /private/tmp, /private/etc.
func procNoPrivate(p string) string {
	for _, d := range []string{"/private/var", "/private/tmp", "/private/etc"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return strings.TrimPrefix(p, "/private")
		}
	}
	return p
}

// procLibraryGroup is one program's processes and the libraries they loaded of one kind, each once; users: which of
// the processes loaded each.
type procLibraryGroup struct {
	procs []ProcInfo
	libs  []LoadedLibrary
	seen  map[string]bool
	users map[string][]ProcInfo
}

// keep leaves only libs and the processes that loaded one of them.
func (g *procLibraryGroup) keep(libs []LoadedLibrary) {
	in := map[int32]bool{}
	for _, l := range libs {
		for _, p := range g.users[l.Path] {
			in[p.PID] = true
		}
	}
	var procs []ProcInfo
	for _, p := range g.procs {
		if in[p.PID] {
			procs = append(procs, p)
		}
	}
	g.procs, g.libs = procs, libs
}

// libraries: what this user's processes loaded beside their own program (ProcLibraries): code from a temporary
// folder or Downloads (process.library-temp), and libraries whose file was deleted after they were loaded
// (process.library-deleted). One finding per program and kind, its processes together. Not Apple's own (the system's
// locations), not an app's own frameworks in its bundle, not a process whose program itself is gone
// (process.deleted-binary says it). Who signed a library is read for the ten listed of each program (procSignatures:
// each path once a round, at most procLibrarySignatures): an Apple-signed one is not counted, a signature broken
// since signing makes it high.
func (r *ProcessRule) libraries(ctx *Context, mine []ProcInfo, gone map[string][]ProcInfo) []Finding {
	libraries := r.Libraries
	if libraries == nil {
		libraries = ProcLibraries
	}
	signature := r.Signature
	if signature == nil {
		signature = LibrarySignature
	}
	temp, deleted := map[string]*procLibraryGroup{}, map[string]*procLibraryGroup{}
	add := func(m map[string]*procLibraryGroup, p ProcInfo, l LoadedLibrary) {
		g := m[p.Path]
		if g == nil {
			g = &procLibraryGroup{seen: map[string]bool{}, users: map[string][]ProcInfo{}}
			m[p.Path] = g
		}
		if len(g.procs) == 0 || g.procs[len(g.procs)-1].PID != p.PID {
			g.procs = append(g.procs, p)
		}
		if !g.seen[l.Path] {
			g.seen[l.Path] = true
			g.libs = append(g.libs, l)
		}
		g.users[l.Path] = append(g.users[l.Path], p)
	}
	for _, p := range mine {
		if _, ok := gone[p.Path]; ok {
			continue
		}
		libs, ok := libraries(p.PID, p.Path)
		if !ok {
			continue
		}
		own := ""
		if i := strings.Index(p.Path, ".app/"); i >= 0 {
			own = p.Path[:i+len(".app/")] // the app's own bundle, its helper apps' frameworks too
		}
		for _, l := range libs {
			if malwareSystemProgram(l.Path) || (own != "" && strings.HasPrefix(l.Path, own)) {
				continue
			}
			if r.libraryPlace(ctx, l.Path) != "" {
				add(temp, p, l)
			} else if l.Deleted {
				add(deleted, p, l)
			}
		}
	}
	var out []Finding
	sigs := newProcSignatures(ctx, signature, procLibrarySignatures)
	for _, prog := range procSortedKeys(temp) {
		g := temp[prog]
		sev := Medium
		var shown []string
		var kept []LoadedLibrary
		places := map[string]bool{}
		for i, l := range g.libs {
			label := "文件已经删掉"
			if !l.Deleted {
				label = "没查签名"
				if i < 10 {
					var sig Signature
					if sig, label = sigs.of(l.Path); sig.Kind == SigApple {
						continue
					}
					if sig.Kind == SigInvalid {
						sev = High
					}
				}
			}
			kept = append(kept, l)
			places[r.libraryPlace(ctx, l.Path)] = true
			if len(shown) < 10 {
				shown = append(shown, l.Path+"（"+label+"）")
			}
		}
		if len(kept) == 0 {
			continue
		}
		place := "临时文件夹"
		if places["下载文件夹"] {
			place = "下载文件夹"
			if places["临时文件夹"] {
				place = "临时文件夹和下载文件夹"
			}
		}
		g.keep(kept) // not the processes whose only such library was Apple's
		out = append(out, procLibraryFinding("process.library-temp", sev, prog, g, "载入了"+place+"里的", "", kept[0].Path,
			map[string]string{"libraries": strings.Join(shown, "；"), "place": place,
				"why": "正常的程序很少从临时文件夹、下载文件夹载入代码；恶意软件常把自己放在这些地方",
				"how": "认得这个程序就不用管（有的工具会把自带的库先解到临时文件夹再用）；不认得的，退出它，再查一遍病毒"}))
	}
	for _, prog := range procSortedKeys(deleted) {
		g := deleted[prog]
		var shown []string
		for i, l := range g.libs {
			if i < 10 {
				shown = append(shown, l.Path)
			}
		}
		out = append(out, procLibraryFinding("process.library-deleted", Medium, prog, g, "载入的", "已经被删掉了，还在用", prog,
			map[string]string{"libraries": strings.Join(shown, "；"),
				"hint": "多半是程序或它用的库升级了、程序还没重启：重启这个程序就好。不认得这个程序的话要留意：有的恶意软件载入以后就删掉自己的文件"}))
	}
	return out
}

// procLibraryFinding: one program's processes and their libraries of one kind, titled 「进程 4100（tool）载入了临时文件夹
// 里的库 hook.dylib」「3 个 tool 进程载入的 2 个库已经被删掉了，还在用」.
func procLibraryFinding(rule string, sev Severity, prog string, g *procLibraryGroup, before, after, path string, ev map[string]string) Finding {
	ps := append([]ProcInfo{}, g.procs...)
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Started.Before(ps[j].Started) })
	name := filepath.Base(prog)
	who := "进程 " + strconv.Itoa(int(ps[0].PID)) + "（" + name + "）"
	if len(ps) > 1 {
		who = strconv.Itoa(len(ps)) + " 个 " + name + " 进程"
	}
	what := "库 " + filepath.Base(g.libs[0].Path)
	if after != "" {
		what += " "
	}
	if len(g.libs) > 1 {
		what = " " + strconv.Itoa(len(g.libs)) + " 个库"
	}
	var pids []string
	for i, p := range ps {
		if i == 20 {
			break
		}
		pids = append(pids, strconv.Itoa(int(p.PID)))
	}
	ev["program"], ev["pids"], ev["count"], ev["started"] = prog, strings.Join(pids, ","), strconv.Itoa(len(ps)), ISODay(ps[0].Started)
	ev["library_count"] = strconv.Itoa(len(g.libs))
	return Finding{Rule: rule, Category: CatProcess, Severity: sev, Verdict: Info, Path: path, Title: who + before + what + after,
		Evidence: ev, Key: prog}
}

func procSortedKeys(m map[string]*procLibraryGroup) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// procDyldSignatures: libraries of DYLD_INSERT_LIBRARIES whose signature one round reads, at most;
// procLibrarySignatures: libraries loaded from a temporary folder or Downloads.
const (
	procDyldSignatures    = 10
	procLibrarySignatures = 20
)

// procSignatures reads who signed the libraries a check names, from paths a process was given (anyone may write
// them): each path once, only a regular file (codesign waits on a named pipe for as long as nobody writes to it),
// only where this round may look (links followed one at a time, never into a guarded folder), at most left of them.
type procSignatures struct {
	ctx  *Context
	read func(string) Signature
	left int
	done map[string]procSigned
}

type procSigned struct {
	sig   Signature
	label string
}

func newProcSignatures(ctx *Context, read func(string) Signature, max int) *procSignatures {
	return &procSignatures{ctx: ctx, read: read, left: max, done: map[string]procSigned{}}
}

// of: who signed the library at path, and how to say it. SigUnknown when it was not read (a relative path, a guarded
// folder, not a regular file, past the limit), SigMissing when it is not there or cannot be reached.
func (s *procSignatures) of(path string) (Signature, string) {
	if d, ok := s.done[path]; ok {
		return d.sig, d.label
	}
	sig, label := s.check(path)
	s.done[path] = procSigned{sig, label}
	return sig, label
}

func (s *procSignatures) check(path string) (Signature, string) {
	unknown := Signature{Kind: SigUnknown}
	if !strings.HasPrefix(path, "/") {
		return unknown, "相对路径，没查签名"
	}
	clean := systemSpelling(path)
	if !s.ctx.MayLook(clean) {
		return unknown, unknown.Label()
	}
	real, ok := ResolvedPath(clean, s.ctx)
	if !ok {
		return Signature{Kind: SigMissing}, "不在了或读不到"
	}
	if !aiIsReg(real) {
		return unknown, "不是普通文件，没查签名"
	}
	if s.left <= 0 {
		return unknown, "没查签名"
	}
	s.left--
	sig := s.read(real)
	return sig, sig.Label()
}
