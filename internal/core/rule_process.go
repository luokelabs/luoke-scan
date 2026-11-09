package core

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProcessRule finds processes that should not be there: whose program was deleted, that pile up under one parent
// (e.g. a status poll that spawns `lsof` every few seconds and never reaps it), or that were left running after
// their parent went away. Only the current user's processes; others are not looked at.
type ProcessRule struct {
	PileUp    int
	OrphanAge time.Duration
	// Snapshot is the process table; nil: this Mac's.
	Snapshot func() []ProcInfo
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
		"dirmngr": true, "keybase": true, "tmux": true, "screen": true, "mosh-server": true, "Xquartz": true}}
	if l != nil {
		procs := make([]ProcInfo, 0, len(f.Processes))
		for _, p := range f.Processes {
			procs = append(procs, ProcInfo{PID: p.PID, PPID: p.PPID, UID: p.UID, Path: p.Path, Started: p.Started})
		}
		r.Snapshot = func() []ProcInfo { return procs }
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
			Title: filepath.Base(g[0].Path) + " 在同一个父进程下堆了 " + strconv.Itoa(len(g)) + " 个",
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
