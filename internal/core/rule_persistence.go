package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// PersistenceRule: everything that starts by itself, beyond the user LaunchAgents with a missing target
// (LaunchAgentRule): the system-wide LaunchAgents and LaunchDaemons, what apps register to run in the background or at
// login (the jobs in this user's launchd session that no plist folder accounts for), the user's crontab, and the PATH
// set in shell startup files. For each program it reads the code signature (never runs it) and whether this user can
// replace it, and remembers what it saw: something that appears later without anyone vouching for it is what malware
// does to stay. The first round only records (a baseline). Something new is reported every round for NewFor after it
// was first seen; what could not be read this round (launchctl or crontab did not answer) keeps what was seen of it
// before. Swift: Rules/PersistenceRule.swift.
type PersistenceRule struct {
	// PlistDirs are the folders of launchd jobs, each with its scope.
	PlistDirs func(home string) []ScopedDir
	// SessionLabels are the jobs in this user's launchd session with their pid as launchctl shows it ("-" when not
	// running); ok false when launchctl does not answer.
	SessionLabels func(uid uint32) (map[string]string, bool)
	// DescribeJob is one job's details (launchctl print gui/<uid>/<label>); ok false when it is gone.
	DescribeJob func(uid uint32, label string) (SessionJob, bool)
	// JobDetailsFor: a job's details are asked again after this long.
	JobDetailsFor time.Duration
	// AppleAgentDirs are where macOS keeps its own agents: their labels are left out of the session's jobs.
	AppleAgentDirs []string
	// Crontab is the user's crontab: "" when there is none; ok false when it cannot be read.
	Crontab   func() (string, bool)
	Signature func(path string) Signature
	// FindApp is the app with a bundle id (a login item names the app that registered it); "" none.
	FindApp    func(id string) string
	CanReplace func(path string) bool
	UID        uint32
	NewFor     time.Duration
	RCFiles    []string
	// SystemPathFiles are /etc/paths and /etc/paths.d/*.
	SystemPathFiles func() []string
}

// PersistenceScope is where a thing that starts by itself is defined.
type PersistenceScope string

const (
	ScopeUserAgent   PersistenceScope = "user-agent"
	ScopeSystemAgent PersistenceScope = "system-agent"
	ScopeDaemon      PersistenceScope = "daemon"
	ScopeLoginItem   PersistenceScope = "login-item"
	ScopeCron        PersistenceScope = "cron"
)

func (s PersistenceScope) label() string {
	switch s {
	case ScopeUserAgent:
		return "你的后台任务"
	case ScopeSystemAgent:
		return "所有用户的后台任务"
	case ScopeDaemon:
		return "系统后台任务（以管理员身份运行）"
	case ScopeLoginItem:
		return "登录项（应用登记的后台程序）"
	}
	return "定时任务"
}

// scriptWhy: a job that runs a script (which is never signed).
const scriptWhy = "它运行的是一个脚本"

// newLabel: how a new one is named on a card ("新加了一个开机自动运行的任务：…").
func (s PersistenceScope) newLabel() string {
	switch s {
	case ScopeUserAgent:
		return "一个开机自动运行的任务"
	case ScopeSystemAgent:
		return "一个给所有用户自动运行的任务"
	case ScopeDaemon:
		return "一个以管理员身份自动运行的任务"
	case ScopeLoginItem:
		return "一个登录项"
	}
	return "一个定时任务"
}

// oddPlace: where a program is kept that installed programs rarely are (Downloads, a temp folder, a cache folder),
// named for a card; "" anywhere else.
func oddPlace(ctx *Context, program string) string {
	p := strings.ToLower(Standardized(program))
	under := func(dir string) bool {
		return dir != "" && (p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/"))
	}
	for _, h := range ctx.spellings() {
		switch {
		case under(h + "/downloads"):
			return "下载文件夹"
		case under(h + "/library/caches"), under(h + "/.cache"):
			return "缓存文件夹"
		case under(h):
			return "" // the home itself may sit in a temp folder (a test's fake home)
		}
	}
	tmp := ""
	if ctx.Tmp != "" {
		tmp = strings.ToLower(Standardized(ctx.Tmp))
	}
	if under(tmp) || under("/tmp") || under("/private/tmp") || under("/var/folders") || under("/private/var/folders") {
		return "临时文件夹"
	}
	return ""
}

// ScopedDir is a folder of launchd jobs and their scope.
type ScopedDir struct {
	Dir   string
	Scope PersistenceScope
}

// SessionJob is a job in the user's launchd session, as `launchctl print gui/<uid>/<label>` describes it.
type SessionJob struct {
	Label string `json:"label"`
	// Path is where it was loaded from (a plist, or the app that registered it).
	Path    string `json:"path,omitempty"`
	Program string `json:"program,omitempty"`
	// ParentBundle is the app that registered it through ServiceManagement, by bundle id.
	ParentBundle string `json:"parentBundle,omitempty"`
}

// LoginItemsGrant is System Settings → General → Login Items & Extensions (scan_open_settings takes this name).
const LoginItemsGrant = "登录项"

// LoginItemsURL opens that page.
const LoginItemsURL = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"

func init() { Register("persistence.review", NewPersistenceRule) }

// NewPersistenceRule is the rule for this Mac (l nil) or a fake home: there the fake home's LaunchAgents and the fake
// /Library's; the session's jobs from the fakes' `launchctl print gui/<uid>` and `launchctl print gui/<uid>/<label>`;
// apps looked for in the fake home only. Nothing of the real Mac (Launch Services, /System's agents, /etc/paths).
func NewPersistenceRule(l *Layout, f *Fakes) Rule {
	r := &PersistenceRule{
		PlistDirs: func(home string) []ScopedDir {
			return []ScopedDir{{filepath.Join(home, "Library/LaunchAgents"), ScopeUserAgent},
				{"/Library/LaunchAgents", ScopeSystemAgent}, {"/Library/LaunchDaemons", ScopeDaemon}}
		},
		SessionLabels: func(uid uint32) (map[string]string, bool) {
			res := Run("/bin/launchctl", []string{"print", "gui/" + strconv.FormatUint(uint64(uid), 10)}, RunOpts{Timeout: 20 * time.Second})
			if res.Status != 0 {
				return nil, false
			}
			return serviceMap(res.Stdout), true
		},
		DescribeJob: func(uid uint32, label string) (SessionJob, bool) {
			res := Run("/bin/launchctl", []string{"print", "gui/" + strconv.FormatUint(uint64(uid), 10) + "/" + label}, RunOpts{Timeout: 10 * time.Second})
			if res.Status != 0 {
				return SessionJob{}, false
			}
			return ParseSessionJob(label, res.Stdout), true
		},
		JobDetailsFor:  24 * time.Hour,
		AppleAgentDirs: []string{"/System/Library/LaunchAgents", "/Library/Apple/System/Library/LaunchAgents"},
		Crontab:        ReadCrontab,
		Signature:      SignatureOf,
		FindApp: func(id string) string {
			if a := AppsWithBundleID(id); len(a) > 0 {
				return a[0]
			}
			return ""
		},
		CanReplace: UserCanReplace,
		UID:        uint32(os.Getuid()),
		NewFor:     7 * 24 * time.Hour,
		RCFiles:    []string{".zshenv", ".zprofile", ".zshrc", ".zlogin", ".bash_profile", ".bashrc", ".profile"},
		SystemPathFiles: func() []string {
			return append([]string{"/etc/paths"}, Children("/etc/paths.d")...)
		},
	}
	if l != nil {
		lib := filepath.Join(l.Root, "SystemLibrary")
		r.PlistDirs = func(home string) []ScopedDir {
			return []ScopedDir{{filepath.Join(home, "Library/LaunchAgents"), ScopeUserAgent},
				{filepath.Join(lib, "LaunchAgents"), ScopeSystemAgent}, {filepath.Join(lib, "LaunchDaemons"), ScopeDaemon}}
		}
		r.SessionLabels = func(uid uint32) (map[string]string, bool) {
			status, text := f.Answer("/bin/launchctl", []string{"print", "gui/" + strconv.FormatUint(uint64(uid), 10)})
			if status != 0 {
				return nil, false
			}
			return serviceMap(text), true
		}
		r.DescribeJob = func(uid uint32, label string) (SessionJob, bool) {
			status, text := f.Answer("/bin/launchctl", []string{"print", "gui/" + strconv.FormatUint(uint64(uid), 10) + "/" + label})
			if status != 0 {
				return SessionJob{}, false
			}
			return ParseSessionJob(label, text), true
		}
		appDirs := []string{filepath.Join(l.Home(), "Applications")}
		r.FindApp = func(id string) string { return FindAppIn(id, appDirs) }
		r.AppleAgentDirs = nil
		r.Crontab = fakeCrontab(f)
		r.SystemPathFiles = func() []string { return nil }
		r.Signature = f.Signature
	}
	return r
}

func (r *PersistenceRule) ID() string { return "persistence.review" }
func (r *PersistenceRule) Emits() []string {
	return []string{"persistence.daemon-writable", "persistence.daemon-missing", "persistence.new", "persistence.bad-signature",
		"persistence.unvouched", "persistence.login-items", "persistence.cron", "persistence.cron-missing",
		"persistence.path-risky", "persistence.path-missing", "persistence.partial"}
}

// ReadCrontab is the user's crontab: "" when there is none; ok false when it cannot be read.
func ReadCrontab() (string, bool) {
	res := Run("/bin/sh", []string{"-c", "/usr/bin/crontab -l 2>&1"}, RunOpts{Timeout: 10 * time.Second})
	if res.Status == 0 {
		return res.Stdout, true
	}
	if strings.Contains(res.Stdout, "no crontab") {
		return "", true
	}
	return "", false
}

func fakeCrontab(f *Fakes) func() (string, bool) {
	return func() (string, bool) {
		if f.Crontab == nil {
			return "", false
		}
		return *f.Crontab, true
	}
}

// persistenceInterpreters run the script they are given: the job's program is that script.
var persistenceInterpreters = map[string]bool{"/bin/sh": true, "/bin/bash": true, "/bin/zsh": true, "/bin/ksh": true, "/bin/dash": true,
	"/usr/bin/env": true, "/usr/bin/python3": true, "/usr/bin/perl": true, "/usr/bin/ruby": true, "/usr/bin/osascript": true, "/usr/bin/arch": true}

// jobProgram is the program a launchd job runs; for an interpreter, the script it is given (the first absolute path).
// ok false when there is none.
func jobProgram(plist map[string]any) (string, bool) {
	argv := appsPlistStrings(plist["ProgramArguments"])
	if p, ok := plist["Program"].(string); ok {
		rest := []string{}
		if len(argv) > 1 {
			rest = argv[1:]
		}
		argv = append([]string{p}, rest...)
	}
	if len(argv) == 0 {
		return "", false
	}
	first := argv[0]
	if persistenceInterpreters[first] {
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "/") {
				return a, true
			}
		}
	}
	return first, true
}

// isSystemProgram: part of macOS, on the sealed system volume; nothing to check.
func isSystemProgram(path string) bool {
	for _, p := range []string{"/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// UserCanReplace: this user could put something else in its place, the file (the .app, for a program inside one) or
// the folder holding it being writable.
func UserCanReplace(path string) bool {
	target := SignatureSubject(path)
	return syscall.Access(target, 2) == nil || syscall.Access(filepath.Dir(target), 2) == nil // W_OK
}

type sessionService struct{ label, pid string }

// serviceList is the jobs in `launchctl print gui/<uid>`'s `services = { pid status label … }` block.
func serviceList(text string) []sessionService {
	var out []sessionService
	inside := false
	for _, raw := range appsSplit(text, "\n") {
		line := strings.Trim(raw, " \t")
		if !inside {
			inside = line == "services = {"
			continue
		}
		if line == "}" {
			break
		}
		parts := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		if len(parts) >= 3 {
			out = append(out, sessionService{parts[len(parts)-1], parts[0]})
		}
	}
	return out
}

func serviceMap(text string) map[string]string {
	m := map[string]string{}
	for _, s := range serviceList(text) {
		if _, ok := m[s.label]; !ok {
			m[s.label] = s.pid
		}
	}
	return m
}

// ParseSessionJob reads the job's own top-level fields (one tab in), not those of the blocks inside it.
func ParseSessionJob(label, text string) SessionJob {
	job := SessionJob{Label: label}
	for _, raw := range appsSplit(text, "\n") {
		if !strings.HasPrefix(raw, "\t") || strings.HasPrefix(raw, "\t\t") {
			continue
		}
		eq := strings.Index(raw, " = ")
		if eq < 0 {
			continue
		}
		key, value := raw[1:eq], raw[eq+3:]
		switch {
		case key == "path" && job.Path == "":
			job.Path = value
		case key == "program" && job.Program == "":
			job.Program = value
		case key == "parent bundle identifier" && job.ParentBundle == "":
			job.ParentBundle = value
		}
	}
	return job
}

// jobLabels are the labels of the plists in dirs.
func jobLabels(dirs []string) map[string]bool {
	out := map[string]bool{}
	for _, d := range dirs {
		for _, f := range Children(d) {
			if PathExtension(f) != "plist" {
				continue
			}
			plist, ok := readJobPlist(f)
			if !ok {
				continue
			}
			if l, ok := plist["Label"].(string); ok {
				out[l] = true
			} else {
				out[NameWithoutExtension(f)] = true
			}
		}
	}
	return out
}

type describedJob struct {
	At  time.Time  `json:"at"`
	PID string     `json:"pid"`
	Job SessionJob `json:"job"`
}

// sessionJobs are the jobs of the session not in skip, described, reusing descriptions kept in the store
// (persistence.jobs) for up to JobDetailsFor; ok false when launchctl does not answer.
func (r *PersistenceRule) sessionJobs(skip map[string]bool, store *Store, now time.Time) ([]SessionJob, bool) {
	labels, ok := r.SessionLabels(r.UID)
	if !ok {
		return nil, false
	}
	known := map[string]describedJob{}
	if store != nil {
		if v, ok := store.Get("persistence.jobs"); ok {
			json.Unmarshal([]byte(v), &known)
		}
	}
	var names []string
	for l := range labels {
		if !skip[l] && !strings.HasPrefix(l, "application.") {
			names = append(names, l)
		}
	}
	sort.Strings(names)
	if len(names) > 200 {
		names = names[:200]
	}
	kept := map[string]describedJob{}
	out := []SessionJob{}
	for _, label := range names {
		pid := labels[label]
		if k, ok := known[label]; ok && k.PID == pid && !k.At.After(now) && now.Sub(k.At) < r.JobDetailsFor {
			kept[label] = k
		} else if job, ok := r.DescribeJob(r.UID, label); ok {
			kept[label] = describedJob{At: now, PID: pid, Job: job}
		} else {
			continue
		}
		out = append(out, kept[label].Job)
	}
	if store != nil {
		if data, err := json.Marshal(kept); err == nil {
			store.Set("persistence.jobs", string(data))
		}
	}
	return out, true
}

// persistenceItem is one thing that starts by itself.
type persistenceItem struct {
	scope PersistenceScope
	name  string
	// source is where it is defined: the plist, the login item's label, or the crontab line's hash.
	source  string
	program string
	hasProg bool
}

func (it persistenceItem) key() string { return string(it.scope) + ":" + it.source + "|" + it.program }

// sessionItems are what the session lists beyond the plists: one item per job. A job an app registered names that
// app's bundle, which carries the signature.
func sessionItems(jobs []SessionJob, appPath func(string) string) []persistenceItem {
	var out []persistenceItem
	for _, j := range jobs {
		// macOS's own, wherever its plist lives.
		if strings.HasPrefix(j.Path, "/System/") || strings.HasPrefix(j.Path, "/Library/Apple/") {
			continue
		}
		program := j.Program
		app := ""
		if j.ParentBundle != "" {
			app = appPath(j.ParentBundle)
		}
		if program == "" {
			program = app
		}
		if program != "" && isSystemProgram(program) && j.ParentBundle == "" && j.Path == "" {
			continue
		}
		name := j.Label
		if app != "" {
			name = NameWithoutExtension(app)
		}
		out = append(out, persistenceItem{scope: ScopeLoginItem, name: name, source: j.Label, program: program, hasProg: program != ""})
	}
	return out
}

type cronEntry struct {
	schedule, program, line string
}

var cronVariable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

// cronEntries are the crontab's lines: the schedule, the program ("" when it is not an absolute path), the line.
func cronEntries(text string) []cronEntry {
	var out []cronEntry
	for _, raw := range appsSplit(text, "\n") {
		line := strings.Trim(raw, " \t")
		if line == "" || strings.HasPrefix(line, "#") || cronVariable.MatchString(line) { // MAILTO=, PATH=
			continue
		}
		parts := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		n := 5
		if strings.HasPrefix(line, "@") {
			n = 1
		}
		if len(parts) <= n {
			continue
		}
		e := cronEntry{schedule: strings.Join(parts[:n], " "), line: line}
		if strings.HasPrefix(parts[n], "/") {
			e.program = parts[n]
		}
		out = append(out, e)
	}
	return out
}

type pathEntry struct {
	line int
	dir  string
}

var (
	pathAssign = regexp.MustCompile(`(^|[\s;])(export\s+)?PATH\s*=\s*`)
	zshPath    = regexp.MustCompile(`(^|[\s;])path\s*\+?=\s*\(`)
)

// pathEntries are the folders a shell startup file puts on PATH: `PATH=a:b:$PATH`, `export PATH=…`, zsh's
// `path=(a b $path)` / `path+=(…)`. Only literal folders (with ~ and $HOME expanded); anything with another variable
// is left out. `.` and an empty entry mean whatever folder the shell is in: they come back as ".".
func pathEntries(text, home string) []pathEntry {
	var out []pathEntry
	expand := func(s string) (string, bool) {
		v := strings.Trim(s, "\"' ")
		v = strings.ReplaceAll(v, "${HOME}", home)
		v = strings.ReplaceAll(v, "$HOME", home)
		if strings.HasPrefix(v, "~/") {
			v = home + v[1:]
		} else if v == "~" {
			v = home
		}
		return v, strings.HasPrefix(v, "/") && !strings.Contains(v, "$")
	}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.Trim(raw, " \t")
		if strings.HasPrefix(line, "#") || utf8.RuneCountInString(line) > 2000 {
			continue
		}
		if loc := pathAssign.FindStringIndex(line); loc != nil {
			value := line[loc[1]:]
			if value != "" && (value[0] == '"' || value[0] == '\'') && strings.IndexByte(value[1:], value[0]) >= 0 {
				value = value[1 : 1+strings.IndexByte(value[1:], value[0])]
			} else {
				words := appsSplit(value, " ")
				value = ""
				if len(words) > 0 {
					value = words[0]
				}
			}
			for _, part := range strings.Split(value, ":") {
				t := strings.Trim(part, "\"' ")
				if t == "" || t == "." {
					out = append(out, pathEntry{i + 1, "."})
				} else if d, ok := expand(part); ok {
					out = append(out, pathEntry{i + 1, d})
				}
			}
		} else if loc := zshPath.FindStringIndex(line); loc != nil {
			rest := line[loc[1]:]
			if end := strings.IndexByte(rest, ')'); end >= 0 {
				for _, part := range appsSplit(rest[:end], " ") {
					if d, ok := expand(part); ok {
						out = append(out, pathEntry{i + 1, d})
					}
				}
			}
		}
	}
	return out
}

type keptSignature struct {
	Identity  string    `json:"identity"`
	Signature Signature `json:"signature"`
	At        time.Time `json:"at"`
}

func (r *PersistenceRule) Run(ctx *Context) (found []Finding, err error) {
	var out []Finding
	var items []persistenceItem
	var unvouched []string
	flagged := map[string]bool{} // reported on their own, not again in the summary
	// Signatures are read once per program and kept while it is the same file, for a week at most.
	readBefore := map[string]keptSignature{}
	if ctx.Store != nil {
		if v, ok := ctx.Store.Get("persistence.signatures"); ok {
			json.Unmarshal([]byte(v), &readBefore)
		}
	}
	read := map[string]keptSignature{}
	defer func() {
		if ctx.Store != nil {
			if data, e := json.Marshal(read); e == nil {
				ctx.Store.Set("persistence.signatures", string(data))
			}
		}
	}()
	signature := func(path string) Signature {
		// Reading a program in a guarded folder without Full Disk Access brings up macOS's dialog: not read, not judged.
		if !ctx.MayLook(path) {
			return Signature{Kind: SigUnknown}
		}
		subject := SignatureSubject(path)
		id := SignatureIdentity(path)
		k, ok := read[subject]
		if !ok {
			k, ok = readBefore[subject]
		}
		if ok && k.Identity == id && id != "" && !k.At.After(ctx.Now) && ctx.Now.Sub(k.At) < 7*24*time.Hour {
			read[subject] = k
			return k.Signature
		}
		sig := r.Signature(path)
		if id != "" {
			read[subject] = keptSignature{Identity: id, Signature: sig, At: ctx.Now}
		}
		return sig
	}
	shown := func(p string) string { return ctx.Shown(p) }

	// 1. launchd jobs: everything but the user's own missing targets (LaunchAgentRule reports those).
	for _, sd := range r.PlistDirs(ctx.Home) {
		scope := sd.Scope
		for _, f := range Children(sd.Dir) {
			if PathExtension(f) != "plist" {
				continue
			}
			plist, ok := readJobPlist(f)
			if !ok {
				continue
			}
			program, ok := jobProgram(plist)
			if !ok {
				continue
			}
			label, ok := plist["Label"].(string)
			if !ok {
				label = NameWithoutExtension(f)
			}
			if d, ok := plist["Disabled"].(bool); ok && d {
				continue
			}
			item := persistenceItem{scope: scope, name: label, source: f, program: program, hasProg: true}
			items = append(items, item)
			// A bare name (`node`) is looked up on launchd's PATH: nothing to check here.
			if !strings.HasPrefix(program, "/") || isSystemProgram(program) {
				continue
			}
			sig := signature(program)
			if sig.Kind == SigMissing {
				if scope != ScopeUserAgent {
					as := "每个用户"
					if scope == ScopeDaemon {
						as = "管理员"
					}
					out = append(out, Finding{Rule: "persistence.daemon-missing", Category: CatPersistence, Severity: Medium, Verdict: Confirm,
						Path: f, Title: scope.label() + " " + label + " 指向已经不存在的程序",
						Evidence: map[string]string{"label": label, "missing": program, "scope": string(scope), "admin": "1",
							"hint": "它每次启动都会失败；以后有人在这个位置放了东西，就会以" + as + "的身份运行"}})
					flagged[item.key()] = true
				}
				continue
			}
			// A program in the user's Desktop, Documents or Downloads is theirs to replace, looked at or not.
			if scope != ScopeUserAgent && (sig.Kind == SigUnknown || r.CanReplace(program)) {
				why := "它对这台 Mac 上的每个用户都会运行：任何以你身份运行的程序都能换掉它"
				if scope == ScopeDaemon {
					why = "它以管理员（root）身份运行：任何以你身份运行的程序都能换掉它，下次启动就拿到管理员权限"
				}
				out = append(out, Finding{Rule: "persistence.daemon-writable", Category: CatPersistence, Severity: High, Verdict: Confirm,
					Path: f, Title: scope.label() + " " + label + " 运行的程序你自己就能改",
					Evidence: map[string]string{"label": label, "program": shown(program), "signature": sig.Label(), "scope": string(scope),
						"admin": "1", "why": why,
						"how": "Homebrew 的服务别用 sudo 起（`brew services start` 不加 sudo，就以你自己的身份运行）；用不到了就删掉这个系统级的后台任务"}})
				flagged[item.key()] = true
			} else if sig.Kind == SigInvalid {
				out = append(out, Finding{Rule: "persistence.bad-signature", Category: CatPersistence, Severity: Medium, Verdict: Confirm,
					Path: f, Title: scope.label() + " " + label + " 的程序签名和文件对不上",
					Evidence: map[string]string{"label": label, "program": shown(program), "scope": string(scope),
						"why": "签名以后文件被改过：可能是更新到一半，也可能被换过"}})
				flagged[item.key()] = true
			} else if sig.Unvouched() || sig.Kind == SigUnknown {
				unvouched = append(unvouched, label+"："+sig.Label())
			}
		}
	}
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}

	// 2. What apps registered (System Settings → General → Login Items & Extensions), and jobs loaded from elsewhere.
	skip := jobLabels(r.AppleAgentDirs)
	for _, it := range items {
		skip[it.name] = true
	}
	unread := map[PersistenceScope]bool{}
	jobs, ok := r.sessionJobs(skip, ctx.Store, ctx.Now)
	if !ok {
		unread[ScopeLoginItem] = true
	} else {
		logins := sessionItems(jobs, r.FindApp)
		items = append(items, logins...)
		var names []string
		for _, l := range logins {
			sig := Signature{Kind: SigMissing}
			if l.hasProg && strings.HasPrefix(l.program, "/") {
				sig = signature(l.program)
			}
			what := sig.Label()
			if !l.hasProg {
				what = "不知道是哪个程序"
			}
			names = append(names, l.name+"（"+what+"）")
			if sig.Unvouched() || sig.Kind == SigUnknown {
				unvouched = append(unvouched, l.name+"："+ScopeLoginItem.label()+"，"+sig.Label())
			}
		}
		if len(logins) > 0 {
			if len(names) > 30 {
				names = names[:30]
			}
			out = append(out, Finding{Rule: "persistence.login-items", Category: CatPersistence, Severity: Low, Verdict: Info,
				Title:    "有 " + strconv.Itoa(len(logins)) + " 个应用登记的后台程序（登录项）",
				Evidence: map[string]string{"items": strings.Join(names, "；"), "how": "不需要的在 系统设置 → 通用 → 登录项与扩展 里关掉"}})
		}
	}

	// 3. crontab.
	if text, ok := r.Crontab(); !ok {
		unread[ScopeCron] = true
	} else {
		entries := cronEntries(text)
		var listed []string
		for _, e := range entries {
			name := "命令"
			if e.program != "" {
				name = filepath.Base(e.program)
			}
			item := persistenceItem{scope: ScopeCron, name: name, source: ShortHash(e.line), program: e.program, hasProg: e.program != ""}
			items = append(items, item)
			if len(listed) < 20 {
				listed = append(listed, e.schedule+" "+name)
			}
			if e.program != "" && !isSystemProgram(e.program) && signature(e.program).Kind == SigMissing {
				out = append(out, Finding{Rule: "persistence.cron-missing", Category: CatPersistence, Severity: Medium, Verdict: Confirm,
					Title:    "定时任务（" + e.schedule + "）要运行的 " + filepath.Base(e.program) + " 已经不在了",
					Evidence: map[string]string{"schedule": e.schedule, "missing": shown(e.program), "how": "在终端里运行 crontab -e，删掉这一行"}})
				flagged[item.key()] = true
			}
		}
		if len(entries) > 0 {
			out = append(out, Finding{Rule: "persistence.cron", Category: CatPersistence, Severity: Low, Verdict: Info,
				Title:    "有 " + strconv.Itoa(len(entries)) + " 个定时任务（crontab）",
				Evidence: map[string]string{"entries": strings.Join(listed, "；"), "how": "在终端里运行 crontab -l 查看，crontab -e 修改"}})
		}
	}
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}

	// 4. What appeared since the last round, without anyone vouching for it.
	if ctx.Store != nil {
		seen := NewTable[time.Time](ctx.Store, "seen-persistence", 1)
		before := seen.Load()
		// When the first round ran (what it saw is the baseline, never "new").
		recorded, hasRecorded := ctx.Store.Get("persistence.baseline")
		var baselineAt time.Time // zero: distant past
		if hasRecorded {
			if secs, err := strconv.ParseFloat(recorded, 64); err == nil {
				baselineAt = time.Unix(0, int64(secs*1e9))
			}
		} else {
			for _, t := range before {
				if baselineAt.IsZero() || t.Before(baselineAt) {
					baselineAt = t
				}
			}
		}
		baseline := len(before) == 0 && !hasRecorded
		now := map[string]time.Time{}
		for k, first := range before {
			for s := range unread {
				if strings.HasPrefix(k, string(s)+":") {
					now[k] = first
				}
			}
		}
		for _, it := range items {
			first, had := before[it.key()]
			if !had {
				first = ctx.Now
			}
			now[it.key()] = first
			// Appeared this round, or in a round after the baseline less than NewFor ago. The baseline is kept as float
			// seconds, which loses the last digits of its nanoseconds: read back, it can come out a few hundred
			// nanoseconds before the baseline round's own time, which would make all that round saw "new".
			isNew := !baseline && (!had || (first.Sub(baselineAt) > time.Millisecond && ctx.Now.Sub(first) < r.NewFor))
			if !isNew || flagged[it.key()] {
				continue
			}
			// Why it is worth a look, in plain words. Serious: what malware does and a program the user set up rarely
			// does (a signature that does not match, a program kept in Downloads, a temp or cache folder, a job run as
			// root or for every user from a program the user can change). Only those are urgent; the rest (no
			// developer's signature, a script, a new crontab line) go on the round's card, to look at when convenient.
			var why []string
			serious := false
			if it.scope == ScopeCron {
				why = append(why, "是 crontab 里新加的一行")
			}
			if it.hasProg && strings.HasPrefix(it.program, "/") && !isSystemProgram(it.program) {
				sig := signature(it.program)
				switch {
				case sig.Kind == SigInvalid:
					why = append(why, "程序的签名和文件对不上，签名以后被改过")
					serious = true
				case sig.Kind == SigScript:
					why = append(why, scriptWhy)
				case sig.Unvouched():
					why = append(why, "程序没有开发者签名")
				case sig.Kind == SigUnknown:
					why = append(why, "程序在桌面、文稿或下载里，没有完全磁盘访问，签名没看")
				}
				if sig.Kind != SigUnknown && (it.scope == ScopeSystemAgent || it.scope == ScopeDaemon) && r.CanReplace(it.program) {
					why = append(why, "它以管理员或所有用户的身份运行，程序却放在你自己就能改的地方")
					serious = true
				}
				if place := oddPlace(ctx, it.program); place != "" {
					why = append(why, "程序放在"+place+"里，装好的程序很少放在那儿")
					serious = true
				}
			} else if it.scope == ScopeLoginItem && it.hasProg {
				// A shell or the like run from a plist outside the usual folders: what malware loads by hand.
				why = append(why, "它用系统自带的 "+filepath.Base(it.program)+" 运行，配置在 "+it.source)
			} else if it.scope == ScopeLoginItem {
				why = append(why, "看不出是哪个程序登记的")
			}
			if len(why) == 0 {
				continue
			}
			for i, w := range why {
				if w == scriptWhy && !serious {
					why[i] = scriptWhy + "（脚本本来就没有签名，这很常见）" // reassuring only when nothing else is odd
				}
			}
			// Only the user's own LaunchAgent goes in a plan (stopped, plist to the Trash); the rest the user does.
			how := map[PersistenceScope]string{ScopeUserAgent: "是你装的就不用管；不认识的话可以停掉它，配置会移到废纸篓，随时能放回",
				ScopeLoginItem:   "是你装的就不用管；不认识的话，在 系统设置 → 通用 → 登录项与扩展 里关掉",
				ScopeCron:        "是你加的就不用管；不认识的话，在终端里运行 crontab -e 删掉这一行",
				ScopeSystemAgent: "是你装的就不用管；不认识的话，在访达里找到它移到废纸篓（会要你的密码）",
				ScopeDaemon:      "是你装的就不用管；不认识的话，在访达里找到它移到废纸篓（会要你的密码）"}[it.scope]
			reason := strings.Join(why, "，")
			severity := Medium
			if serious {
				severity = High
			}
			ev := map[string]string{"scope": string(it.scope), "name": it.name, "why": reason, "how": how}
			if it.scope == ScopeUserAgent || it.scope == ScopeSystemAgent || it.scope == ScopeDaemon {
				ev["label"] = it.name
			}
			if it.hasProg {
				ev["program"] = shown(it.program)
			}
			if it.scope != ScopeUserAgent && it.scope != ScopeLoginItem && it.scope != ScopeCron {
				ev["admin"] = "1"
			}
			// A program that was not looked at (a guarded folder, no Full Disk Access) is not the finding's path: that
			// would be resolved to make its id, which looks. Known by the item instead.
			notLooked := it.hasProg && !ctx.MayLook(it.program)
			path, key := it.source, ""
			if it.scope == ScopeCron || it.scope == ScopeLoginItem {
				path = it.program
			}
			if notLooked {
				path, key = "", it.key()
			}
			out = append(out, Finding{Rule: "persistence.new", Category: CatPersistence, Severity: severity, Verdict: Confirm, Path: path,
				Title: "新加了" + it.scope.newLabel() + "：" + it.name, Evidence: ev, Key: key})
			flagged[it.key()] = true
		}
		// One batch that starts over (Replace fails while there is no log yet: store.go removes it unconditionally).
		if err := seen.Apply(now, nil, true); err != nil {
			return nil, err
		}
		if baseline {
			if err := ctx.Store.Set("persistence.baseline", strconv.FormatFloat(float64(ctx.Now.UnixNano())/1e9, 'f', -1, 64)); err != nil {
				return nil, err
			}
		}
	}

	// What could not be read this round is kept as it was (above), and said, so "nothing found" is not read into it.
	var notRead []string
	if unread[ScopeLoginItem] {
		notRead = append(notRead, "登录项（launchctl 没答复）")
	}
	if unread[ScopeCron] {
		notRead = append(notRead, "定时任务（读不出 crontab）")
	}
	if len(notRead) > 0 {
		s := strings.Join(notRead, "、")
		out = append(out, Finding{Rule: "persistence.partial", Category: CatPersistence, Severity: Low, Verdict: Info,
			Title:    "这一轮有几类会自己启动的没查成：" + s,
			Evidence: map[string]string{"skipped": s, "hint": "上次查到的照旧记着，下一轮再查"}})
	}

	if len(unvouched) > 0 {
		n := len(unvouched)
		if len(unvouched) > 20 {
			unvouched = unvouched[:20]
		}
		out = append(out, Finding{Rule: "persistence.unvouched", Category: CatPersistence, Severity: Low, Verdict: Info,
			Title: strconv.Itoa(n) + " 个会自己启动的程序没有开发者签名",
			Evidence: map[string]string{"items": strings.Join(unvouched, "；"),
				"hint": "Homebrew 和自己编的程序通常就是这样，不一定有问题；不认识的值得看一眼"}})
	}

	// 5. PATH: a folder anyone can write to, or a download / temp folder, ahead of the system's lets someone else's
	// program run in place of a command you type.
	var risky, missing []string
	var files []string
	for _, f := range r.RCFiles {
		files = append(files, filepath.Join(ctx.Home, f))
	}
	files = append(files, r.SystemPathFiles()...)
	tempRoots := []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/var/folders/", "/private/var/folders/"}
	if ctx.Tmp != "" {
		tempRoots = append(tempRoots, Canonical(ctx.Tmp)+"/")
	}
	downloads := Canonical(filepath.Join(ctx.Home, "Downloads")) + "/"
	downloadsAsSpelled := filepath.Join(ctx.Home, "Downloads")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil || !utf8.Valid(data) {
			continue
		}
		text := string(data)
		var entries []pathEntry
		if strings.HasPrefix(f, "/etc/") {
			for i, l := range appsSplit(text, "\n") {
				if d := strings.Trim(l, " \t"); strings.HasPrefix(d, "/") {
					entries = append(entries, pathEntry{i + 1, d})
				}
			}
		} else {
			entries = pathEntries(text, ctx.Home)
		}
		for _, e := range entries {
			where := HomeRelative(f, ctx.Home) + " 第 " + strconv.Itoa(e.line) + " 行"
			if e.dir == "." {
				risky = append(risky, "当前所在的文件夹（. 或空的一项，"+where+"）")
				continue
			}
			// In a guarded folder: risky by where it is, without looking (a download folder on the PATH is the risk).
			if !ctx.MayLook(e.dir) {
				if strings.HasPrefix(e.dir, downloadsAsSpelled) {
					risky = append(risky, ctx.Shown(e.dir)+"（"+where+"）")
				}
				continue
			}
			var st syscall.Stat_t
			if syscall.Stat(e.dir, &st) != nil {
				missing = append(missing, HomeRelative(e.dir, ctx.Home)+"（"+where+"）")
				continue
			}
			canon := Canonical(e.dir) + "/"
			temp := false
			for _, t := range tempRoots {
				temp = temp || strings.HasPrefix(canon, t)
			}
			if st.Mode&0o002 != 0 || temp || strings.HasPrefix(canon, downloads) {
				risky = append(risky, HomeRelative(e.dir, ctx.Home)+"（"+where+"）")
			}
		}
	}
	if len(risky) > 0 {
		n := len(risky)
		if n > 10 {
			risky = risky[:10]
		}
		out = append(out, Finding{Rule: "persistence.path-risky", Category: CatPersistence, Severity: Medium, Verdict: Confirm,
			Title: "PATH 里有 " + strconv.Itoa(n) + " 个谁都能放东西进去的文件夹",
			Evidence: map[string]string{"dirs": strings.Join(risky, "；"),
				"why": "临时文件夹、下载文件夹或谁都能写的文件夹放在 PATH 里，别人放一个同名程序进去，你敲的命令就会运行它",
				"how": "从这几行里去掉这些文件夹"}})
	}
	if len(missing) > 0 {
		n := len(missing)
		if n > 10 {
			missing = missing[:10]
		}
		out = append(out, Finding{Rule: "persistence.path-missing", Category: CatPersistence, Severity: Low, Verdict: Info,
			Title: "PATH 里有 " + strconv.Itoa(n) + " 个已经不存在的文件夹",
			Evidence: map[string]string{"dirs": strings.Join(missing, "；"),
				"hint": "以后有人建了这个文件夹，里面的程序就会被当成命令；用不到就从配置里去掉"}})
	}
	return out, nil
}
