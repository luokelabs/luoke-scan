package core

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// StartupHooksRule: less common ways to have code run, beside launchd jobs and login items (PersistenceRule): a
// library pushed into other programs (DYLD_INSERT_LIBRARIES in a launchd job, an app's LSEnvironment or a shell
// startup file), authorization plugins (run inside the login window, with the password typed there), login and logout
// hooks, a command Terminal runs for every new window, iTerm2's scripts that start with it, and local periodic scripts.
// Only read from their files; nothing is run. Swift: Rules/StartupHooksRule.swift.
type StartupHooksRule struct {
	Signature func(path string) Signature
	// Etc (periodic's local settings) and UsrLocal (local periodic scripts).
	Etc, UsrLocal string
	RCFiles       []string
	// PeriodicTool runs the periodic scripts: gone from recent macOS, and then nothing there runs.
	PeriodicTool string
}

func init() { Register("startup", NewStartupHooksRule) }

// NewStartupHooksRule is the rule for this Mac (l nil) or a fake home: nothing of the real Mac's /etc, /usr/local,
// /usr/sbin; what codesign says of the paths in the fakes' codesign map is from there.
func NewStartupHooksRule(l *Layout, f *Fakes) Rule {
	r := &StartupHooksRule{Signature: SignatureOf, Etc: "/private/etc", UsrLocal: "/usr/local",
		RCFiles:      []string{".zshenv", ".zprofile", ".zshrc", ".zlogin", ".bash_profile", ".bashrc", ".profile"},
		PeriodicTool: "/usr/sbin/periodic"}
	if l != nil {
		r.Etc, r.UsrLocal = filepath.Join(l.Root, "etc"), filepath.Join(l.Root, "usr-local")
		r.PeriodicTool = filepath.Join(l.Root, "usr-sbin/periodic")
		r.Signature = startupFakeCodesign(f)
	}
	return r
}

// startupFakeCodesign is what codesign says in a fake home: the fakes' codesign map for the paths in it, codesign itself for
// the others.
func startupFakeCodesign(f *Fakes) func(string) Signature {
	return func(p string) Signature {
		if s, ok := f.Codesign[p]; ok {
			return ParseSignature(s)
		}
		return SignatureOf(p)
	}
}

func (r *StartupHooksRule) ID() string { return "startup" }
func (r *StartupHooksRule) Emits() []string {
	return []string{"startup.dyld-insert", "startup.auth-plugin", "startup.login-hook", "startup.terminal-command",
		"startup.iterm-autolaunch", "startup.periodic"}
}

// dyldInjecting makes the dynamic loader take another library first, into every program started with it; the
// redirecting ones replace the libraries it looks for.
const dyldInjecting = "DYLD_INSERT_LIBRARIES"

var dyldVariables = []string{dyldInjecting, "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH"}

// startupHead is the first 64 KB of a small regular file (not following a link, not one kept only in iCloud); ok false
// for anything else.
func startupHead(path string) (string, bool) {
	const limit = 64 << 10
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size > limit || st.Flags&0x40000000 != 0 { // SF_DATALESS
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, limit))
	return strings.ToValidUTF8(string(data), "�"), true
}

func (r *StartupHooksRule) Run(ctx *Context) ([]Finding, error) {
	out := r.dyld(ctx)
	out = append(out, r.authPlugins(ctx)...)
	out = append(out, r.loginHooks(ctx)...)
	out = append(out, r.terminal(ctx)...)
	out = append(out, r.periodic()...)
	return out, nil
}

func dyldFinding(path, what, variable string) Finding {
	inject := variable == dyldInjecting
	sev, effect := Medium, "程序会先去别处找它要的库"
	if inject {
		sev, effect = High, "启动的程序都会先载入另一个库"
	}
	return Finding{Rule: "startup.dyld-insert", Category: CatPersistence, Severity: sev, Verdict: Info, Path: path,
		Title: what + "设了 " + variable + "：" + effect,
		Evidence: map[string]string{"variable": variable, "why": "恶意软件用它把自己的代码塞进别的程序；开发调试时也有人这样设",
			"how": "是你自己调试时加的就删掉这一行（调完不该留着）；不认得的，删掉它所在的设置"},
		Key: path + "#" + variable}
}

var dyldInRC = regexp.MustCompile(`(^|\s|export\s+)DYLD_INSERT_LIBRARIES=`)

// dyld: DYLD_* set where programs start: launchd jobs (theirs and the system's), apps' Info.plist, shell startup files.
func (r *StartupHooksRule) dyld(ctx *Context) []Finding {
	var out []Finding
	jobDirs := []string{filepath.Join(ctx.Home, "Library/LaunchAgents")}
	if l := ctx.SystemLibrary; l != "" {
		jobDirs = append(jobDirs, filepath.Join(l, "LaunchAgents"), filepath.Join(l, "LaunchDaemons"))
	}
	for _, d := range jobDirs {
		for _, u := range Children(d) {
			if PathExtension(u) != "plist" {
				continue
			}
			p, _ := readJobPlist(u)
			env, _ := p["EnvironmentVariables"].(map[string]any)
			for _, v := range dyldVariables {
				if _, ok := env[v]; ok {
					out = append(out, dyldFinding(u, "后台任务 "+NameWithoutExtension(u)+" ", v))
				}
			}
		}
	}
	for _, dir := range ctx.AppDirs {
		for _, app := range Children(dir) {
			if PathExtension(app) != "app" {
				continue
			}
			p, _ := readJobPlist(filepath.Join(app, "Contents/Info.plist"))
			env, _ := p["LSEnvironment"].(map[string]any)
			for _, v := range dyldVariables {
				if _, ok := env[v]; ok {
					out = append(out, dyldFinding(app, "应用 "+NameWithoutExtension(app)+" 的设置里", v))
				}
			}
		}
	}
	for _, f := range r.RCFiles {
		path := filepath.Join(ctx.Home, f)
		text, ok := startupHead(path)
		if !ok {
			continue
		}
		for _, l := range startupLines(text) {
			line := strings.Trim(l, " \t")
			if strings.HasPrefix(line, "#") {
				continue
			}
			if dyldInRC.MatchString(line) {
				out = append(out, dyldFinding(path, "shell 的启动文件 ~/"+f+" 里", dyldInjecting))
				break
			}
		}
	}
	return out
}

// startupLines splits at every kind of line break (Character.isNewline), leaving out empty lines.
func startupLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case '\n', '\r', '\v', '\f', 0x85, 0x2028, 0x2029:
			return true
		}
		return false
	})
}

// authPlugins: plugins of the login window (/Library/Security/SecurityAgentPlugins). macOS's own live in /System, so
// each here was added by someone; one nobody vouches for is reported as such.
func (r *StartupHooksRule) authPlugins(ctx *Context) []Finding {
	if ctx.SystemLibrary == "" {
		return nil
	}
	var out []Finding
	for _, b := range Children(filepath.Join(ctx.SystemLibrary, "Security/SecurityAgentPlugins")) {
		if PathExtension(b) != "bundle" {
			continue
		}
		sig := r.Signature(b)
		bad := sig.Unvouched() || sig.Kind == SigInvalid
		sev, how := Low, "公司的单点登录、磁盘加密软件会装这个；认得就留着"
		if bad {
			sev, how = High, "不认得的话，这很可能是恶意软件：先别再登录别的账户，请懂行的人看一下"
		}
		out = append(out, Finding{Rule: "startup.auth-plugin", Category: CatPersistence, Severity: sev, Verdict: Info, Path: b,
			Title:    "登录窗口里装了插件 " + NameWithoutExtension(b) + "（" + sig.Label() + "）",
			Evidence: map[string]string{"signature": sig.Label(), "why": "它在你输入登录密码的地方运行，看得到这个密码", "how": how}})
	}
	return out
}

// loginHooks: scripts run as root at every login or logout (the login window's LoginHook, LogoutHook): long
// deprecated. Read from the Mac's preferences; one in a user's own preferences never runs.
func (r *StartupHooksRule) loginHooks(ctx *Context) []Finding {
	if ctx.SystemLibrary == "" {
		return nil
	}
	u := filepath.Join(ctx.SystemLibrary, "Preferences/com.apple.loginwindow.plist")
	p, _ := readJobPlist(u)
	var out []Finding
	for _, k := range []string{"LoginHook", "LogoutHook"} {
		script, ok := p[k].(string)
		if !ok || script == "" {
			continue
		}
		when := "每次退出登录"
		if k == "LoginHook" {
			when = "每次登录"
		}
		out = append(out, Finding{Rule: "startup.login-hook", Category: CatPersistence, Severity: Medium, Verdict: Info, Path: u,
			Title: when + "都会以管理员身份运行 " + filepath.Base(script),
			Evidence: map[string]string{"script": script, "why": "这是早就不推荐的老办法，现在几乎只有很旧的软件和恶意软件还在用",
				"how": "不认得的话，在终端里运行 sudo defaults delete /Library/Preferences/com.apple.loginwindow " + k},
			Key: u + "#" + k})
	}
	return out
}

var envSetting = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// commandProgram is the program a command line starts, by its file name only: past NAME=value settings and env
// (which may carry a key), never its arguments.
func commandProgram(cmd string) string {
	for _, w := range appsSplit(cmd, " ") {
		if w != "env" && !envSetting.MatchString(w) && !strings.HasPrefix(w, "-") {
			return filepath.Base(w)
		}
	}
	return "?"
}

// terminal: what Terminal runs in every new window of a profile (its "Run command"), and iTerm2's scripts that start
// with it.
func (r *StartupHooksRule) terminal(ctx *Context) []Finding {
	var out []Finding
	prefs := filepath.Join(ctx.Home, "Library/Preferences/com.apple.Terminal.plist")
	p, _ := readJobPlist(prefs)
	profiles, _ := p["Window Settings"].(map[string]any)
	var running []string
	for name, v := range profiles {
		prof, _ := v.(map[string]any)
		cmd, ok := prof["CommandString"].(string)
		if !ok || strings.Trim(cmd, " \t") == "" {
			continue
		}
		running = append(running, name+"："+commandProgram(cmd))
	}
	sort.Strings(running)
	if len(running) > 0 {
		out = append(out, Finding{Rule: "startup.terminal-command", Category: CatPersistence, Severity: Low, Verdict: Info, Path: prefs,
			Title: "终端每开一个窗口都会先运行一条命令（" + strconv.Itoa(len(running)) + " 个描述文件）",
			Evidence: map[string]string{"profiles": strings.Join(running, "；"),
				"how": "是你自己设的就留着；不认得的在 终端 → 设置 → 描述文件 → Shell，清掉「运行命令」"}})
	}
	auto := filepath.Join(ctx.Home, "Library/Application Support/iTerm2/Scripts/AutoLaunch")
	var scripts []string
	for _, u := range Children(auto) {
		if n := filepath.Base(u); !strings.HasPrefix(n, ".") {
			scripts = append(scripts, n)
		}
	}
	sort.Strings(scripts)
	if len(scripts) > 0 {
		shown := scripts
		if len(shown) > 10 {
			shown = shown[:10]
		}
		out = append(out, Finding{Rule: "startup.iterm-autolaunch", Category: CatPersistence, Severity: Low, Verdict: Info, Path: auto,
			Title:    "iTerm2 每次打开都会运行 " + strconv.Itoa(len(scripts)) + " 个脚本",
			Evidence: map[string]string{"scripts": strings.Join(shown, "；"), "how": "是你自己放的就留着；不认得的从这个文件夹里删掉"}})
	}
	return out
}

// periodic: scripts the system runs daily, weekly and monthly besides its own (/usr/local/etc/periodic), and
// periodic's local settings (which can add more folders).
func (r *StartupHooksRule) periodic() []Finding {
	if !Exists(r.PeriodicTool) {
		return nil
	}
	var local []string
	for _, d := range []string{"daily", "weekly", "monthly"} {
		for _, u := range Children(filepath.Join(r.UsrLocal, "etc/periodic", d)) {
			local = append(local, filepath.Base(filepath.Dir(u))+"/"+filepath.Base(u))
		}
	}
	conf := Exists(filepath.Join(r.Etc, "periodic.conf.local")) || Exists(filepath.Join(r.Etc, "periodic.conf"))
	if len(local) == 0 && !conf {
		return nil
	}
	ev := map[string]string{"how": "系统每天、每周、每月以管理员身份运行这些；是你或你装的软件放的就留着"}
	title := "系统的定时维护里加了别的东西"
	if len(local) > 0 {
		sorted := append([]string{}, local...)
		sort.Strings(sorted)
		if len(sorted) > 10 {
			sorted = sorted[:10]
		}
		ev["scripts"] = strings.Join(sorted, "；")
		title += "（" + strconv.Itoa(len(local)) + " 个脚本）"
	}
	if conf {
		ev["settings"] = "/etc/periodic.conf 或 periodic.conf.local 改过定时任务的设置"
	}
	return []Finding{{Rule: "startup.periodic", Category: CatPersistence, Severity: Low, Verdict: Info,
		Path: filepath.Join(r.UsrLocal, "etc/periodic"), Title: title, Evidence: ev}}
}
