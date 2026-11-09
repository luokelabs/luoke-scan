package core

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// EventTapRule lists programs that watch every key pressed in every app (an event tap on the keyboard for all
// processes): what keyboard tools, launchers and password managers do, and what a keylogger does. Listed with who
// signed each; one nobody vouches for is reported on its own. macOS's own are left out. Asking which taps there are
// needs no permission and shows no dialog.
type EventTapRule struct {
	// Taps are the taps on key presses, from the window server; ok false when not known. nil: KeyboardTaps.
	Taps func() ([]EventTap, bool)
	// Signature checks a program; nil: SignatureOf.
	Signature func(path string) Signature
}

// EventTap is a tap: the program holding it, whether it only listens, whether it watches keys in every app.
type EventTap struct {
	// Program is "" when its program file is gone (deleted while it runs).
	Program    string
	ListenOnly bool
	AllApps    bool
	PID        int32
}

// KeyboardTaps are this Mac's taps on key down and key up (CGGetEventTapList, each tapping process's program from
// ProcPath); ok false when the window server cannot be asked.
// Set by the cgo file (macos_cgo.go); a build without cgo does not know them, and the rule is skipped.
var KeyboardTaps = func() ([]EventTap, bool) { return nil, false }

func init() { Register("keyboard", NewEventTapRule) }

// NewEventTapRule is the rule for this Mac (l nil) or a fake home: there the taps are the fakes' eventTaps and a
// program's signature is the fakes' codesign answer, else codesign's.
func NewEventTapRule(l *Layout, f *Fakes) Rule {
	r := &EventTapRule{}
	if l != nil {
		r.Signature = keyboardCodesign(f)
		var taps []EventTap
		if f.EventTaps != nil {
			taps = []EventTap{}
			for _, t := range *f.EventTaps {
				pid := int32(0)
				if t.PID != nil {
					pid = *t.PID
				}
				taps = append(taps, EventTap{Program: t.Program, ListenOnly: t.ListenOnly, AllApps: t.AllApps, PID: pid})
			}
		}
		known := f.EventTaps != nil
		r.Taps = func() ([]EventTap, bool) { return taps, known }
	}
	return r
}

// keyboardCodesign is what a signature check finds in a fake home: the fakes' codesign answer for the path, else
// codesign's (a developer's signature cannot be made in a fixture).
func keyboardCodesign(f *Fakes) func(string) Signature {
	return func(p string) Signature {
		if s, ok := f.Codesign[p]; ok {
			return ParseSignature(s)
		}
		return SignatureOf(p)
	}
}

func (r *EventTapRule) ID() string      { return "keyboard" }
func (r *EventTapRule) Emits() []string { return []string{"keyboard.watchers", "keyboard.unvouched"} }

// tapLabel is the app a program belongs to ("…/Raycast.app/Contents/MacOS/Raycast" → Raycast), or its file name.
func tapLabel(path string) string {
	if i := strings.LastIndex(path, ".app/"); i >= 0 {
		return filepath.Base(path[:i])
	}
	if path == "" {
		return "（已经退出的程序）"
	}
	return filepath.Base(path)
}

// tapInterpreter: programs Apple signs that run whatever script they are given. A tap held by one is the script's,
// which nobody vouches for.
func tapInterpreter(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if strings.Contains(path, "/Python.app/") || strings.HasPrefix(name, "python") {
		return true
	}
	for _, n := range []string{"osascript", "perl", "ruby", "bash", "zsh", "sh", "swift", "tclsh"} {
		if name == n {
			return true
		}
	}
	return false
}

func (r *EventTapRule) Run(ctx *Context) ([]Finding, error) {
	taps := r.Taps
	if taps == nil {
		taps = KeyboardTaps
	}
	signature := r.Signature
	if signature == nil {
		signature = SignatureOf
	}
	all, ok := taps()
	if !ok {
		return nil, Skip("问不到窗口服务器（没有登录的图形界面）")
	}
	var vouched []string
	var out []Finding
	unvouched := func(p, name, why string, sev Severity) {
		// A program not looked at is not the finding's path (its id would resolve it); the key says which.
		path, program := p, "（程序文件已经不在了）"
		if p == "" || !ctx.MayLook(p) {
			path = ""
		}
		if p != "" {
			program = ctx.Shown(p)
		}
		out = append(out, Finding{Rule: "keyboard.unvouched", Category: CatProcess, Severity: sev, Verdict: Info, Path: path,
			Title: name + " 在看你在所有应用里按的每一个键",
			Evidence: map[string]string{"program": program, "signature": why,
				"why": "键盘记录器就是这样偷密码的；自己编的小工具、Homebrew 装的快捷键工具也可能这样",
				"how": "认得就留着；不认得的先退出它，再在 系统设置 → 隐私与安全性 → 输入监控、辅助功能 里关掉它的权限，把程序移到废纸篓"},
			Key: "keyboard/" + p})
	}
	// A program deleted while it runs (proc_pidpath has nothing): what a keylogger that cleans up after itself looks like.
	for _, t := range all {
		if t.AllApps && t.Program == "" {
			unvouched("", "程序文件已经删掉了的进程（pid "+strconv.Itoa(int(t.PID))+"）", "程序文件不在了", High)
		}
	}
	seen := map[string]bool{}
	var programs []string
	for _, t := range all {
		if t.AllApps && t.Program != "" && !strings.HasPrefix(t.Program, "/System/") && !seen[t.Program] {
			seen[t.Program] = true
			programs = append(programs, t.Program)
		}
	}
	sort.Strings(programs)
	for _, p := range programs {
		// In a guarded folder without Full Disk Access its signature is not read; being there is reason enough to say.
		if !ctx.MayLook(p) {
			unvouched(p, "放在桌面、文稿或下载里的程序 "+tapLabel(p), Signature{Kind: SigUnknown}.Label(), Medium)
			continue
		}
		sig := signature(p)
		if sig.Kind == SigApple {
			if tapInterpreter(p) {
				unvouched(p, "跑脚本的 "+tapLabel(p)+"（在跑某个脚本）", "苹果签名的解释器，脚本没人担保", Medium)
			}
			continue
		}
		if sig.Unvouched() || sig.Kind == SigInvalid || sig.Kind == SigMissing {
			// Homebrew's tools are mostly unsigned or ad hoc signed: one of those is far more often a hotkey tool.
			sev := High
			if strings.HasPrefix(p, "/opt/homebrew/") || strings.HasPrefix(p, "/usr/local/Cellar/") || strings.HasPrefix(p, "/usr/local/opt/") {
				sev = Medium
			}
			unvouched(p, "没有开发者担保的程序 "+tapLabel(p), sig.Label(), sev)
		} else {
			vouched = append(vouched, tapLabel(p))
		}
	}
	if len(vouched) > 0 {
		set := map[string]bool{}
		var names []string
		for _, n := range vouched {
			if !set[n] {
				set[n] = true
				names = append(names, n)
			}
		}
		sort.Strings(names)
		shown := names
		more := ""
		if len(names) > 5 {
			shown, more = names[:5], " 等"
		}
		out = append(out, Finding{Rule: "keyboard.watchers", Category: CatProcess, Severity: Low, Verdict: Info,
			Title: strconv.Itoa(len(names)) + " 个程序在看你在所有应用里按的键：" + strings.Join(shown, "、") + more,
			Evidence: map[string]string{"programs": strings.Join(names, "；"),
				"why": "快捷键工具、启动器、输入增强和密码管理器要这个才能用",
				"how": "认得就留着；不认得的在 系统设置 → 隐私与安全性 → 输入监控、辅助功能 里关掉"},
			Key: strings.Join(names, "|")})
	}
	return out, nil
}
