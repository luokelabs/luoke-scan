package core

import (
	"os"
	"path/filepath"
	"strings"
)

// LaunchAgentRule: user LaunchAgents that point at things that no longer exist (the app or checkout behind them was
// deleted). They fail on every login; if the path is later made again by someone else, it runs their code.
// Swift: Rules/LaunchAgentRule.swift.
type LaunchAgentRule struct{}

func init() { Register("persistence.launchagent-missing", NewLaunchAgentRule) }

func NewLaunchAgentRule(l *Layout, f *Fakes) Rule { return &LaunchAgentRule{} }

func (r *LaunchAgentRule) ID() string { return "persistence.launchagent-missing" }
func (r *LaunchAgentRule) Emits() []string {
	return []string{"persistence.launchagent-missing", "persistence.launchagent-unreadable"}
}

// launchJobDependencies are the absolute paths a job depends on: the program, the working directory, and any
// absolute-path argument (`/usr/bin/env swift run --package-path <dir>` style jobs).
func launchJobDependencies(plist map[string]any) []string {
	var paths []string
	if p, ok := plist["Program"].(string); ok {
		paths = append(paths, p)
	}
	for _, a := range appsPlistStrings(plist["ProgramArguments"]) {
		if strings.HasPrefix(a, "/") {
			paths = append(paths, a)
		}
	}
	if w, ok := plist["WorkingDirectory"].(string); ok {
		paths = append(paths, w)
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// readJobPlist reads a launchd job's plist as a dictionary; ok false when it cannot be read or is not one.
func readJobPlist(path string) (map[string]any, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	v, err := DecodePlist(data)
	d, ok := v.(map[string]any)
	return d, err == nil && ok
}

func (r *LaunchAgentRule) Run(ctx *Context) ([]Finding, error) {
	dir := filepath.Join(ctx.Home, "Library/LaunchAgents")
	if !Exists(dir) {
		return nil, nil
	}
	var out []Finding
	for _, f := range Children(dir) {
		if PathExtension(f) != "plist" {
			continue
		}
		plist, ok := readJobPlist(f)
		if !ok {
			out = append(out, Finding{Rule: "persistence.launchagent-unreadable", Category: CatPersistence, Severity: Low, Verdict: Info,
				Path: f, Title: filepath.Base(f) + " 读不出来", Evidence: map[string]string{}})
			continue
		}
		// One in a guarded folder is not looked for without Full Disk Access: unknown, not missing.
		var missing []string
		for _, p := range launchJobDependencies(plist) {
			if ctx.MayLook(p) && !Exists(p) {
				missing = append(missing, p)
			}
		}
		if len(missing) == 0 {
			continue
		}
		label, ok := plist["Label"].(string)
		if !ok {
			label = NameWithoutExtension(f)
		}
		out = append(out, Finding{Rule: r.ID(), Category: CatPersistence, Severity: Medium, Verdict: Confirm, Path: f,
			Title: "后台任务 " + label + " 指向已经不存在的位置",
			Evidence: map[string]string{"label": label, "missing": strings.Join(missing, "；"),
				"hint": "它每次登录都会启动失败；以后有人在这个位置放了东西，就会以你的身份运行"}})
	}
	return out, nil
}
