package core

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gitSafety turns off what a repo's own .git/config can make git run during read-only commands (an unpacked archive
// may carry one): fsmonitor on `status`, hooks, gpg on `log` when it shows signatures. Clean filters are checked
// separately (ReadGitState), since their names are the repo's own.
var gitSafety = []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "log.showSignature=false",
	"-c", "status.showUntrackedFiles=normal"}

// Git runs /usr/bin/git read-only in repo: no optional locks, none of the user's or the system's settings (GitEnv),
// no prompts. Status 127 without the developer tools (then /usr/bin/git would offer to install them: a dialog).
func Git(repo string, args ...string) ProcResult {
	if !DeveloperTools() {
		return ProcResult{Status: 127}
	}
	a := append([]string{"--no-optional-locks"}, gitSafety...)
	a = append(a, "-C", repo)
	a = append(a, args...)
	return Run("/usr/bin/git", a, RunOpts{Env: GitEnv})
}

var developerTools = sync.OnceValue(func() bool {
	r := Run("/usr/bin/xcode-select", []string{"-p"}, RunOpts{Timeout: 10 * time.Second})
	dir := strings.TrimSpace(r.Stdout)
	return r.Status == 0 && dir != "" && IsExecutable(dir+"/usr/bin/git")
})

// DeveloperTools says whether git can run without asking: /usr/bin/git stands in for it and offers to install the
// developer tools when neither Xcode nor the command line tools are there. Asked once.
func DeveloperTools() bool { return developerTools() }

// GitState is what decides whether deleting a project would lose work.
type GitState struct {
	LastCommit time.Time // zero: no commit
	HasRemote  bool
	Unpushed   int
	// Dirty is the number of uncommitted changes; nil when they could not be checked safely (the repo configures clean
	// filters).
	Dirty   *int
	Stashes int
	// IgnoredKept are ignored entries that are not rebuildable output (.env, local databases, data folders): they
	// exist only here.
	IgnoredKept []string
}

// SafeToDrop says nothing exists only on this Mac.
func (g GitState) SafeToDrop() bool {
	return g.HasRemote && g.Unpushed == 0 && g.Dirty != nil && *g.Dirty == 0 && g.Stashes == 0 && len(g.IgnoredKept) == 0
}

// gitRebuildable are ignored entries tools rebuild (dependencies, build output, caches): losing them loses nothing.
var gitRebuildable = spaceSet("node_modules", ".build", "build", "dist", "out", "target", "DerivedData", ".venv", "venv",
	"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".next", ".nuxt", ".gradle", "Pods", ".DS_Store",
	".swiftpm", ".dart_tool", ".parcel-cache", ".turbo", ".cache", "coverage", ".idea", ".vscode", ".eggs")

var gitRebuildableExtensions = spaceSet("pyc", "pyo", "o", "a", "class", "log", "egg-info")

func gitIsRebuildable(entry string) bool {
	name := filepath.Base(entry)
	return gitRebuildable[name] || gitRebuildableExtensions[spaceExt(name)]
}

// ReadGitState asks git about repo. A command that fails or times out is a *SkippedError naming it.
func ReadGitState(repo string) (GitState, error) {
	out := func(args ...string) (string, error) {
		r := Git(repo, args...)
		if r.TimedOut {
			return "", Skip("git " + args[0] + " 超时：" + repo)
		}
		if r.Status != 0 {
			return "", Skip("git " + args[0] + " 失败（" + strconv.Itoa(r.Status) + "）：" + repo)
		}
		return strings.TrimSpace(r.Stdout), nil
	}
	var g GitState
	if log := Git(repo, "log", "-1", "--format=%ct"); log.Status == 0 { // an empty repo: no commits, non-zero exit
		if s, err := strconv.ParseFloat(strings.TrimSpace(log.Stdout), 64); err == nil {
			g.LastCommit = time.Unix(int64(s), 0)
		}
	}
	remotes, err := out("remote")
	if err != nil {
		return g, err
	}
	g.HasRemote = remotes != ""
	if g.HasRemote {
		n, err := out("rev-list", "--count", "--branches", "--not", "--remotes")
		if err != nil {
			return g, err
		}
		g.Unpushed, _ = strconv.Atoi(n)
	}
	// `git status` runs a repo's clean filters on changed files; their programs are the repo's own choice.
	filters := Git(repo, "config", "--get-regexp", `^filter\..*\.(clean|process)$`)
	if filters.Status != 0 && filters.Status != 1 {
		return g, Skip("git config 失败（" + strconv.Itoa(filters.Status) + "）：" + repo)
	}
	if filters.Status == 1 { // 1: no such keys
		status, err := out("status", "--porcelain", "--ignored")
		if err != nil {
			return g, err
		}
		changes := 0
		for _, line := range strings.Split(status, "\n") {
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "!! ") {
				entry := strings.Trim(line[3:], "/\"")
				if !gitIsRebuildable(entry) {
					g.IgnoredKept = append(g.IgnoredKept, entry)
				}
			} else {
				changes++
			}
		}
		g.Dirty = &changes
	}
	stashes, err := out("stash", "list")
	if err != nil {
		return g, err
	}
	for _, line := range strings.Split(stashes, "\n") {
		if line != "" {
			g.Stashes++
		}
	}
	return g, nil
}
