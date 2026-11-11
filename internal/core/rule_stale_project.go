package core

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() { Register("stale.project", NewStaleProjectRule) }

// StaleProjectRule finds projects nobody touched for a long time. Deleting a project is never safe; with anything
// that exists only here (unpushed commits, uncommitted changes, stashes, no remote, ignored files that are not build
// output, folders next to the repos) it is info only, listing what would be lost.
//
// What it concluded about each folder is kept with the journal event it holds up to: a folder nothing was written in
// since (FSEvents) is not walked again and its repos are not asked again. One in use stays in use at least until the
// change found in it is StaleAfter old (deleting that file would show in the journal).
type StaleProjectRule struct {
	Journal JournalSource
	// MinArtifactBytes: below this, what a project's tools would make again is not worth a finding.
	MinArtifactBytes int64
	// MinFolderBytes: below this, an old folder that is not in git is not listed (empty folders a tool left, a few notes).
	MinFolderBytes int64
}

// NewStaleProjectRule makes the rule (the same for a fake home).
func NewStaleProjectRule(l *Layout, f *Fakes) Rule {
	return &StaleProjectRule{Journal: NewJournalSource(), MinArtifactBytes: 100 << 20, MinFolderBytes: 1 << 20}
}

func (r *StaleProjectRule) ID() string { return "stale.project" }
func (r *StaleProjectRule) Emits() []string {
	return []string{"stale.project", "stale.folders", "stale.artifacts"}
}

// staleArtifactKind is a folder a project's tool makes again from what is in the project: dependencies, build output,
// its caches. Known by its name and a file of that tool next to it (markers; *.ext for any file with that extension),
// and, where the name is common, a file of the tool inside it.
type staleArtifactKind struct {
	name    string
	markers []string
	inside  string
	// again is how it comes back.
	again string
}

// staleArtifactKinds are the kinds known (rules/build-artifacts.json), in order: of several for one folder name, the
// first whose markers are there.
var staleArtifactKinds []staleArtifactKind

// StaleArtifact is one such folder, relative to the project, with its size.
type StaleArtifact struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	Again string `json:"again"`
}

// StaleArtifactKind is the kind dir is, judged now: its name, its tool's file next to it (and inside it, where asked),
// nothing in it that git tracks, and no repository anywhere in it (a package checked out to edit: pip -e git+… puts
// one in a virtual environment's src). ok false: not one, or not sure. The kind is named by the folder name it is for.
func StaleArtifactKind(dir string) (string, bool) {
	k, _, ok := staleArtifact(dir)
	if !ok {
		return "", false
	}
	return k.name, true
}

// staleArtifact is StaleArtifactKind and the folder's size, from one walk.
func staleArtifact(dir string) (staleArtifactKind, int64, bool) {
	var st syscall.Stat_t
	if syscall.Lstat(dir, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return staleArtifactKind{}, 0, false
	}
	parent, name := filepath.Dir(dir), filepath.Base(dir)
	var siblings []string
	for _, c := range Children(parent) {
		siblings = append(siblings, filepath.Base(c))
	}
	has := func(marker string) bool {
		if strings.HasPrefix(marker, "*.") {
			for _, s := range siblings {
				if strings.HasSuffix(s, marker[1:]) {
					return true
				}
			}
			return false
		}
		return Exists(filepath.Join(parent, marker))
	}
	var kind *staleArtifactKind
	for i, k := range staleArtifactKinds {
		if k.name != name {
			continue
		}
		marked := false
		for _, m := range k.markers {
			if has(m) {
				marked = true
				break
			}
		}
		if marked && (k.inside == "" || Exists(filepath.Join(dir, k.inside))) {
			kind = &staleArtifactKinds[i]
			break
		}
	}
	if kind == nil {
		return staleArtifactKind{}, 0, false
	}
	// A repository inside, at any depth, is someone's work, not output.
	repo := false
	var bytes int64
	Tree(dir, func(e Entry) bool { return !e.InGit }, func(e Entry) bool {
		if e.InGit {
			repo = true
			return false
		}
		bytes += e.Bytes
		return true
	})
	if repo {
		return staleArtifactKind{}, 0, false
	}
	// Anything in it that git tracks was put there on purpose. git is asked only inside a repository (without the
	// developer tools, /usr/bin/git would offer to install them).
	if staleInRepo(parent) {
		r := Git(parent, "ls-files", "-z", "--", name)
		if r.TimedOut || r.Status != 0 || r.Stdout != "" {
			return staleArtifactKind{}, 0, false
		}
	}
	return *kind, bytes, true
}

// staleInRepo says whether dir or a folder above it has a .git.
func staleInRepo(dir string) bool {
	for p := filepath.Clean(dir); p != "/" && p != "."; p = filepath.Dir(p) {
		if Exists(filepath.Join(p, ".git")) {
			return true
		}
	}
	return false
}

// StaleArtifacts are the artifact folders in a project, looked for up to depth folders down (monorepos keep one per
// package), not inside one already found, not in hidden folders, not through links; at most limit folders looked into.
func StaleArtifacts(project string, depth, limit int) []StaleArtifact {
	names := map[string]bool{}
	for _, k := range staleArtifactKinds {
		names[k.name] = true
	}
	type queued struct {
		dir   string
		level int
	}
	var out []StaleArtifact
	queue := []queued{{project, 0}}
	seen := 0
	for len(queue) > 0 && seen < limit {
		q := queue[0]
		queue = queue[1:]
		seen++
		entries, ok := List(q.dir)
		if !ok {
			continue
		}
		for _, u := range entries {
			e, ok := Item(u)
			if !ok || !e.IsDir {
				continue
			}
			name := filepath.Base(u)
			if names[name] {
				if kind, bytes, ok := staleArtifact(u); ok {
					if bytes > 0 {
						out = append(out, StaleArtifact{Path: u[len(project)+1:], Bytes: bytes, Again: kind.again})
					}
					continue
				}
			}
			if !strings.HasPrefix(name, ".") && q.level+1 < depth {
				queue = append(queue, queued{u, q.level + 1})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// WouldLose is what deleting a project folder would lose: work that exists only here.
type WouldLose struct {
	Repos       int
	Lose        []string
	LastCommits map[string]string
}

func staleIsRepo(dir string) bool { return Exists(filepath.Join(dir, ".git")) }

// staleHasLinkedGit says whether the folder or a repo one level down has a .git that is a file (a linked worktree, or
// a separate git dir).
func staleHasLinkedGit(dir string) bool {
	for _, u := range append([]string{dir}, Children(dir)...) {
		var st syscall.Stat_t
		if syscall.Lstat(filepath.Join(u, ".git"), &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG {
			return true
		}
	}
	return false
}

// StaleWouldLose checks a project folder repo by repo (a folder that holds several repos one level down, with whatever
// sits next to them); ok false when it holds no repo. Also asked again right before a folder is moved: commits made
// since the scan are only in .git.
func StaleWouldLose(dir string) (WouldLose, bool) {
	name := filepath.Base(dir)
	var repos []string
	single := staleIsRepo(dir)
	if single {
		repos = []string{dir}
	} else {
		for _, c := range Children(dir) {
			if staleIsRepo(c) {
				repos = append(repos, c)
			}
		}
	}
	if len(repos) == 0 {
		return WouldLose{}, false
	}
	w := WouldLose{Repos: len(repos), LastCommits: map[string]string{}}
	if !single {
		// Whatever sits next to the repos is not in git: it can't be recovered from a remote.
		isRepo := spaceSet(repos...)
		var others []string
		for _, c := range Children(dir) {
			if !isRepo[c] && filepath.Base(c) != ".DS_Store" {
				others = append(others, filepath.Base(c))
			}
		}
		if len(others) > 0 {
			sort.Strings(others)
			w.Lose = append(w.Lose, name+" 里还有不在 git 里的："+staleFirst(others, 5))
		}
	}
	for _, r := range repos {
		label := name
		if !single {
			label = name + "/" + filepath.Base(r)
		}
		g, err := ReadGitState(r)
		if err != nil {
			// Can't tell what would be lost, so this project can only be info.
			if se, ok := err.(*SkippedError); ok {
				w.Lose = append(w.Lose, label+" 的 git 状态读不出来（"+se.Reason+"）")
			} else {
				w.Lose = append(w.Lose, label+" 的 git 状态读不出来")
			}
			continue
		}
		if !g.LastCommit.IsZero() {
			w.LastCommits["last_commit:"+label] = ISODay(g.LastCommit)
		}
		if !g.HasRemote {
			w.Lose = append(w.Lose, label+" 没有远程仓库")
		}
		if g.Unpushed > 0 {
			w.Lose = append(w.Lose, label+" 有 "+strconv.Itoa(g.Unpushed)+" 个提交没推送")
		}
		if g.Dirty != nil && *g.Dirty > 0 {
			w.Lose = append(w.Lose, label+" 有 "+strconv.Itoa(*g.Dirty)+" 处改动没提交")
		}
		if g.Dirty == nil {
			w.Lose = append(w.Lose, label+" 配了过滤器（filter），没检查有没有没提交的改动")
		}
		if g.Stashes > 0 {
			w.Lose = append(w.Lose, label+" 有 "+strconv.Itoa(g.Stashes)+" 个 stash")
		}
		if len(g.IgnoredKept) > 0 {
			w.Lose = append(w.Lose, label+" 有被 git 忽略、只在这台 Mac 上的："+staleFirst(g.IgnoredKept, 5))
		}
	}
	return w, true
}

// staleFirst is the first n joined, and how many there are when there are more.
func staleFirst(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, "、")
	}
	return strings.Join(items[:n], "、") + " 等 " + strconv.Itoa(len(items)) + " 样"
}

// staleVerdict is what a folder was found to be, as kept between rounds.
type staleVerdict struct {
	// InUseUntil: in use (changed recently) until then; nothing else is kept then.
	InUseUntil *time.Time `json:"inUseUntil,omitempty"`
	Bytes      int64      `json:"bytes"`
	// Repos nil: not a git project (a plain folder).
	Repos   *int              `json:"repos,omitempty"`
	Lose    []string          `json:"lose,omitempty"`
	Commits map[string]string `json:"commits,omitempty"`
	// Artifacts are what its tools make again; nil: not looked for yet (kept before they were looked for).
	Artifacts []StaleArtifact `json:"artifacts"`
}

// staleRow is a staleVerdict with the journal event it holds up to.
type staleRow struct {
	EventID    uint64       `json:"eventID"`
	Inode      uint64       `json:"inode"`
	MeasuredAt time.Time    `json:"measuredAt"`
	Verdict    staleVerdict `json:"verdict"`
}

func projectState(s *Store) Table[staleRow] { return NewTable[staleRow](s, "project_state", 2) }

// staleArtifactsOf are StaleArtifacts with the usual limits; none found is an empty list, not "not looked for".
func staleArtifactsOf(dir string) []StaleArtifact {
	if a := StaleArtifacts(dir, 4, 3000); a != nil {
		return a
	}
	return []StaleArtifact{}
}

func (r *StaleProjectRule) Run(ctx *Context) ([]Finding, error) {
	if artifactsErr != nil {
		return nil, rulesMissing("build-artifacts.json")
	}
	since := ctx.Now.Add(-ctx.StaleAfter)
	var table Table[staleRow]
	known := map[string]staleRow{}
	if ctx.Store != nil {
		table = projectState(ctx.Store)
		known = table.Load()
	}
	// Roots this round may not look at; said only of one an earlier round found projects in (whether it is there
	// cannot be asked without looking).
	canonHome, homePath := Canonical(ctx.Home), filepath.Clean(ctx.Home)
	relOf := func(root string) string { return strings.TrimPrefix(filepath.Clean(root), homePath) }
	var left, roots []string
	for _, root := range ctx.ProjectRoots {
		if ctx.MayLook(root) {
			if Exists(root) {
				roots = append(roots, root)
			}
			continue
		}
		prefix := canonHome + relOf(root) + "/"
		for k := range known {
			if strings.HasPrefix(k, prefix) {
				left = append(left, root)
				break
			}
		}
	}
	// Nothing to look at this round: what is remembered stays as it is.
	if len(roots) == 0 && len(left) > 0 {
		shown := make([]string, len(left))
		for i, l := range left {
			shown[i] = ctx.Shown(l)
		}
		return nil, Skip(NotLooked(strings.Join(shown, "、") + " 里的项目"))
	}
	var ids []uint64
	for _, k := range known {
		ids = append(ids, k.EventID)
	}
	inc, err := BeginIncrement(ctx, "fsevents.journal.projects", roots, minEventID(ids), r.Journal, func() error {
		known = map[string]staleRow{}
		if ctx.Store == nil {
			return nil
		}
		return table.Apply(nil, nil, true)
	})
	if err != nil {
		return nil, err
	}
	rows := map[string]staleRow{}
	present := map[string]bool{}
	save := func(forget []string) {
		if ctx.Store != nil {
			table.Apply(rows, forget, false)
		}
	}
	var out []Finding
	for _, root := range roots {
		type plainFolder struct {
			name  string
			bytes int64
		}
		var plain []plainFolder // not in git: one finding per root
		for _, dir := range Children(root) {
			if !spaceIsDir(dir) {
				continue
			}
			if ctx.IsCancelled() {
				save(nil) // keep what was looked at
				return nil, Skip(Interrupted)
			}
			key, ino := Canonical(dir), Inode(dir)
			present[key] = true
			var v staleVerdict
			if k, ok := known[key]; ok && k.Inode == ino && r.Journal.Reusable(k.MeasuredAt, ctx.Now) && !inc.Changes.Touched(key, k.EventID) &&
				(k.Verdict.InUseUntil == nil || ctx.Now.Before(*k.Verdict.InUseUntil)) {
				v = k.Verdict
				if v.InUseUntil == nil && v.Artifacts == nil { // kept before artifacts were looked for: still good up to its event
					v.Artifacts = staleArtifactsOf(dir)
					rows[key] = staleRow{EventID: k.EventID, Inode: k.Inode, MeasuredAt: k.MeasuredAt, Verdict: v}
				}
			} else {
				if changed, bytes := FirstChange(dir, since, ctx.Now, true); !changed.IsZero() {
					until := changed.Add(ctx.StaleAfter)
					v = staleVerdict{InUseUntil: &until}
				} else if w, ok := StaleWouldLose(dir); ok {
					repos := w.Repos
					v = staleVerdict{Bytes: bytes, Repos: &repos, Lose: w.Lose, Commits: w.LastCommits, Artifacts: staleArtifactsOf(dir)}
				} else {
					v = staleVerdict{Bytes: bytes, Artifacts: staleArtifactsOf(dir)}
				}
				// A linked worktree (its .git a file pointing elsewhere): commits and fetches happen in another folder's
				// .git, which the journal does not report under this one. Looked at every round.
				if !staleHasLinkedGit(dir) {
					rows[key] = staleRow{EventID: inc.Start, Inode: ino, MeasuredAt: ctx.Now, Verdict: v}
				}
			}
			if v.InUseUntil != nil {
				continue // in use
			}
			name := filepath.Base(dir)
			var total int64
			for _, a := range v.Artifacts {
				total += a.Bytes
			}
			if total >= r.MinArtifactBytes {
				var listed, targets []string
				again := map[string]bool{}
				for i, a := range v.Artifacts {
					if i < 10 {
						listed = append(listed, a.Path+"（"+FormatBytes(a.Bytes)+"）")
					}
					targets = append(targets, filepath.Join(dir, a.Path))
					again[a.Again] = true
				}
				artifacts := strings.Join(listed, "；")
				if len(v.Artifacts) > 10 {
					artifacts += " 等 " + strconv.Itoa(len(v.Artifacts)) + " 个"
				}
				var how []string
				for a := range again {
					how = append(how, a)
				}
				sort.Strings(how)
				out = append(out, Finding{Rule: "stale.artifacts", Category: CatStaleProject, Severity: Low, Verdict: Confirm, Path: dir,
					Bytes: Size(total), Title: name + " 半年多没动过，里面能重新生成的依赖和构建产物占 " + FormatBytes(total),
					Evidence: map[string]string{"artifacts": artifacts, "targets": strings.Join(targets, "\n"),
						"how": "只删这些，项目本身留着；要再开发时照常装依赖、构建一遍就回来：" + strings.Join(how, "、")}})
			}
			if v.Repos == nil {
				if v.Bytes >= r.MinFolderBytes {
					plain = append(plain, plainFolder{name, v.Bytes})
				}
				continue
			}
			evidence := map[string]string{"size": FormatBytes(v.Bytes), "repos": strconv.Itoa(*v.Repos)}
			for k, c := range v.Commits {
				if _, ok := evidence[k]; !ok {
					evidence[k] = c
				}
			}
			clean := len(v.Lose) == 0
			verdict, title := Confirm, name+" 半年多没动过，都已推送，删了能从远程找回"
			if !clean {
				evidence["would_lose"] = strings.Join(v.Lose, "；")
				verdict, title = Info, name+" 半年多没动过，但有只在这台 Mac 上的工作"
			}
			out = append(out, Finding{Rule: "stale.project", Category: CatStaleProject, Severity: Low, Verdict: verdict, Path: dir,
				Bytes: Size(v.Bytes), Title: title, Evidence: evidence})
		}
		if len(plain) > 0 {
			sort.SliceStable(plain, func(i, j int) bool { return plain[i].bytes > plain[j].bytes })
			var total int64
			var listed []string
			for i, p := range plain {
				total += p.bytes
				if i < 20 {
					listed = append(listed, p.name+"（"+FormatBytes(p.bytes)+"）")
				}
			}
			out = append(out, Finding{Rule: "stale.folders", Category: CatStaleProject, Severity: Low, Verdict: Info, Path: root,
				Bytes:    Size(total),
				Title:    DisplayName(root) + " 里有 " + strconv.Itoa(len(plain)) + " 个文件夹半年多没动过（不在 git 里，无法确认别处有没有副本）",
				Evidence: map[string]string{"count": strconv.Itoa(len(plain)), "size": FormatBytes(total), "folders": strings.Join(listed, "；")}})
		}
	}
	// Rows of a root not looked at this round are kept, not forgotten as gone. Spelled from the home without resolving
	// anything inside a guarded folder (resolving is looking).
	var rel []string
	for _, l := range left {
		rel = append(rel, relOf(l))
	}
	var forget []string
	for k := range known {
		if present[k] {
			continue
		}
		kept := false
		for _, r := range rel {
			kept = kept || strings.HasPrefix(k, canonHome+r+"/")
		}
		if !kept {
			forget = append(forget, k)
		}
	}
	save(forget)
	if len(left) > 0 {
		shown := make([]string, len(rel))
		for i, r := range rel {
			shown[i] = "~" + r
		}
		return nil, Skip(NotLooked(strings.Join(shown, "、")+" 里的项目"), out...)
	}
	return out, nil
}
