package core

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// What AI coding tools read by themselves when they start or open a project: AGENTS.md, CLAUDE.md, GEMINI.md, Cursor's
// rules, Copilot's instructions… Read within bounds and checked with the skills' text checks (skillcheck.go); nothing
// of a file's contents is kept or sent.

// AgentFile is one such file as read.
type AgentFile struct {
	Agent   string
	Scope   SkillScope
	Project string
	// Path as the tool finds it (links on the way not resolved); RealPath with links resolved: what was read.
	Path, RealPath string
	// Name is relative to the project (or the home), as shown: "AGENTS.md", ".cursor/rules/style.mdc".
	Name    string
	Bytes   int64
	Text    string
	HasText bool
	Unread  Unread
	// Digest: 16 hex digits of what was read; the same file copied into several projects is said once.
	Digest string
}

// asSkill is the file as a one-file skill, the shape the text checks take.
func (a AgentFile) asSkill() Skill {
	return Skill{Agent: a.Agent, Scope: a.Scope, Place: a.Name, Project: a.Project, Folder: filepath.Dir(a.Path),
		RealFolder: filepath.Dir(a.RealPath), Metadata: map[string]string{}, Instructions: a.Text, InstructionsLine: 1,
		Files:  []SkillFile{{Path: a.Name, Bytes: a.Bytes, Kind: FileKindText, Text: a.Text, HasText: a.HasText, Unread: a.Unread}},
		Digest: a.Digest}
}

// AgentFilePlace is where a tool keeps the instructions it reads by itself, relative to the home (personal) or a
// project's folder; Folder: a folder of such files, its Markdown files one level down.
type AgentFilePlace struct {
	Agent  string
	Scope  SkillScope
	Path   string
	Folder bool
}

// AgentFilePlaces: one table, easy to extend; what does not exist is skipped.
var AgentFilePlaces = []AgentFilePlace{
	{"Claude Code", ScopePersonal, ".claude/CLAUDE.md", false},
	{"Codex", ScopePersonal, ".codex/AGENTS.md", false},
	{"Gemini CLI", ScopePersonal, ".gemini/GEMINI.md", false},
	{"多个 AI 工具共用", ScopeProject, "AGENTS.md", false},
	{"Claude Code", ScopeProject, "CLAUDE.md", false},
	{"Claude Code", ScopeProject, "CLAUDE.local.md", false},
	{"Claude Code", ScopeProject, ".claude/CLAUDE.md", false},
	{"Gemini CLI", ScopeProject, "GEMINI.md", false},
	{"Cursor", ScopeProject, ".cursorrules", false},
	{"Cursor", ScopeProject, ".cursor/rules", true},
	{"Windsurf", ScopeProject, ".windsurfrules", false},
	{"GitHub Copilot", ScopeProject, ".github/copilot-instructions.md", false},
	{"GitHub Copilot", ScopeProject, ".github/instructions", true},
}

// AgentFileLimits bound what a round reads.
type AgentFileLimits struct {
	MaxFiles, MaxFileBytes, MaxRoundBytes, MaxFolderFiles, MaxProjects int
}

// DefaultAgentFileLimits: 400 files, 256 KB a file, 16 MB a round, 40 files from one folder of rules, 500 projects.
func DefaultAgentFileLimits() AgentFileLimits {
	return AgentFileLimits{MaxFiles: 400, MaxFileBytes: 256 << 10, MaxRoundBytes: 16 << 20, MaxFolderFiles: 40, MaxProjects: 500}
}

// AgentFilesFound is what a search found.
type AgentFilesFound struct {
	Files []AgentFile
	Left  []string
	More  int
}

type agentSpot struct {
	place   AgentFilePlace
	project string
	spelled string
	real    string
	name    string
}

func agentFileSpots(ctx *Context, places []AgentFilePlace, limits AgentFileLimits) ([]agentSpot, []string) {
	type base struct {
		place   AgentFilePlace
		project string
		dir     string
	}
	var bases []base
	for _, p := range places {
		if p.Scope == ScopePersonal {
			bases = append(bases, base{p, "", ctx.Home})
		}
	}
	var left []string
	var projectPlaces []AgentFilePlace
	for _, p := range places {
		if p.Scope == ScopeProject {
			projectPlaces = append(projectPlaces, p)
		}
	}
	if len(projectPlaces) > 0 {
		for _, root := range ctx.ProjectRoots {
			if !ctx.MayLook(root) {
				left = append(left, ctx.Shown(root)+" 里项目给 AI 看的说明")
				continue
			}
			for _, p := range aiProjectFolders(root, limits.MaxProjects) {
				for _, pl := range projectPlaces {
					bases = append(bases, base{pl, p, p})
				}
			}
		}
	}
	var out []agentSpot
	seen := map[string]bool{}
	take := func(place AgentFilePlace, project, spelled, name string) {
		st, ok := aiLstat(spelled)
		if !ok {
			return
		}
		real := spelled
		if aiStLink(st) || !ctx.MayLook(spelled) {
			r, ok := ResolvedPath(spelled, ctx)
			if !ok {
				return
			}
			real = r
		}
		if !ctx.MayLook(real) || !aiIsReg(real) {
			return
		}
		// CLAUDE.md is often a link to AGENTS.md: the same file is read and said once.
		c := Canonical(real)
		if seen[c] {
			return
		}
		seen[c] = true
		out = append(out, agentSpot{place, project, spelled, real, name})
	}
	for _, b := range bases {
		at := filepath.Join(b.dir, b.place.Path)
		if !b.place.Folder {
			take(b.place, b.project, at, b.place.Path)
			continue
		}
		if !aiIsDir(at) || !ctx.MayLook(at) {
			continue
		}
		var names []string
		for _, c := range Children(at) {
			n := filepath.Base(c)
			if strings.HasSuffix(n, ".md") || strings.HasSuffix(n, ".mdc") {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		if len(names) > limits.MaxFolderFiles {
			names = names[:limits.MaxFolderFiles]
		}
		for _, n := range names {
			take(b.place, b.project, filepath.Join(at, n), b.place.Path+"/"+n)
		}
	}
	return out, aiSortedUnique(left)
}

// FindAgentFiles are the instruction files on this Mac, read within limits.
func FindAgentFiles(ctx *Context, places []AgentFilePlace, limits AgentFileLimits) AgentFilesFound {
	spots, left := agentFileSpots(ctx, places, limits)
	budget := limits.MaxRoundBytes
	var files []AgentFile
	for i, s := range spots {
		if i >= limits.MaxFiles || ctx.IsCancelled() {
			break
		}
		files = append(files, readAgentFile(s, limits, &budget, ctx.Home))
	}
	more := len(spots) - limits.MaxFiles
	if more < 0 {
		more = 0
	}
	return AgentFilesFound{Files: files, Left: left, More: more}
}

func readAgentFile(s agentSpot, limits AgentFileLimits, budget *int, home string) AgentFile {
	st, ok := aiLstat(s.real)
	var size int64
	if ok {
		size = st.Size
	}
	a := AgentFile{Agent: s.place.Agent, Scope: s.place.Scope, Project: s.project, Path: s.spelled, RealPath: s.real, Name: s.name, Bytes: size}
	switch {
	case ok && aiDataless(st):
		a.Unread = UnreadICloud // reading it would download it
	case size > int64(limits.MaxFileBytes):
		a.Unread = UnreadTooLarge
	case int64(*budget) < size:
		a.Unread = UnreadBudget
	default:
		if data, ok := aiReadHead(s.real, int(size)); ok {
			*budget -= len(data)
			if t, ok := aiDecodeUTF8(data); ok {
				a.Text, a.HasText = t, true
			} else {
				a.Unread = UnreadUnreadable
			}
		} else {
			a.Unread = UnreadUnreadable
		}
	}
	// The same text is one instruction wherever it is (copies, links). One not read is known only as itself (where it
	// really is, from the home, so the key stays the same on another Mac).
	h := sha256.New()
	if a.HasText {
		h.Write([]byte(a.Text))
	} else {
		h.Write([]byte(HomeRelative(s.real, home) + "|" + strconv.FormatInt(size, 10) + "|" + string(a.Unread)))
	}
	sum := h.Sum(nil)
	a.Digest = hex.EncodeToString(sum[:8])
	return a
}
