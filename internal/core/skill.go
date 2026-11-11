package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// An AI agent's skill as found on this Mac: a folder with a SKILL.md (YAML front matter with at least name and
// description, then instructions in Markdown for the agent), often with scripts and other files. Read once per round,
// within bounds, and handed to the checks (skillcheck.go). Its contents are not stored and never leave this Mac; the one
// place they go is luoke-core's local model, on this Mac: for a skill the rules reported, a shortened excerpt
// (SkillReviewInput) when that task is on (internal/service/hubtask.go).

// SkillScope says whose a skill is: the user's own (in the home) or a project's.
type SkillScope string

const (
	ScopePersonal SkillScope = "personal"
	ScopeProject  SkillScope = "project"
)

// SkillFileKind is what a file is, from its name and first bytes.
type SkillFileKind string

const (
	FileKindText     SkillFileKind = "text"     // text that is not a program: Markdown, plain text, JSON, YAML…
	FileKindScript   SkillFileKind = "script"   // a program in readable form (any text starting with #! too)
	FileKindCompiled SkillFileKind = "compiled" // a program that cannot be read as text
	FileKindBinary   SkillFileKind = "binary"   // bytes of an unknown kind
	FileKindArchive  SkillFileKind = "archive"
	FileKindOther    SkillFileKind = "other" // pictures, fonts, documents, sound
)

// Unread is why a file's contents were not read ("" when they were, or it was not to be).
type Unread string

const (
	UnreadTooLarge     Unread = "too-large"
	UnreadBudget       Unread = "budget"
	UnreadLinkOutside  Unread = "link-outside"
	UnreadDependencies Unread = "dependencies"
	UnreadTooDeep      Unread = "too-deep"
	UnreadICloud       Unread = "icloud"
	UnreadUnreadable   Unread = "unreadable"
)

// SkillFile is one file of a skill.
type SkillFile struct {
	// Path is relative to the skill's folder; a folder that was not looked through ends with "/".
	Path  string
	Bytes int64
	Kind  SkillFileKind
	// Text is the whole contents of a text or script file, when read (HasText).
	Text    string
	HasText bool
	Unread  Unread
}

// Skill is a skill as read.
type Skill struct {
	Agent string
	Scope SkillScope
	Place string
	// Project is the project's folder for a project's own skill ("" otherwise).
	Project string
	// Folder as the agent finds it (links on the way not resolved); RealFolder with links resolved: what was read.
	Folder, RealFolder string
	Name, Description  string
	// AllowedTools from the front matter, one entry per tool; HasAllowedTools false when it declares none.
	AllowedTools    []string
	HasAllowedTools bool
	Metadata        map[string]string
	// Instructions is SKILL.md after its front matter, starting at InstructionsLine (1-based).
	Instructions     string
	InstructionsLine int
	Files            []SkillFile
	// Unlisted: files beyond the limit, neither listed nor read.
	Unlisted int
	// Digest: 16 hex digits of every file's path, size and what was read of it.
	Digest string
}

// SkillPlace is where an agent keeps skills, relative to the home (personal) or a project's folder (project); Depth is
// how many folders below it a SKILL.md may be.
type SkillPlace struct {
	Agent string
	Scope SkillScope
	Path  string
	Depth int
}

// SkillPlaces: one table, easy to extend; a folder that does not exist is skipped.
var SkillPlaces = []SkillPlace{
	{"Claude Code", ScopePersonal, ".claude/skills", 2},
	// Plugins' own skills: marketplaces/<m>/plugins/<p>/skills/<s>, cache/<m>/<p>/<version>/skills/<s>.
	{"Claude Code 插件", ScopePersonal, ".claude/plugins", 7},
	{"Cursor", ScopePersonal, ".cursor/skills", 2},
	{"Gemini CLI", ScopePersonal, ".gemini/skills", 2},
	{"GitHub Copilot", ScopePersonal, ".copilot/skills", 2},
	{"Codex", ScopePersonal, ".codex/skills", 3},
	{"多个 AI 工具共用", ScopePersonal, ".agents/skills", 2},
	{"Claude Code", ScopeProject, ".claude/skills", 2},
	{"Cursor", ScopeProject, ".cursor/skills", 2},
	{"Gemini CLI", ScopeProject, ".gemini/skills", 2},
	{"GitHub Copilot", ScopeProject, ".github/skills", 2},
	{"Codex", ScopeProject, ".codex/skills", 2},
	{"多个 AI 工具共用", ScopeProject, ".agents/skills", 2},
}

// SkillLimits bound what a round reads.
type SkillLimits struct {
	MaxSkills, MaxFiles, MaxFileBytes, MaxSkillBytes, MaxRoundBytes, MaxDepth, MaxEntries, MaxSearchDirs, MaxProjects int
}

// DefaultSkillLimits: 200 skills, 300 files each, 512 KB a text file, 4 MB a skill, 64 MB a round, 8 folders deep,
// 5000 entries in a skill, 4000 folders searched, 500 projects.
func DefaultSkillLimits() SkillLimits {
	return SkillLimits{MaxSkills: 200, MaxFiles: 300, MaxFileBytes: 512 << 10, MaxSkillBytes: 4 << 20, MaxRoundBytes: 64 << 20,
		MaxDepth: 8, MaxEntries: 5000, MaxSearchDirs: 4000, MaxProjects: 500}
}

// SkillsFound is what a search found.
type SkillsFound struct {
	Skills []Skill
	// Left: places this round may not look at (no Full Disk Access), as shown to the user.
	Left []string
	// More: skills beyond the limit, not read.
	More int
}

type skillSpot struct {
	place   SkillPlace
	project string
	spelled string
	real    string
}

func aiLstat(path string) (syscall.Stat_t, bool) {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil {
		return st, false
	}
	return st, true
}

func aiStDir(st syscall.Stat_t) bool  { return st.Mode&syscall.S_IFMT == syscall.S_IFDIR }
func aiStReg(st syscall.Stat_t) bool  { return st.Mode&syscall.S_IFMT == syscall.S_IFREG }
func aiStLink(st syscall.Stat_t) bool { return st.Mode&syscall.S_IFMT == syscall.S_IFLNK }

func aiIsDir(path string) bool {
	st, ok := aiLstat(path)
	return ok && aiStDir(st)
}

func aiIsReg(path string) bool {
	st, ok := aiLstat(path)
	return ok && aiStReg(st)
}

// aiSFDataless: kept only in iCloud, reading it would download it.
const aiSFDataless = 0x40000000

func aiDataless(st syscall.Stat_t) bool { return st.Flags&aiSFDataless != 0 }

// ResolvedPath is path with its links followed one at a time (at most 32 hops), as long as each step stays where this
// round may look; ok false when one leads into a guarded folder or nowhere. "." and ".." are taken out by hand.
func ResolvedPath(path string, ctx *Context) (string, bool) {
	names := func(p string) []string {
		var out []string
		for _, n := range strings.Split(p, "/") {
			if n == "" || n == "." {
				continue
			}
			if n == ".." {
				if len(out) > 0 {
					out = out[:len(out)-1]
				}
			} else {
				out = append(out, n)
			}
		}
		return out
	}
	todo, done, hops := names(path), "", 0
	for len(todo) > 0 {
		next := done + "/" + todo[0]
		todo = todo[1:]
		if !ctx.MayLook(next) {
			return "", false
		}
		st, ok := aiLstat(next)
		if !ok {
			return "", false
		}
		if !aiStLink(st) {
			done = next
			continue
		}
		hops++
		if hops > 32 {
			return "", false
		}
		dest, err := os.Readlink(next)
		if err != nil {
			return "", false
		}
		if strings.HasPrefix(dest, "/") {
			todo = append(names(dest), todo...)
		} else {
			todo = append(names(done+"/"+dest), todo...)
		}
		done = ""
	}
	if done == "" {
		return "/", true
	}
	return done, true
}

// aiSortedUnique is a set of strings in order.
func aiSortedUnique(a []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func (ctx *Context) noFullDiskAccess() bool { return ctx.FullDiskAccess != nil && !*ctx.FullDiskAccess }

// aiProjectFolders are the projects of a project folder: its folders (not links), by path, at most max.
func aiProjectFolders(root string, max int) []string {
	var projects []string
	for _, c := range Children(root) {
		if aiIsDir(c) {
			projects = append(projects, c)
		}
	}
	sort.Strings(projects)
	if len(projects) > max {
		projects = projects[:max]
	}
	return projects
}

// skillSpots are the folders holding skills, each once (by its real location), in the order of places, then by path.
func skillSpots(ctx *Context, places []SkillPlace, limits SkillLimits) ([]skillSpot, []string) {
	type base struct {
		place   SkillPlace
		project string
		dir     string
	}
	var bases []base
	for _, p := range places {
		if p.Scope == ScopePersonal {
			bases = append(bases, base{p, "", filepath.Join(ctx.Home, p.Path)})
		}
	}
	var left []string
	var projectPlaces []SkillPlace
	for _, p := range places {
		if p.Scope == ScopeProject {
			projectPlaces = append(projectPlaces, p)
		}
	}
	if len(projectPlaces) > 0 {
		for _, root := range ctx.ProjectRoots {
			if !ctx.MayLook(root) {
				left = append(left, ctx.Shown(root)+" 里项目的 skill")
				continue
			}
			for _, p := range aiProjectFolders(root, limits.MaxProjects) {
				for _, pl := range projectPlaces {
					bases = append(bases, base{pl, p, filepath.Join(p, pl.Path)})
				}
			}
		}
	}
	var out []skillSpot
	seen := map[string]bool{}
	unfollowed := func(spelled string) {
		if ctx.noFullDiskAccess() {
			left = append(left, ctx.Shown(spelled)+" 链接到的 skill")
		}
	}
	type queued struct {
		real, spelled string
		depth         int
	}
	for _, b := range bases {
		st, ok := aiLstat(b.dir)
		if !ok {
			continue
		}
		real := b.dir
		if aiStLink(st) || !ctx.MayLook(b.dir) {
			r, ok := ResolvedPath(b.dir, ctx)
			if !ok {
				unfollowed(b.dir)
				continue
			}
			real = r
		}
		if !aiIsDir(real) {
			continue
		}
		queue := []queued{{real, b.dir, 0}}
		looked := 0
		for len(queue) > 0 && looked < limits.MaxSearchDirs {
			q := queue[0]
			queue = queue[1:]
			looked++
			children := Children(q.real)
			sort.SliceStable(children, func(i, j int) bool { return filepath.Base(children[i]) < filepath.Base(children[j]) })
			for _, child := range children {
				name := filepath.Base(child)
				if name == ".git" || name == "node_modules" {
					continue
				}
				cst, ok := aiLstat(child)
				if !ok {
					continue
				}
				childSpelled := q.spelled + "/" + name
				target := child
				if aiStLink(cst) {
					r, ok := ResolvedPath(child, ctx)
					if !ok {
						unfollowed(childSpelled)
						continue
					}
					target = r
				}
				if !ctx.MayLook(target) || !aiIsDir(target) {
					continue
				}
				canonical := Canonical(target)
				if seen[canonical] {
					continue
				}
				seen[canonical] = true
				if aiIsReg(filepath.Join(target, "SKILL.md")) {
					out = append(out, skillSpot{b.place, b.project, childSpelled, canonical})
				} else if q.depth+1 < b.place.Depth {
					queue = append(queue, queued{target, childSpelled, q.depth + 1})
				}
			}
		}
	}
	return out, aiSortedUnique(left)
}

// FindSkills are the skills on this Mac, read within limits. read false: only the files are listed (what the virus
// scan needs).
func FindSkills(ctx *Context, places []SkillPlace, limits SkillLimits, read bool) SkillsFound {
	spots, left := skillSpots(ctx, places, limits)
	budget := limits.MaxRoundBytes
	var skills []Skill
	for i, s := range spots {
		if i >= limits.MaxSkills || ctx.IsCancelled() {
			break
		}
		skills = append(skills, readSkill(s, limits, &budget, read))
	}
	more := len(spots) - limits.MaxSkills
	if more < 0 {
		more = 0
	}
	return SkillsFound{Skills: skills, Left: left, More: more}
}

// SkillFiles are the regular files of the skills on this Mac, by their real paths, at most limit (for the virus scan).
func SkillFiles(ctx *Context, limit int) []string {
	var out []string
	for _, s := range FindSkills(ctx, SkillPlaces, DefaultSkillLimits(), false).Skills {
		for _, f := range s.Files {
			if f.Unread != "" && f.Unread != UnreadTooLarge && f.Unread != UnreadBudget {
				continue
			}
			if len(out) >= limit {
				return out
			}
			out = append(out, s.RealFolder+"/"+f.Path)
		}
	}
	return out
}

var skillLockfiles = map[string]bool{"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "poetry.lock": true,
	"uv.lock": true, "Cargo.lock": true, "Gemfile.lock": true, "composer.lock": true, "bun.lockb": true, "Pipfile.lock": true, "go.sum": true}

func aiHashParts(h hash.Hash, parts ...string) {
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
}

// aiDecodeUTF8 is Foundation's String(data:encoding: .utf8): ok false for bytes that are not UTF-8; one leading byte
// order mark dropped.
func aiDecodeUTF8(b []byte) (string, bool) {
	if !utf8.Valid(b) {
		return "", false
	}
	s := string(b)
	return strings.TrimPrefix(s, "\uFEFF"), true
}

func readSkill(s skillSpot, limits SkillLimits, budget *int, read bool) Skill {
	root := s.real
	var files []SkillFile
	unlisted, used, entries := 0, 0, 0
	h := sha256.New()
	var walk func(dir, rel string, depth int)
	walk = func(dir, rel string, depth int) {
		if !mayOpen(dir) {
			return
		}
		f, err := os.Open(dir)
		if err != nil {
			return
		}
		names, err := f.Readdirnames(-1)
		f.Close()
		if err != nil && len(names) == 0 {
			return
		}
		sort.Strings(names)
		for _, name := range names {
			entries++
			if entries > limits.MaxEntries {
				unlisted++
				continue
			}
			if name == ".DS_Store" || name == ".git" {
				continue
			}
			path := dir + "/" + name
			relPath := name
			if rel != "" {
				relPath = rel + "/" + name
			}
			st, ok := aiLstat(path)
			if !ok {
				continue
			}
			if aiStLink(st) {
				// Where it points, from the link itself: one inside is walked as what it points at; one outside is not
				// followed.
				dest, _ := os.Readlink(path)
				target := dest
				if !strings.HasPrefix(dest, "/") {
					target = dir + "/" + dest
				}
				normal := aiNormalized(target)
				if normal == root || strings.HasPrefix(normal, root+"/") {
					continue
				}
				files = append(files, SkillFile{Path: relPath, Kind: FileKindOther, Unread: UnreadLinkOutside})
				aiHashParts(h, relPath, "link", dest)
				continue
			}
			if aiStDir(st) {
				if _, venv := aiLstat(path + "/pyvenv.cfg"); name == "node_modules" || name == "site-packages" || venv {
					files = append(files, SkillFile{Path: relPath + "/", Kind: FileKindOther, Unread: UnreadDependencies})
					aiHashParts(h, relPath, "deps")
				} else if depth >= limits.MaxDepth {
					files = append(files, SkillFile{Path: relPath + "/", Kind: FileKindOther, Unread: UnreadTooDeep})
					aiHashParts(h, relPath, "deep")
				} else {
					walk(path, relPath, depth+1)
				}
				continue
			}
			if !aiStReg(st) {
				continue
			}
			if len(files) >= limits.MaxFiles {
				unlisted++
				continue
			}
			// Python's own cache of a source file that is here: the source is what is read.
			if strings.HasSuffix(name, ".pyc") && aiNSLast(rel) == "__pycache__" {
				if stems := strings.FieldsFunc(name, func(r rune) bool { return r == '.' }); len(stems) > 0 && aiIsReg(dir+"/../"+stems[0]+".py") {
					continue
				}
			}
			size := st.Size
			modified := strconv.FormatInt(st.Mtimespec.Sec, 10)
			if !read {
				files = append(files, SkillFile{Path: relPath, Bytes: size, Kind: FileKindOther})
				continue
			}
			if aiDataless(st) {
				files = append(files, SkillFile{Path: relPath, Bytes: size, Kind: skillFileKind(name, nil), Unread: UnreadICloud})
				aiHashParts(h, relPath, strconv.FormatInt(size, 10), modified)
				continue
			}
			var head []byte
			var headOK bool
			if *budget > 0 {
				head, headOK = aiReadHead(path, 4096)
			}
			if !headOK {
				why := UnreadBudget
				if *budget > 0 {
					why = UnreadUnreadable
				}
				files = append(files, SkillFile{Path: relPath, Bytes: size, Kind: skillFileKind(name, nil), Unread: why})
				aiHashParts(h, relPath, strconv.FormatInt(size, 10), modified)
				continue
			}
			*budget -= len(head)
			k := skillFileKind(name, head)
			file := SkillFile{Path: relPath, Bytes: size, Kind: k}
			if k == FileKindText || k == FileKindScript {
				if size > int64(limits.MaxFileBytes) {
					file.Unread = UnreadTooLarge
				} else if int64(used)+size > int64(limits.MaxSkillBytes) || int64(*budget) < size {
					file.Unread = UnreadBudget
				} else if data, ok := aiReadHead(path, int(size)); ok {
					used += len(data)
					*budget -= len(data)
					if t, ok := aiDecodeUTF8(data); ok {
						file.Text, file.HasText = t, true
					} else {
						file.Kind = FileKindBinary
					}
				} else {
					file.Unread = UnreadUnreadable
				}
			}
			files = append(files, file)
			if file.HasText {
				aiHashParts(h, relPath, strconv.FormatInt(size, 10), file.Text)
			} else {
				aiHashParts(h, relPath, strconv.FormatInt(size, 10), modified, base64.StdEncoding.EncodeToString(head))
			}
		}
	}
	walk(root, "", 0)

	skillMD := ""
	for _, f := range files {
		if f.Path == "SKILL.md" {
			skillMD = f.Text
			break
		}
	}
	fm := parseFrontmatter(skillMD)
	name := ""
	if v, ok := fm.fields["name"]; ok && v.hasText {
		name = v.text
	}
	sum := h.Sum(nil)
	digest := hex.EncodeToString(sum[:8])
	metadata := map[string]string{}
	for k, v := range fm.fields {
		if k == "name" || k == "description" || k == "allowed-tools" {
			continue
		}
		if v.hasText {
			metadata[k] = v.text
		}
	}
	sk := Skill{Agent: s.place.Agent, Scope: s.place.Scope, Place: s.place.Path, Project: s.project, Folder: s.spelled,
		RealFolder: root, Name: name, Metadata: metadata, Instructions: fm.body, InstructionsLine: fm.bodyLine, Files: files,
		Unlisted: unlisted, Digest: digest}
	if sk.Name == "" {
		sk.Name = filepath.Base(s.spelled)
	}
	if v, ok := fm.fields["description"]; ok && v.hasText {
		sk.Description = v.text
	}
	tools, ok := fm.fields["allowed-tools"]
	if !ok {
		tools, ok = fm.fields["allowed_tools"]
	}
	if ok {
		sk.AllowedTools, sk.HasAllowedTools = skillToolList(tools), true
	}
	return sk
}

// aiNormalized is a path with "." and ".." taken out by hand (Foundation's standardizing turns /private/var back
// into the link /var).
func aiNormalized(path string) string {
	var out []string
	for _, n := range strings.Split(path, "/") {
		if n == "" || n == "." {
			continue
		}
		if n == ".." {
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		} else {
			out = append(out, n)
		}
	}
	return "/" + strings.Join(out, "/")
}

// aiReadHead is up to limit bytes from the start of a regular file, not following a link and not waiting on a pipe.
func aiReadHead(path string, limit int) ([]byte, bool) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if limit == 0 {
		return []byte{}, true
	}
	buf := make([]byte, limit)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		if n == 0 {
			return nil, false
		}
	}
	return buf[:n], true
}

// aiNSExt is NSString's pathExtension of a name: what follows the last dot, "" when that is nothing, has a space,
// or the dot starts the name.
func aiNSExt(name string) string {
	name = filepath.Base(name)
	i := strings.LastIndex(name, ".")
	if i <= 0 || i == len(name)-1 {
		return ""
	}
	ext := name[i+1:]
	if strings.ContainsAny(ext, " ") {
		return ""
	}
	return ext
}

// aiNSLast is NSString's lastPathComponent: "" for "", "/" for "/".
func aiNSLast(p string) string {
	if p == "" {
		return ""
	}
	t := strings.TrimRight(p, "/")
	if t == "" {
		return "/"
	}
	if i := strings.LastIndex(t, "/"); i >= 0 {
		return t[i+1:]
	}
	return t
}

func aiSet(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

var (
	compiledExt = aiSet("pyc", "pyo", "class", "jar", "war", "wasm", "so", "dylib", "o", "a", "node", "exe", "dll",
		"scpt", "scptd", "bundle", "framework", "dex", "elc", "beam")
	archiveExt = aiSet("zip", "tar", "gz", "tgz", "bz2", "tbz", "xz", "txz", "zst", "7z", "rar", "dmg", "pkg", "mpkg",
		"whl", "egg", "iso", "xip", "lz", "lzma", "cpio", "apk", "crx", "vsix", "xpi", "deb", "rpm")
	otherExt = aiSet("png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "icns", "tif", "tiff", "heic", "avif", "psd",
		"pdf", "ttf", "otf", "woff", "woff2", "eot", "mp3", "mp4", "m4a", "wav", "mov", "ogg", "webm",
		"flac", "aac", "docx", "xlsx", "pptx", "odt", "ods", "odp", "key", "numbers", "pages", "sketch", "fig")
	scriptExt = aiSet("sh", "bash", "zsh", "fish", "ksh", "csh", "command", "tool", "py", "pyw", "js", "mjs", "cjs", "ts",
		"mts", "cts", "tsx", "jsx", "rb", "pl", "pm", "php", "ps1", "psm1", "lua", "swift", "go", "rs",
		"applescript", "jxa", "tcl", "r", "jl", "groovy", "kts", "scala", "java", "c", "cc", "cpp", "m", "mm",
		"bat", "cmd", "vbs", "awk", "sed", "nu", "zx")
)

// skillFileKind is what a file is, from its name and its first bytes (empty: name only).
func skillFileKind(name string, head []byte) SkillFileKind {
	ext := strings.ToLower(aiNSExt(name))
	b := head
	if len(b) > 8 {
		b = b[:8]
	}
	starts := func(m ...byte) bool { return len(b) >= len(m) && string(b[:len(m)]) == string(m) }
	if otherExt[ext] {
		return FileKindOther
	}
	if starts(0xFE, 0xED, 0xFA, 0xCE) || starts(0xFE, 0xED, 0xFA, 0xCF) || starts(0xCE, 0xFA, 0xED, 0xFE) || starts(0xCF, 0xFA, 0xED, 0xFE) ||
		starts(0xCA, 0xFE, 0xBA, 0xBE) || starts(0x7F, 0x45, 0x4C, 0x46) || starts(0x00, 0x61, 0x73, 0x6D) ||
		compiledExt[ext] || (starts(0x4D, 0x5A) && (ext == "exe" || ext == "dll" || ext == "sys" || ext == "com" || ext == "")) {
		return FileKindCompiled
	}
	if archiveExt[ext] || starts(0x50, 0x4B, 0x03, 0x04) || starts(0x1F, 0x8B) || starts(0x42, 0x5A, 0x68) || starts(0xFD, 0x37, 0x7A, 0x58, 0x5A) ||
		starts(0x37, 0x7A, 0xBC, 0xAF) || starts(0x52, 0x61, 0x72, 0x21) || starts(0x78, 0x61, 0x72, 0x21) {
		return FileKindArchive
	}
	if len(head) == 0 {
		if scriptExt[ext] {
			return FileKindScript
		}
		return FileKindText
	}
	cut := len(head) - 3
	if cut < 0 {
		cut = 0
	}
	if strings.IndexByte(string(head), 0) >= 0 || (!utf8.Valid(head) && !utf8.Valid(head[:cut])) {
		return FileKindBinary
	}
	if scriptExt[ext] || starts('#', '!') {
		return FileKindScript
	}
	return FileKindText
}

// ---------------------------------------------------------------- front matter

type fmValue struct {
	text    string
	hasText bool
	list    []string
	hasList bool
}

type skillFrontmatter struct {
	fields   map[string]fmValue
	body     string
	bodyLine int
}

// aiIsWS is CharacterSet.whitespaces: Unicode general category Zs and tab.
func isWS(r rune) bool { return r == '\t' || unicode.Is(unicode.Zs, r) }

// aiIsWSNL is CharacterSet.whitespacesAndNewlines: Z*, U+000A–U+000D and U+0085.
func isWSNL(r rune) bool {
	return (r >= 0x0a && r <= 0x0d) || r == 0x85 || r == '\t' || unicode.Is(unicode.Z, r)
}

func aiTrimWS(s string) string   { return strings.TrimFunc(s, isWS) }
func aiTrimWSNL(s string) string { return strings.TrimFunc(s, isWSNL) }

func aiFirstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

// parseFrontmatter reads the YAML front matter's top-level fields (plain, quoted and block values, lists) and what
// follows it. Only what a skill's front matter needs; nested maps are skipped.
func parseFrontmatter(text string) skillFrontmatter {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	if len(lines) > 0 {
		lines[0] = strings.TrimPrefix(lines[0], "\uFEFF")
	}
	end := -1
	if aiTrimWS(lines[0]) == "---" {
		for i := 1; i < len(lines); i++ {
			if t := aiTrimWS(lines[i]); t == "---" || t == "..." {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return skillFrontmatter{fields: map[string]fmValue{}, body: text, bodyLine: 1}
	}
	fields := map[string]fmValue{}
	unquote := func(s string) string {
		t := []rune(aiTrimWS(s))
		if len(t) >= 2 && ((t[0] == '"' && t[len(t)-1] == '"') || (t[0] == '\'' && t[len(t)-1] == '\'')) {
			return string(t[1 : len(t)-1])
		}
		return string(t)
	}
	i := 1
	for i < end {
		line := lines[i]
		i++
		if line == "" {
			continue
		}
		f := aiFirstRune(line)
		colon := strings.Index(line, ":")
		if f == ' ' || f == '\t' || f == '#' || colon < 0 {
			continue
		}
		key := aiTrimWS(line[:colon])
		value := aiTrimWS(line[colon+1:])
		if strings.HasPrefix(value, "#") {
			value = ""
		}
		var block []string
		for i < end && (lines[i] == "" || lines[i][0] == ' ' || lines[i][0] == '\t') {
			block = append(block, lines[i])
			i++
		}
		switch {
		case strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">"):
			parts := make([]string, len(block))
			for j, b := range block {
				parts[j] = aiTrimWS(b)
			}
			sep := " "
			if strings.HasPrefix(value, "|") {
				sep = "\n"
			}
			fields[key] = fmValue{text: aiTrimWSNL(strings.Join(parts, sep)), hasText: true}
		case value == "":
			var items []string
			for _, b := range block {
				t := aiTrimWS(b)
				if strings.HasPrefix(t, "- ") || t == "-" {
					items = append(items, unquote(t[1:]))
				}
			}
			if len(items) > 0 {
				fields[key] = fmValue{list: items, hasList: true}
			}
		case strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]"):
			parts := skillSplitOutside(value[1 : len(value)-1])
			for j, p := range parts {
				parts[j] = unquote(p)
			}
			fields[key] = fmValue{list: parts, hasList: true}
		default:
			more := []string{value}
			for _, b := range block {
				if t := aiTrimWS(b); t != "" {
					more = append(more, t)
				}
			}
			fields[key] = fmValue{text: unquote(strings.Join(more, " ")), hasText: true}
		}
	}
	return skillFrontmatter{fields: fields, body: strings.Join(lines[end+1:], "\n"), bodyLine: end + 2}
}

// skillSplitOutside splits at commas outside parentheses and quotes.
func skillSplitOutside(s string) []string {
	var out []string
	var cur []rune
	depth := 0
	var quote rune
	for _, c := range s {
		if quote != 0 {
			cur = append(cur, c)
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
			cur = append(cur, c)
		case '(', '[':
			depth++
			cur = append(cur, c)
		case ')', ']':
			depth--
			cur = append(cur, c)
		case ',':
			if depth == 0 {
				out = append(out, string(cur))
				cur = nil
			} else {
				cur = append(cur, c)
			}
		default:
			cur = append(cur, c)
		}
	}
	out = append(out, string(cur))
	var kept []string
	for _, p := range out {
		if t := aiTrimWS(p); t != "" {
			kept = append(kept, t)
		}
	}
	return kept
}

// skillToolList is allowed-tools as one entry per tool: a list, or a line of them separated by commas (or by spaces, when
// no entry has parentheses).
func skillToolList(v fmValue) []string {
	out := []string{}
	if v.hasList {
		for _, l := range v.list {
			out = append(out, skillSplitOutside(l)...)
		}
		return out
	}
	for _, p := range skillSplitOutside(v.text) {
		if strings.Contains(p, "(") {
			out = append(out, p)
			continue
		}
		for _, w := range strings.Split(p, " ") {
			if w != "" {
				out = append(out, w)
			}
		}
	}
	return out
}
