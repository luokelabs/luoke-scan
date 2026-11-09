package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// IntelHomebrew is an Intel (x86) Homebrew in /usr/local on an Apple silicon Mac, next to the Apple silicon one in
// /opt/homebrew: the one judgement of whether it may go, which the round that offers it and the password step that
// moves it both make. Swift: IntelHomebrew.swift.
//
// What goes is what Homebrew's own uninstaller takes out of a prefix: the installed packages (Cellar, Caskroom) and
// Homebrew itself (Homebrew), into the Trash, all three or none. The links Homebrew made to them stay where they are,
// so putting the folders back gives the same Homebrew as before; once the folders are gone from the Trash too, a later
// round offers the links (DanglingLinks).
type IntelHomebrew struct {
	UsrLocal, OptHomebrew string
	// Home is the user's home: their shell set-up (brew shellenv) and their Trash; "" not looked at.
	Home string
	// Trash is the user's Trash ("": the home's .Trash).
	Trash string
	// JavaVMs is where JDKs are registered with macOS (a JDK of Homebrew's is a link to its package).
	JavaVMs string
	// Quiet: written to within this long, .git included (brew update): in use.
	Quiet time.Duration
	// Stop is asked during the walk for links (nil: never).
	Stop func() bool
}

// IntelHomebrewFolders are what goes, as Homebrew's uninstaller names them under a prefix.
var IntelHomebrewFolders = []string{"Cellar", "Caskroom", "Homebrew"}

// IntelHomebrewLinkFolders are where Homebrew links what it installs and its own pieces.
var IntelHomebrewLinkFolders = []string{"bin", "etc", "include", "lib", "opt", "sbin", "share", "var", "Frameworks"}

// IntelHomebrewState is Homebrew's own state in the prefix: goes with the links.
const IntelHomebrewState = "var/homebrew"

// intelHomebrewProfiles are shell set-up files that may start this Homebrew (eval "$(/usr/local/bin/brew shellenv)").
var intelHomebrewProfiles = []string{".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile", ".config/fish/config.fish"}

// NewIntelHomebrew is the one in /usr/local beside /opt/homebrew, for a home ("" none).
func NewIntelHomebrew(home string) IntelHomebrew {
	return IntelHomebrew{UsrLocal: "/usr/local", OptHomebrew: "/opt/homebrew", Home: home,
		JavaVMs: "/Library/Java/JavaVirtualMachines", Quiet: 30 * 24 * time.Hour}
}

func appsIsFile(p string) bool {
	var st syscall.Stat_t
	return syscall.Lstat(p, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG
}

// Installed: Homebrew's repository in /usr/local/Homebrew with brew in it. An old layout with the repository at
// /usr/local itself is not taken apart.
func (b IntelHomebrew) Installed() bool {
	return appsIsFile(filepath.Join(b.UsrLocal, "Homebrew/bin/brew"))
}

// Other: the Apple silicon Homebrew is there.
func (b IntelHomebrew) Other() bool { return Exists(filepath.Join(b.OptHomebrew, "bin/brew")) }

// places whose use counts as using this Homebrew, lowercased, each ending in "/": its folders and opt (links into
// Cellar), as written and as their links resolve; and its brew.
func (b IntelHomebrew) places() []string {
	seen := map[string]bool{}
	for _, name := range append(append([]string{}, IntelHomebrewFolders...), "opt") {
		u := filepath.Join(b.UsrLocal, name)
		for _, p := range []string{u, Canonical(u)} {
			seen[strings.ToLower(p)+"/"] = true
		}
	}
	seen[strings.ToLower(filepath.Join(b.UsrLocal, "bin/brew"))] = true
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// runs: a program's own path in one of its places.
func (b IntelHomebrew) runs(path string) bool {
	p := strings.ToLower(path)
	for _, pl := range b.places() {
		if strings.HasPrefix(p, pl) || p+"/" == pl {
			return true
		}
	}
	return false
}

// mentions: text that names one of its places anywhere (a launchd job's sh -c "…", a crontab line).
func (b IntelHomebrew) mentions(text string) bool {
	t := strings.ToLower(text)
	for _, pl := range b.places() {
		if strings.Contains(t, pl) || t+"/" == pl {
			return true
		}
	}
	return false
}

// Blocker is why it may not go now, or "". programs: what the launchd jobs (LaunchdPaths) and the crontab name;
// running: the programs running now.
func (b IntelHomebrew) Blocker(programs, running []string) string {
	if !b.Installed() {
		return "不是 Homebrew 装在 /usr/local/Homebrew 的那种布局"
	}
	if !b.Other() {
		return "Apple 芯片版的 Homebrew 不在：这是唯一的一套"
	}
	for _, p := range programs {
		if b.mentions(p) {
			return "有开机自己运行或定时运行的任务用着它（brew services、crontab 之类）"
		}
	}
	for _, p := range running {
		if b.runs(p) {
			return "有程序正在用它"
		}
	}
	if b.Home != "" {
		for _, f := range intelHomebrewProfiles {
			if data, err := os.ReadFile(filepath.Join(b.Home, f)); err == nil && utf8.Valid(data) && b.mentions(string(data)) {
				return "shell 的配置里还在用它（brew shellenv 之类）"
			}
		}
	}
	for _, u := range Children(b.JavaVMs) {
		if b.runs(Canonical(u)) {
			return "Java 的 JDK 还指着它"
		}
	}
	return ""
}

// Removable are the folders that go, with their size: each there, a folder and not a link, and everything in it
// owner's or root's, with nothing written to within Quiet (.git too); ok false when there is a blocker or when one
// folder does not qualify (then none goes).
func (b IntelHomebrew) Removable(programs, running []string, owner uint32, now time.Time) ([]string, int64, bool) {
	if b.Blocker(programs, running) != "" {
		return nil, 0, false
	}
	since := now.Add(-b.Quiet)
	recent := func(d time.Time) bool { return !d.Before(since) && !d.After(now) }
	var out []string
	var bytes int64
	for _, name := range IntelHomebrewFolders {
		u := filepath.Join(b.UsrLocal, name)
		top, ok := Item(u)
		if !ok {
			continue
		}
		if !top.IsDir || top.Owner != owner || recent(top.Modified) {
			return nil, 0, false
		}
		fine := true
		Tree(u, nil, func(e Entry) bool {
			if (e.Owner != owner && e.Owner != 0) || recent(e.Modified) {
				fine = false
				return false
			}
			bytes += e.Bytes
			return true
		})
		if !fine {
			return nil, 0, false
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, 0, false
	}
	return out, bytes, true
}

// OnlyHere are the packages installed only here, not in the Apple silicon one: what would have to be installed there
// again.
func (b IntelHomebrew) OnlyHere() []string {
	names := func(root, kind string) map[string]bool {
		out := map[string]bool{}
		for _, u := range Children(filepath.Join(root, kind)) {
			if n := filepath.Base(u); !strings.HasPrefix(n, ".") {
				out[n] = true
			}
		}
		return out
	}
	var out []string
	for _, kind := range []string{"Cellar", "Caskroom"} {
		there := names(b.OptHomebrew, kind)
		var here []string
		for n := range names(b.UsrLocal, kind) {
			if !there[n] {
				here = append(here, n)
			}
		}
		sort.Strings(here)
		out = append(out, here...)
	}
	return out
}

// InTrash: something in the user's Trash by one of its folders' names ("Cellar", "Cellar 2"): it may still be put
// back. A Trash that cannot be listed (no Full Disk Access) may hold them too.
func (b IntelHomebrew) InTrash() bool {
	t := b.Trash
	if t == "" {
		if b.Home == "" {
			return false
		}
		t = filepath.Join(b.Home, ".Trash")
	}
	items, ok := List(t)
	if !ok {
		return Exists(t)
	}
	for _, u := range items {
		n := filepath.Base(u)
		for _, f := range IntelHomebrewFolders {
			if n == f || strings.HasPrefix(n, f+" ") {
				return true
			}
		}
	}
	return false
}

// WasHere: a sign an Intel Homebrew was here and its links were left: its own brew link, pointing at nothing now.
func (b IntelHomebrew) WasHere() bool {
	brew := filepath.Join(b.UsrLocal, "bin/brew")
	var st syscall.Stat_t
	return syscall.Lstat(brew, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFLNK && b.IsDangling(brew)
}

// Gone: its folders are gone for good, not in /usr/local, not in the Trash.
func (b IntelHomebrew) Gone() bool {
	if b.InTrash() {
		return false
	}
	for _, f := range IntelHomebrewFolders {
		if _, ok := Item(filepath.Join(b.UsrLocal, f)); ok {
			return false
		}
	}
	return true
}

// DanglingLinks are the links in IntelHomebrewLinkFolders that point into its folders, where nothing is any more.
// Only once the folders are gone for good, and where one was. ok false when Stop said so.
func (b IntelHomebrew) DanglingLinks() ([]string, bool) {
	if !b.WasHere() || !b.Gone() {
		return []string{}, true
	}
	out := []string{}
	n := 0
	stop := func() bool { return b.Stop != nil && b.Stop() }
	for _, name := range IntelHomebrewLinkFolders {
		finished := Tree(filepath.Join(b.UsrLocal, name), nil, func(e Entry) bool {
			n++
			if n%2000 == 0 && stop() {
				return false
			}
			if e.IsLink && b.IsDangling(e.Path) {
				out = append(out, e.Path)
			}
			return true
		})
		if !finished && stop() {
			return nil, false
		}
	}
	return out, true
}

// IsDangling: a link to somewhere in its folders where nothing is, what it says read relative to its own folder.
func (b IntelHomebrew) IsDangling(link string) bool {
	dest, err := os.Readlink(link)
	if err != nil {
		return false
	}
	return b.pointsInto(dest, filepath.Dir(link)) && !Exists(link)
}

// IsDanglingAt is the same for the link name in the open folder dirfd, which is at folder: read and followed from that
// folder, not by path (the folder may have been swapped since).
func (b IntelHomebrew) IsDanglingAt(dirfd int, name, folder string) bool {
	buf := make([]byte, 1025)
	n, err := Readlinkat(dirfd, name, buf[:len(buf)-1])
	if err != nil || n <= 0 {
		return false
	}
	dest := strings.ToValidUTF8(string(buf[:n]), "�")
	var st syscall.Stat_t
	return b.pointsInto(dest, folder) && Fstatat(dirfd, name, &st, 0) == syscall.ENOENT
}

// pointsInto: a link's text, read from folder, lands in one of its folders.
func (b IntelHomebrew) pointsInto(dest, folder string) bool {
	target := dest
	if !strings.HasPrefix(dest, "/") {
		target = filepath.Join(folder, dest)
	}
	lexical := filepath.Clean(target) + "/"
	// /usr/local as written, and as realpath(3) has it.
	bases := []string{filepath.Clean(b.UsrLocal)}
	if r, err := filepath.EvalSymlinks(b.UsrLocal); err == nil {
		bases = append(bases, r)
	}
	for _, f := range IntelHomebrewFolders {
		for _, base := range bases {
			if strings.HasPrefix(lexical, base+"/"+f+"/") {
				return true
			}
		}
	}
	return false
}
