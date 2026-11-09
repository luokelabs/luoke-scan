package core

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Canonical is one spelling per place, as Foundation's resolvingSymlinksInPath writes it: links resolved, and a
// leading /private dropped from /private/tmp, /private/var, /private/etc when the place without it exists.
func Canonical(path string) string {
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		r = resolveExisting(path)
	}
	for _, d := range []string{"/private/tmp", "/private/var", "/private/etc"} {
		if r == d || strings.HasPrefix(r, d+"/") {
			short := strings.TrimPrefix(r, "/private")
			if _, err := os.Lstat(short); err == nil {
				return short
			}
		}
	}
	return r
}

// resolveExisting resolves the links of the longest part of path that exists and keeps the rest as written.
func resolveExisting(path string) string {
	path = filepath.Clean(path)
	rest := ""
	for p := path; p != "/" && p != "."; p = filepath.Dir(p) {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		rest = filepath.Join(filepath.Base(p), rest)
	}
	return path
}

// Place is Canonical, the same whether or not the thing is still there (no leading /private either way): what names
// a finding must not change when the user moves it away.
func Place(path string) string {
	c := Canonical(path)
	for _, d := range []string{"/private/tmp", "/private/var", "/private/etc"} {
		if c == d || strings.HasPrefix(c, d+"/") {
			return strings.TrimPrefix(c, "/private")
		}
	}
	return c
}

// HomeRelative is ~/… for a path under home (compared component by component, /tmp and /private/tmp alike);
// anything else as it was.
func HomeRelative(path, home string) string {
	parts := func(p string) []string {
		c := strings.Split(strings.TrimPrefix(Place(p), "/"), "/")
		return c
	}
	h := parts(home)
	dir, base := filepath.Dir(path), filepath.Base(path)
	u := append(parts(dir), base)
	if path == "/" {
		u = []string{""}
	}
	if len(u) == len(h) && strings.Join(u, "/") == strings.Join(h, "/") {
		return "~"
	}
	if len(u) > len(h) && strings.Join(u[:len(h)], "/") == strings.Join(h, "/") {
		return "~/" + strings.Join(u[len(h):], "/")
	}
	return path
}

// Standardized is a path as Foundation's standardizedFileURL writes it: "." and ".." taken out, and a leading /private
// dropped when what is left exists (the Swift version's spelling of the paths it was given: --fixture, --home).
func Standardized(p string) string {
	c := filepath.Clean(p)
	if strings.HasPrefix(c, "/private/") {
		if short := strings.TrimPrefix(c, "/private"); Exists(short) {
			return short
		}
	}
	return c
}

// Exists says whether something is there (following a link, as FileManager.fileExists does).
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Children are a folder's direct children in the order the file system gives them; none when it cannot be listed.
func Children(dir string) []string {
	l, _ := List(dir)
	return l
}

// List is a folder's direct children in the file system's order, or ok false when it cannot be listed (not "empty":
// a cache must not forget what is in it). Spelled under the folder's real path, as contentsOfDirectory(at:) has them
// (/private/var/folders/x/y for /var/folders/x/y).
func List(dir string) ([]string, bool) {
	if !mayOpen(dir) {
		return nil, false
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil && len(ents) == 0 {
		return nil, false
	}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, true
}

// Modified is the content modification time, following a link; ok false when it cannot be read.
func Modified(path string) (time.Time, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return st.ModTime(), true
}

// Inode of the item itself (not following a link); 0 when it cannot be read.
func Inode(path string) uint64 {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil {
		return 0
	}
	return st.Ino
}
