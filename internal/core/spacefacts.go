package core

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// Small facts the space rules share (the space group's own; other groups may have theirs).

// spaceExt is a name's extension as Foundation's URL.pathExtension gives it: after the last dot, none for a name that
// starts with its only dot (".env") or ends with one, nor one with a space in it ("a.b c").
func spaceExt(name string) string {
	name = strings.TrimRight(name, "/")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return ""
	}
	ext := name[i+1:]
	if strings.ContainsRune(ext, ' ') {
		return ""
	}
	return ext
}

// spaceIsDir says whether path is a folder itself (a link to one is not), as URL's isDirectory resource value says.
func spaceIsDir(path string) bool {
	e, ok := Item(path)
	return ok && e.IsDir
}

// spaceStandardized is a path as Foundation's standardizedFileURL spells it: cleaned, and a leading /private dropped
// when the place without it exists.
func spaceStandardized(path string) string {
	p := filepath.Clean(path)
	if strings.HasPrefix(p, "/private/") {
		if _, err := os.Lstat(strings.TrimPrefix(p, "/private")); err == nil {
			return strings.TrimPrefix(p, "/private")
		}
	}
	return p
}

// StalePackageExtensions are packages whose app may not be installed here (then the system does not know them as
// packages), and the common ones.
var StalePackageExtensions = spaceSet("app", "bundle", "framework", "plugin", "photoslibrary", "musiclibrary", "tvlibrary",
	"imovielibrary", "fcpbundle", "logicx", "band", "lrdata", "lrlibrary", "pvm", "vmwarevm", "utm", "sparsebundle", "rtfd",
	"xcarchive", "pages", "numbers", "key")

// spaceHasBundleBit says whether Finder shows the folder as one file because of its bundle bit (kHasBundle in
// com.apple.FinderInfo).
// TODO(cgo-free): Launch Services also knows folders as packages by the types installed apps declare; without it only
// StalePackageExtensions and the bundle bit are known.
func spaceHasBundleBit(path string) bool {
	var buf [32]byte
	size, err := xattrFollowing(path, "com.apple.FinderInfo", buf[:])
	if err != nil || size < 10 {
		return false
	}
	flags := uint16(buf[8])<<8 | uint16(buf[9])
	return flags&0x2000 != 0
}

// spaceIsPackage says whether a folder is one Finder shows as one file (an app, a photo library). Only one with an
// extension can be.
func spaceIsPackage(path string) bool {
	ext := spaceExt(path)
	if ext == "" {
		return false
	}
	return StalePackageExtensions[strings.ToLower(ext)] || spaceHasBundleBit(path)
}

// spaceCompareVersions compares dotted versions by their numbers: -1, 0, 1; ok false when either has none.
func spaceCompareVersions(a, b string) (int, bool) {
	nums := func(s string) []int {
		var out []int
		for _, f := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsNumber(r) }) {
			if n, err := strconv.Atoi(f); err == nil {
				out = append(out, n)
			}
		}
		return out
	}
	x, y := nums(a), nums(b)
	if len(x) == 0 || len(y) == 0 {
		return 0, false
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		p, q := 0, 0
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			if p < q {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func spaceSet(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}
