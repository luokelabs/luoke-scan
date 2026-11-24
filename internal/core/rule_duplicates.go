package core

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

func init() { Register("space.duplicates", NewDuplicateRule) }

// DuplicateRule finds large files kept more than once with the same contents, in the folders people put their own
// files in. What a set wastes is what its copies hold on their own (APFS: a clone holds nothing of its own, so clones
// are no waste). Contents are compared by SHA-256, read only for files whose size and first and last 64 KiB already
// match, and remembered per file (path, inode, size, modification time) so an unchanged file is not read again.
type DuplicateRule struct {
	Places   []string
	MinBytes int64
	// MinWaste: a set is reported when its copies hold at least this much of their own.
	MinWaste int64
	MaxSets  int
	// MaxFiles are the files looked at per folder; past that the folder is reported as not looked through.
	MaxFiles int
}

// NewDuplicateRule makes the rule; for a fake home files and waste count from 1 MiB.
func NewDuplicateRule(l *Layout, f *Fakes) Rule {
	r := &DuplicateRule{Places: []string{"Downloads", "Desktop", "Documents", "Movies", "Music", "Pictures"},
		MinBytes: 10 << 20, MinWaste: 50 << 20, MaxSets: 20, MaxFiles: 200_000}
	if l != nil {
		r.MinBytes, r.MinWaste = 1<<20, 1<<20
	}
	return r
}

// duplicatesLeftOut follows the places in the reason the rule gives for those it left out (NotLooked).
const duplicatesLeftOut = " 里的重复文件"

// DuplicatesNever: what the rule never compares, as codes (data/category's compared.never), each left out in files:
// hidden files and folders, node_modules, packages (an app, a photo library: one file in Finder), links, a file with
// another name too (a hard link), one kept only in iCloud, and what is on another volume mounted inside a folder.
var DuplicatesNever = []string{"hidden", "node_modules", "package", "symlink", "hard-link", "icloud-only", "other-volume"}

// DuplicatesNotLooked are the places a round's rule left out for want of Full Disk Access, read back from the reason it
// was skipped with: its own (NotLooked), or one an interrupted round carried over with an earlier round's findings.
// nil when the reason names none.
func DuplicatesNotLooked(reason string) []string {
	_, rest, ok := strings.Cut(reason, NoAccessMark+"，")
	if !ok {
		return nil
	}
	places, _, ok := strings.Cut(rest, duplicatesLeftOut)
	if !ok || places == "" {
		return nil
	}
	return strings.Split(places, "、")
}

func (r *DuplicateRule) ID() string { return "space.duplicates" }
func (r *DuplicateRule) Emits() []string {
	return []string{"space.duplicates", "space.duplicates-partial"}
}

type dupFile struct {
	path     string
	size     int64
	inode    uint64
	modified float64
	born     int64
}

// FileHash is a file's SHA-256 as it was when read: still good while inode, size and modification time are.
type FileHash struct {
	Inode    uint64  `json:"inode"`
	Size     int64   `json:"size"`
	Modified float64 `json:"modified"`
	Hash     string  `json:"hash"`
}

func fileHashes(s *Store) Table[FileHash] { return NewTable[FileHash](s, "file_hashes", 1) }

const sfDataless = 0x40000000

// files are the files to compare, and which places were looked through completely (only under those is a remembered
// hash of a file no longer found forgotten). A file that takes less than MinBytes on disk (compressed, sparse, kept
// only in iCloud) frees less than that either way.
func (r *DuplicateRule) files(ctx *Context) (out []dupFile, complete []string) {
	for _, place := range r.Places {
		dir := filepath.Join(ctx.Home, place)
		if !ctx.MayLook(dir) {
			continue
		}
		seen := 0
		whole := Tree(dir, func(e Entry) bool {
			// Not into node_modules, hidden folders or packages (an app, a photo library: Finder shows each as one file).
			return !strings.HasPrefix(e.Name, ".") && e.Name != "node_modules" && !spaceIsPackage(e.Path)
		}, func(e Entry) bool {
			seen++
			if seen > r.MaxFiles || ctx.IsCancelled() {
				return false
			}
			if e.IsDir || e.IsLink || e.Bytes < r.MinBytes || strings.HasPrefix(e.Name, ".") {
				return true
			}
			var st syscall.Stat_t
			// Not: another name of a file (a hard link: deleting one frees nothing), one kept only in iCloud (reading it
			// would download it).
			if syscall.Lstat(e.Path, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size < r.MinBytes ||
				st.Nlink != 1 || st.Flags&sfDataless != 0 {
				return true
			}
			out = append(out, dupFile{path: e.Path, size: st.Size, inode: st.Ino,
				modified: float64(st.Mtimespec.Sec) + float64(st.Mtimespec.Nsec)/1e9, born: st.Birthtimespec.Sec})
			return true
		})
		if ctx.IsCancelled() {
			return out, complete
		}
		if whole {
			complete = append(complete, place)
		}
	}
	return out, complete
}

// dupGroups groups xs by key, each group in the order of xs, the groups in the order their first member came.
func dupGroups(xs []dupFile, key func(dupFile) string) [][]dupFile {
	index := map[string]int{}
	var out [][]dupFile
	for _, x := range xs {
		k := key(x)
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], x)
	}
	return out
}

func (r *DuplicateRule) Run(ctx *Context) ([]Finding, error) {
	all, complete := r.files(ctx)
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}
	var table Table[FileHash]
	known := map[string]FileHash{}
	if ctx.Store != nil {
		table = fileHashes(ctx.Store)
		known = table.Load()
	}
	save := func(set map[string]FileHash, del []string) {
		if ctx.Store != nil {
			table.Apply(set, del, false)
		}
	}
	fresh := map[string]FileHash{}
	var sets [][]dupFile
	unique := 0
	for _, group := range dupGroups(all, func(f dupFile) string { return strconv.FormatInt(f.size, 10) }) {
		if len(group) < 2 {
			continue
		}
		bySample := dupGroups(group, func(f dupFile) string {
			if s, ok := fileSample(f.path, f.size); ok {
				return s
			}
			unique++
			return "unreadable " + strconv.Itoa(unique)
		})
		for _, g := range bySample {
			if len(g) < 2 {
				continue
			}
			var hashed []dupFile
			hashes := map[string]string{}
			for _, f := range g {
				if ctx.IsCancelled() {
					save(fresh, nil) // what was read this round is not read again
					return nil, Skip(Interrupted)
				}
				hash := ""
				if k, ok := known[f.path]; ok && k.Inode == f.inode && k.Size == f.size && k.Modified == f.modified {
					hash = k.Hash
				} else if h, ok := fileDigest(f.path, ctx.IsCancelled); ok {
					hash = h
				} else {
					continue
				}
				fresh[f.path] = FileHash{Inode: f.inode, Size: f.size, Modified: f.modified, Hash: hash}
				hashes[f.path] = hash
				hashed = append(hashed, f)
			}
			for _, s := range dupGroups(hashed, func(f dupFile) string { return hashes[f.path] }) {
				if len(s) > 1 {
					sets = append(sets, s)
				}
			}
		}
	}
	var looked []string
	for _, p := range complete {
		looked = append(looked, Canonical(filepath.Join(ctx.Home, p))+"/")
	}
	var gone []string
	for k := range known {
		if _, ok := fresh[k]; ok || !ctx.MayLook(k) {
			continue
		}
		c := Canonical(k)
		for _, l := range looked {
			if strings.HasPrefix(c, l) {
				gone = append(gone, k)
				break
			}
		}
	}
	save(fresh, gone)
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}

	var out []Finding
	// One spelling for both sides.
	downloads := Canonical(filepath.Join(ctx.Home, "Downloads")) + "/"
	inDownloads := func(p string) bool { return strings.HasPrefix(Canonical(p), downloads) }
	for _, set := range sets {
		// Kept: one outside Downloads if there is one, then the oldest, then the shortest path.
		ordered := append([]dupFile(nil), set...)
		sort.SliceStable(ordered, func(i, j int) bool {
			a, b := ordered[i], ordered[j]
			da, db := inDownloads(a.path), inDownloads(b.path)
			if da != db {
				return !da
			}
			if a.born != b.born {
				return a.born < b.born
			}
			return utf8.RuneCountInString(a.path) < utf8.RuneCountInString(b.path)
		})
		keep, copies := ordered[0], ordered[1:]
		var waste int64
		for _, c := range copies {
			if b, ok := PrivateBytes(c.path); ok {
				waste += b
			} else {
				waste += c.size
			}
		}
		if waste < r.MinWaste {
			continue
		}
		hash := fresh[keep.path].Hash
		rel := make([]string, len(copies))
		targets := make([]string, len(copies))
		for i, c := range copies {
			rel[i], targets[i] = HomeRelative(c.path, ctx.Home), c.path
		}
		short := hash
		if len(short) > 16 {
			short = short[:16]
		}
		out = append(out, Finding{Rule: "space.duplicates", Category: CatSpace, Severity: Low, Verdict: Confirm, Path: keep.path, Bytes: Size(waste),
			Title: strconv.Itoa(len(set)) + " 份一样的 " + DisplayName(keep.path) + "（每份 " + FormatBytes(keep.size) + "），多占了 " + FormatBytes(waste),
			Evidence: map[string]string{"keep": HomeRelative(keep.path, ctx.Home), "copies": strings.Join(rel, "；"),
				"targets": strings.Join(targets, "\n"), "sha256": short,
				"how": "留一份、把别的移到废纸篓；或者都留着、换成克隆：几份共用一份数据，以后改了其中一份，别的不受影响"},
			Key: "space.duplicates:" + hash})
	}
	var partial, left []string
	for _, p := range r.Places {
		dir := filepath.Join(ctx.Home, p)
		if !ctx.MayLook(dir) {
			left = append(left, p)
			continue
		}
		isComplete := false
		for _, c := range complete {
			isComplete = isComplete || c == p
		}
		if !isComplete && Exists(dir) {
			partial = append(partial, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return bytesOf(out[i]) > bytesOf(out[j]) })
	if len(out) > r.MaxSets {
		out = out[:r.MaxSets]
	}
	if len(partial) > 0 {
		folders := strings.Join(partial, "、")
		out = append(out, Finding{Rule: "space.duplicates-partial", Category: CatSpace, Severity: Low, Verdict: Info,
			Title:    folders + " 里文件太多，重复文件只看了前 " + strconv.Itoa(r.MaxFiles) + " 个",
			Evidence: map[string]string{"folders": folders}})
	}
	if len(left) > 0 {
		return nil, Skip(NotLooked(strings.Join(left, "、")+duplicatesLeftOut), out...)
	}
	return out, nil
}
