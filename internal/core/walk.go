package core

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// walkLimit, while a round without Full Disk Access runs, says which folders a walk may open. Every rule checks where
// it starts; this stops a walk from an open folder going into a closed one under it (~/Pictures holding the Photos
// library): opening that makes macOS ask the user, and nobody asked for it.
var walkLimit atomic.Pointer[func(string) bool]

func limitWalks(ctx *Context) (done func()) {
	if ctx.FullDiskAccess == nil || *ctx.FullDiskAccess {
		return func() {}
	}
	limit := ctx.MayLook
	walkLimit.Store(&limit)
	return func() { walkLimit.Store(nil) }
}

func mayOpen(dir string) bool {
	limit := walkLimit.Load()
	return limit == nil || (*limit)(dir)
}

// Entry is what a walk sees of one item, without opening it.
type Entry struct {
	Path     string
	Name     string
	IsDir    bool
	IsLink   bool
	Bytes    int64 // allocated size of a file; 0 for folders and links
	Modified time.Time
	InGit    bool // inside a .git folder (or the .git folder itself)
	Device   int32
	Owner    uint32
	Links    uint32 // how many names a file has (more than one: hard links); 0 for folders and links
	// What a clone-aware read (treeClones, spaceListEntries on APFS) says of a file's blocks; zero from any other read.
	Shares  uint8  // sharesSome: may share blocks with another file; sharesAll: shares all of them (a clone nobody changed)
	CloneID uint64 // the data stream's id: the same for files that are whole clones of each other (within a volume)
}

func entryOf(path string, st *syscall.Stat_t) Entry {
	mode := st.Mode & syscall.S_IFMT
	e := Entry{Path: path, Name: filepath.Base(path), IsDir: mode == syscall.S_IFDIR, IsLink: mode == syscall.S_IFLNK,
		Modified: time.Unix(st.Mtimespec.Sec, st.Mtimespec.Nsec), Device: st.Dev, Owner: st.Uid}
	if !e.IsDir && !e.IsLink {
		e.Bytes = st.Blocks * 512
		e.Links = uint32(st.Nlink)
	}
	return e
}

// Item is one item, not following a link; ok false when it is not there.
func Item(path string) (Entry, bool) {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil {
		return Entry{}, false
	}
	return entryOf(path, &st), true
}

// Tree walks under root (not root itself) in the file system's order, not following links and not going into other
// volumes. visit sees every item; enter says whether to go into a folder. Either returning false stops the walk:
// Tree then returns false.
func Tree(root string, enter func(Entry) bool, visit func(Entry) bool) bool {
	return tree(root, false, enter, visit)
}

// treeClones is Tree, with what each file's blocks share (Entry.Shares, CloneID) where the volume says
// (APFS): two more attributes in the same bulk read, no call per file.
func treeClones(root string, enter func(Entry) bool, visit func(Entry) bool) bool {
	return tree(root, true, enter, visit)
}

func tree(root string, clones bool, enter func(Entry) bool, visit func(Entry) bool) bool {
	var st syscall.Stat_t
	if syscall.Lstat(root, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || !mayOpen(root) {
		return true
	}
	read := readFolderStat
	switch fs := volumeType(root); {
	case fs == "apfs" && clones:
		read = readFolderClones
	case fs == "apfs" || fs == "hfs":
		read = readFolder
	}
	return walkFolder(root, st.Dev, false, read, enter, visit)
}

// bulkVolume says whether the volume path is on is one where getattrlistbulk is known to say what lstat says (APFS,
// HFS+). Others go the plain way: on exFAT it gave a just-written file a modification time 10 ms off lstat's; SMB,
// NFS, FAT are not tested. The walk stays on one volume, so this is asked once.
func bulkVolume(path string) bool {
	fs := volumeType(path)
	return fs == "apfs" || fs == "hfs"
}

// volumeType is the name of the file system path is on ("apfs", "hfs", "exfat"...), "" when not known.
func volumeType(path string) string {
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil {
		return ""
	}
	var name []byte
	for _, c := range fs.Fstypename {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	return string(name)
}

func openFolder(path string) (int, error) {
	return syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
}

// walkFolder walks under dir, reading each folder with read (readFolder, or readFolderStat where bulk reads are not
// trusted).
func walkFolder(dir string, device int32, inGit bool, read func(string) ([]Entry, bool), enter func(Entry) bool,
	visit func(Entry) bool) bool {
	entries, ok := read(dir)
	if !ok {
		return true
	}
	var subs []Entry
	for _, e := range entries {
		e.InGit = inGit || e.Name == ".git"
		if !visit(e) {
			return false
		}
		if e.IsDir && mayOpen(e.Path) && (enter == nil || enter(e)) { // 没权限不进受保护的文件夹（看了 macOS 会弹框）
			subs = append(subs, e)
		}
	}
	for _, s := range subs {
		if s.Device != device {
			continue // another volume mounted here (from the entry's own lstat: no second one per folder)
		}
		if !walkFolder(s.Path, device, s.InGit, read, enter, visit) {
			return false
		}
	}
	return true
}

// readFolder is a folder's entries (InGit not set) in the file system's order, as readFolderStat has them, read in
// bulk with getattrlistbulk: one system call for many entries instead of one lstat each. ok false when the folder
// cannot be opened. When getattrlistbulk fails (not supported here, or partway), it is readFolderStat.
func readFolder(dir string) ([]Entry, bool) {
	fd, err := openFolder(dir)
	if err != nil {
		return nil, false
	}
	entries, ok := readBulk(fd, dir, false, nil)
	syscall.Close(fd)
	if !ok {
		return readFolderStat(dir)
	}
	return entries, true
}

// readFolderClones is readFolder, asking also for what each file's blocks share (APFS only: the extended attributes
// are not asked of other file systems). When that read fails it is readFolder: the sizes without the sharing.
func readFolderClones(dir string) ([]Entry, bool) {
	fd, err := openFolder(dir)
	if err != nil {
		return nil, false
	}
	entries, ok := readBulk(fd, dir, true, nil)
	syscall.Close(fd)
	if !ok {
		return readFolder(dir)
	}
	return entries, true
}

// readFolderStat is the plain way: the folder's names, then one lstat each (an entry gone in between is left out).
func readFolderStat(dir string) ([]Entry, bool) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	names, _ := f.Readdirnames(-1)
	f.Close()
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		p := dir + "/" + n
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil {
			continue
		}
		out = append(out, entryOf(p, &st))
	}
	return out, true
}

// What readBulk asks for of each entry: what entryOf takes from lstat, the file flags and a per-entry error. Folders
// are not taken from it: for a folder with a volume mounted on it, or a firmlink (/Users, /Library,
// /System/Library/Caches...), getattrlistbulk describes the folder underneath, not what lstat (and opening it) reaches,
// and nothing it returns tells them apart (ATTR_DIR_MOUNTSTATUS says 0 for them on APFS).
const (
	bulkCommon = unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_NAME | unix.ATTR_CMN_DEVID | unix.ATTR_CMN_OBJTYPE |
		unix.ATTR_CMN_MODTIME | unix.ATTR_CMN_OWNERID | unix.ATTR_CMN_FLAGS | unix.ATTR_CMN_ERROR
	// The link count (u_int32_t, lstat's st_nlink) comes before the allocated size (off_t): the order of their bits.
	bulkFile = unix.ATTR_FILE_LINKCOUNT | unix.ATTR_FILE_ALLOCSIZE
	// With FSOPT_ATTR_CMN_EXTENDED the fork attributes are read as extended common ones (<sys/attr.h>; x/sys names the
	// option, not these): the data stream's id and the flags below. How many whole clones a data stream has
	// (ATTR_CMNEXT_CLONE_REFCNT) is not asked here: measured, it alone made the read a third slower; it is asked of the
	// few files that need it (shareFacts).
	attrCmnExtCloneID = 0x00000100 // ATTR_CMNEXT_CLONEID, u_int64_t
	attrCmnExtFlags   = 0x00000200 // ATTR_CMNEXT_EXT_FLAGS, u_int64_t
	bulkClones        = attrCmnExtCloneID | attrCmnExtFlags
	efMayShareBlocks  = 0x00000001 // EF_MAY_SHARE_BLOCKS (<sys/stat.h>)
	efSharesAllBlocks = 0x00000040 // EF_SHARES_ALL_BLOCKS
	// Entry.Shares
	sharesSome = 1
	sharesAll  = 2
	// vnode types (sys/vnode.h)
	vREG = 1
	vLNK = 5
)

var bulkBufs = sync.Pool{New: func() any { b := make([]byte, 128<<10); return &b }}

// readBulk reads the folder open as fd with getattrlistbulk; ok false when it cannot (not supported here, or failed
// partway): the caller then lists it the plain way. Only files and links are taken from it; a folder, an entry whose
// attributes are missing or came with an error, and one that might not be what lstat says (dataless, a device, a size
// not in whole 512-byte blocks) is lstat'ed itself.
// clones: ask also for what each file's blocks share (Entry.Shares, CloneID); an entry that is lstat'ed
// has none. stop (may be nil) is asked between the system calls; when it says so, ok is false as well.
func readBulk(fd int, dir string, clones bool, stop func() bool) ([]Entry, bool) {
	al := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: bulkCommon, Fileattr: bulkFile}
	var options uint64
	if clones {
		al.Forkattr = bulkClones
		options = unix.FSOPT_ATTR_CMN_EXTENDED
	}
	bp := bulkBufs.Get().(*[]byte)
	defer bulkBufs.Put(bp)
	buf := *bp
	var out []Entry
	for {
		if stop != nil && stop() {
			return nil, false
		}
		n, err := getattrlistbulk(fd, &al, buf, options)
		if err != nil {
			return nil, false
		}
		if n == 0 {
			return out, true
		}
		off := 0
		for i := 0; i < n; i++ {
			if off+4 > len(buf) {
				return nil, false
			}
			size := int(le32(buf, off))
			if size < 4 || off+size > len(buf) {
				return nil, false
			}
			e, how := parseBulk(buf[off:off+size], dir)
			switch how {
			case bulkBad:
				return nil, false
			case bulkStat:
				var st syscall.Stat_t
				if Fstatat(fd, e.Name, &st, AtSymlinkNoFollow) != nil {
					break // gone since: left out, as readFolderStat leaves it out
				}
				out = append(out, entryOf(e.Path, &st))
			default:
				out = append(out, e)
			}
			off += size
		}
	}
}

const (
	bulkOK   = iota
	bulkStat // the name is good, the rest is to be lstat'ed
	bulkBad  // cannot read this record at all
)

// parseBulk reads one packed record: its length, the set of attributes returned for it, then each returned attribute
// in the order of its bit (common, then file attributes, then the extended common ones), each a multiple of 4 bytes long, so packed without gaps. A name is an
// attrreference_t (offset from itself, length with the NUL).
func parseBulk(r []byte, dir string) (Entry, int) {
	if len(r) < 4+20 {
		return Entry{}, bulkBad
	}
	common, fileAttrs, ext := le32(r, 4), le32(r, 16), le32(r, 20) // attribute_set_t: common, volume, folder, file, fork
	p := 24
	if common&unix.ATTR_CMN_NAME == 0 || p+8 > len(r) {
		return Entry{}, bulkBad
	}
	nameOff, nameLen := int(int32(le32(r, p))), int(le32(r, p+4))
	start := p + nameOff
	if nameLen < 1 || start < 0 || start+nameLen > len(r) {
		return Entry{}, bulkBad
	}
	name := r[start : start+nameLen-1]
	for i, c := range name {
		if c == 0 {
			name = name[:i]
			break
		}
	}
	if len(name) == 0 {
		return Entry{}, bulkBad
	}
	e := Entry{Name: string(name)}
	e.Path = dir + "/" + e.Name
	p += 8
	var dev, typ, owner, flags, errno, links uint32
	var sec, nsec, alloc int64
	var cloneID, extFlags uint64
	short := false
	field := func(set, bit uint32, size int) (int, bool) { // where the attribute is, when it was returned
		if set&bit == 0 {
			return 0, false
		}
		if p+size > len(r) {
			short = true
			return 0, false
		}
		at := p
		p += size
		return at, true
	}
	if at, ok := field(common, unix.ATTR_CMN_DEVID, 4); ok {
		dev = le32(r, at)
	}
	if at, ok := field(common, unix.ATTR_CMN_OBJTYPE, 4); ok {
		typ = le32(r, at)
	}
	if at, ok := field(common, unix.ATTR_CMN_MODTIME, 16); ok {
		sec, nsec = int64(le64(r, at)), int64(le64(r, at+8))
	}
	if at, ok := field(common, unix.ATTR_CMN_OWNERID, 4); ok {
		owner = le32(r, at)
	}
	if at, ok := field(common, unix.ATTR_CMN_FLAGS, 4); ok {
		flags = le32(r, at)
	}
	if at, ok := field(common, unix.ATTR_CMN_ERROR, 4); ok {
		errno = le32(r, at)
	}
	if at, ok := field(fileAttrs, unix.ATTR_FILE_LINKCOUNT, 4); ok {
		links = le32(r, at)
	}
	if at, ok := field(fileAttrs, unix.ATTR_FILE_ALLOCSIZE, 8); ok {
		alloc = int64(le64(r, at))
	}
	if at, ok := field(ext, attrCmnExtCloneID, 8); ok {
		cloneID = le64(r, at)
	}
	if at, ok := field(ext, attrCmnExtFlags, 8); ok {
		extFlags = le64(r, at)
	}
	// An attribute that was not asked for: the record is not what is read here.
	if short || fileAttrs&^bulkFile != 0 || ext&^bulkClones != 0 {
		return Entry{}, bulkBad
	}
	const basic = unix.ATTR_CMN_DEVID | unix.ATTR_CMN_OBJTYPE | unix.ATTR_CMN_MODTIME | unix.ATTR_CMN_OWNERID |
		unix.ATTR_CMN_FLAGS
	if errno != 0 || common&basic != basic || flags&unix.SF_DATALESS != 0 {
		return e, bulkStat
	}
	switch typ {
	case vLNK:
		e.IsLink = true
	case vREG:
		// lstat's st_blocks is the whole allocation (all forks) in 512-byte blocks: take it only when it is whole
		if fileAttrs&unix.ATTR_FILE_ALLOCSIZE == 0 || alloc < 0 || alloc%512 != 0 {
			return e, bulkStat
		}
		// lstat's st_nlink is 16 bits wide: a count that is missing, or would not fit, is lstat's to say
		if fileAttrs&unix.ATTR_FILE_LINKCOUNT == 0 || links == 0 || links > 0xFFFF {
			return e, bulkStat
		}
		e.Bytes = alloc
		e.Links = links
		// Sharing counts only with both the flags and the id: a file without them is one that shares nothing.
		if ext&(attrCmnExtCloneID|attrCmnExtFlags) == attrCmnExtCloneID|attrCmnExtFlags && cloneID != 0 {
			switch {
			case extFlags&efSharesAllBlocks != 0:
				e.Shares = sharesAll
			case extFlags&efMayShareBlocks != 0:
				e.Shares = sharesSome
			}
			if e.Shares != 0 {
				e.CloneID = cloneID
			}
		}
	default:
		return e, bulkStat // folders (see bulkCommon), devices, sockets, pipes
	}
	e.Modified = time.Unix(sec, nsec)
	e.Device = int32(dev)
	e.Owner = owner
	return e, bulkOK
}

func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func le64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

// TreeFacts is what one walk finds: the size, the newest change up to now (not inside .git), the earliest change
// after now (unpacked files carry future dates), the top item's own modification time.
type TreeFacts struct {
	Bytes    int64
	Newest   time.Time // zero: none
	Future   time.Time // zero: none
	Modified time.Time
	IsDir    bool
}

// WalkFacts walks once for size and change times; ok false when stop said so. now zero: only the size.
func WalkFacts(path string, now time.Time, stop func() bool) (TreeFacts, bool) {
	var out TreeFacts
	see := func(d time.Time) {
		if now.IsZero() {
			return
		}
		if !d.After(now) {
			if d.After(out.Newest) {
				out.Newest = d
			}
		} else if out.Future.IsZero() || d.Before(out.Future) {
			out.Future = d
		}
	}
	top, ok := Item(path)
	if !ok {
		return TreeFacts{}, true
	}
	see(top.Modified)
	out.Modified, out.IsDir = top.Modified, top.IsDir
	if !top.IsDir {
		out.Bytes = top.Bytes
		return out, true
	}
	n := 0
	finished := Tree(path, nil, func(e Entry) bool {
		n++
		if n%2000 == 0 && stop != nil && stop() {
			return false
		}
		if e.IsLink {
			return true
		}
		out.Bytes += e.Bytes
		if !e.InGit {
			see(e.Modified)
		}
		return true
	})
	return out, finished
}

// SpaceTally: files and their allocated bytes.
type SpaceTally struct {
	Bytes int64 `json:"bytes"`
	Count int64 `json:"count"`
}

// SpaceBigFile is one of the biggest files anywhere inside a folder: its path under that folder, its allocated size,
// the day it was last changed.
type SpaceBigFile struct {
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes"`
	Modified string `json:"modified"`
}

// SpaceMix is what a folder is made of, all the way down: its files by kind (FileKind) and by the year they were last
// changed ("" for a date before 1980 or after the walk), and the biggest of them. Unknown: the bytes of subfolders
// found unchanged that had no mix remembered (measured by a version before this one), not in Kinds, Years or Top.
type SpaceMix struct {
	Kinds   map[string]SpaceTally `json:"kinds"`
	Years   map[string]int64      `json:"years"`
	Top     []SpaceBigFile        `json:"top"`
	Unknown int64                 `json:"unknown,omitempty"`
}

// spaceMixTop: how many of the biggest files a mix keeps; spaceMixFileMin: the smallest that counts as one.
const (
	spaceMixTop     = 10
	spaceMixFileMin = 1 << 20
)

// file counts one file: rel is its path under the mix's folder.
func (m *SpaceMix) file(rel string, bytes int64, modified, now time.Time) {
	if m.Kinds == nil {
		m.Kinds, m.Years = map[string]SpaceTally{}, map[string]int64{}
	}
	name := rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		name = rel[i+1:]
	}
	k := FileKind(name)
	t := m.Kinds[k]
	t.Bytes += bytes
	t.Count++
	m.Kinds[k] = t
	year := ""
	if y := modified.Local().Year(); y >= 1980 && !modified.After(now) {
		year = strconv.Itoa(y)
	}
	m.Years[year] += bytes
	if bytes >= spaceMixFileMin {
		m.Top = append(m.Top, SpaceBigFile{Path: rel, Bytes: bytes, Modified: ISODay(modified)})
		if len(m.Top) >= 8*spaceMixTop {
			m.trim()
		}
	}
}

// add counts a subfolder's mix; name is the subfolder's name in the mix's folder.
func (m *SpaceMix) add(sub SpaceMix, name string) {
	if m.Kinds == nil {
		m.Kinds, m.Years = map[string]SpaceTally{}, map[string]int64{}
	}
	for k, t := range sub.Kinds {
		x := m.Kinds[k]
		x.Bytes += t.Bytes
		x.Count += t.Count
		m.Kinds[k] = x
	}
	for y, b := range sub.Years {
		m.Years[y] += b
	}
	for _, f := range sub.Top {
		m.Top = append(m.Top, SpaceBigFile{Path: name + "/" + f.Path, Bytes: f.Bytes, Modified: f.Modified})
	}
	m.Unknown += sub.Unknown
	m.trim()
}

// trim keeps the spaceMixTop biggest files, the biggest first (then by path).
func (m *SpaceMix) trim() {
	if m.Kinds == nil {
		m.Kinds, m.Years = map[string]SpaceTally{}, map[string]int64{}
	}
	sort.Slice(m.Top, func(i, j int) bool {
		if m.Top[i].Bytes != m.Top[j].Bytes {
			return m.Top[i].Bytes > m.Top[j].Bytes
		}
		return m.Top[i].Path < m.Top[j].Path
	})
	if len(m.Top) > spaceMixTop {
		m.Top = m.Top[:spaceMixTop]
	}
}

// WalkMix walks once for the size and what the folder is made of; ok false when stop said so. The size is WalkFacts'.
func WalkMix(path string, now time.Time, stop func() bool) (int64, SpaceMix, bool) {
	return walkMix(path, now, stop, nil)
}

// WalkClones is WalkMix, and which of the files share their blocks with others (SpaceClones), in the same walk.
func WalkClones(path string, now time.Time, stop func() bool) (int64, SpaceMix, SpaceClones, bool) {
	var c SpaceClones
	b, m, ok := walkMix(path, now, stop, &c)
	c.trim()
	return b, m, c, ok
}

func walkMix(path string, now time.Time, stop func() bool, clones *SpaceClones) (int64, SpaceMix, bool) {
	var m SpaceMix
	top, ok := Item(path)
	if !ok || !top.IsDir {
		m.trim()
		return top.Bytes, m, true
	}
	var total int64
	n := 0
	walk := Tree
	if clones != nil {
		walk = treeClones
	}
	finished := walk(path, nil, func(e Entry) bool {
		n++
		if n%2000 == 0 && stop != nil && stop() {
			return false
		}
		if e.IsLink {
			return true
		}
		total += e.Bytes
		if !e.IsDir {
			m.file(strings.TrimPrefix(e.Path, path+"/"), e.Bytes, e.Modified, now)
			if clones != nil {
				clones.file(e)
			}
		}
		return true
	})
	m.trim()
	return total, m, finished
}

// AllocatedSize of a file or a tree, not following links and not crossing into other volumes.
func AllocatedSize(path string) int64 {
	f, _ := WalkFacts(path, time.Time{}, nil)
	return f.Bytes
}

// FirstChange walks until the first change between since and now (inclusive; .git's dates not looked at) and says
// when; else zero and the size (when size is wanted).
func FirstChange(path string, since, now time.Time, size bool) (time.Time, int64) {
	recent := func(d time.Time) bool { return !d.Before(since) && !d.After(now) }
	top, ok := Item(path)
	if !ok {
		return time.Time{}, 0
	}
	if recent(top.Modified) {
		return top.Modified, 0
	}
	if !top.IsDir {
		return time.Time{}, top.Bytes
	}
	var total int64
	var changed time.Time
	Tree(path, func(e Entry) bool { return size || !e.InGit }, func(e Entry) bool {
		if !e.InGit && recent(e.Modified) {
			changed = e.Modified
			return false
		}
		total += e.Bytes
		return true
	})
	if !changed.IsZero() || !size {
		return changed, 0
	}
	return time.Time{}, total
}

// SizeUnlessChanged is the size, or ok false when anything changed between since and now.
func SizeUnlessChanged(path string, since, now time.Time) (int64, bool) {
	c, b := FirstChange(path, since, now, true)
	return b, c.IsZero()
}

// Changed says whether anything under path changed between since and now.
func Changed(path string, since, now time.Time) bool {
	c, _ := FirstChange(path, since, now, false)
	return !c.IsZero()
}
