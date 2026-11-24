package core

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The system calls the standard library does not wrap on macOS, through golang.org/x/sys/unix (11-05: no
// system call numbers written by hand). Where x/sys has no wrapper (getattrlist, getattrlistbulk, proc_info, fcntl F_GETPATH, iopolicysys) the call
// goes through unix.Syscall6 with x/sys's own name for it. Everything is in this one file: the rest of the package
// calls these.

const (
	AtFDCWD           = unix.AT_FDCWD
	AtSymlinkNoFollow = unix.AT_SYMLINK_NOFOLLOW
	AtRemoveDir       = unix.AT_REMOVEDIR
	RenameExcl        = unix.RENAME_EXCL
	RenameSwap        = unix.RENAME_SWAP
	XattrNoFollow     = unix.XATTR_NOFOLLOW
)

// syscall.Stat_t and unix.Stat_t are the same struct stat: the callers keep the standard library's type.
var _ [unsafe.Sizeof(syscall.Stat_t{}) - unsafe.Sizeof(unix.Stat_t{})]byte
var _ [unsafe.Sizeof(unix.Stat_t{}) - unsafe.Sizeof(syscall.Stat_t{})]byte

// Openat opens name in the folder open as dir.
func Openat(dir int, name string, flags int, mode uint32) (int, error) {
	return unix.Openat(dir, name, flags, mode)
}

// Fstatat stats name in the folder open as dir (AtSymlinkNoFollow: the link itself).
func Fstatat(dir int, name string, st *syscall.Stat_t, flags int) error {
	return unix.Fstatat(dir, name, (*unix.Stat_t)(unsafe.Pointer(st)), flags)
}

// Unlinkat removes name from the folder open as dir (AtRemoveDir: an empty folder).
func Unlinkat(dir int, name string, flags int) error { return unix.Unlinkat(dir, name, flags) }

// Mkdirat makes a folder in the folder open as dir.
func Mkdirat(dir int, name string, mode uint32) error { return unix.Mkdirat(dir, name, mode) }

// RenameatxNp renames between two open folders (RenameExcl: never over something there).
func RenameatxNp(fromDir int, from string, toDir int, to string, flags uint) error {
	return unix.RenameatxNp(fromDir, from, toDir, to, uint32(flags))
}

// Readlinkat reads the link name in the folder open as dir.
func Readlinkat(dir int, name string, buf []byte) (int, error) {
	return unix.Readlinkat(dir, name, buf)
}

// Fgetxattr reads an extended attribute of an open file (at most 512 bytes); nil when it has none.
func Fgetxattr(fd int, name string) []byte {
	buf := make([]byte, 512)
	n, err := unix.Fgetxattr(fd, name, buf)
	if err != nil || n <= 0 {
		return nil
	}
	return buf[:n]
}

// Fremovexattr removes an extended attribute of an open file.
func Fremovexattr(fd int, name string) { unix.Fremovexattr(fd, name) }

// SetXattrNoFollow sets an extended attribute on a path, not following a link.
func SetXattrNoFollow(path, name string, value []byte) error {
	if len(value) == 0 {
		return syscall.EINVAL
	}
	return unix.Lsetxattr(path, name, value, 0)
}

// Xattr reads an extended attribute (not following a link), at most max bytes; ok false when there is none or it is
// bigger. max 0: only whether it is there.
func Xattr(path, name string, max int) ([]byte, bool) {
	if max <= 0 {
		_, err := unix.Lgetxattr(path, name, nil)
		return nil, err == nil
	}
	buf := make([]byte, max)
	n, err := unix.Lgetxattr(path, name, buf)
	if err != nil || n < 0 {
		return nil, false
	}
	return buf[:n], true
}

// xattrFollowing reads an extended attribute through a link, into buf; how much it read.
func xattrFollowing(path, name string, buf []byte) (int, error) {
	return unix.Getxattr(path, name, buf)
}

// xattrNames are a path's extended attributes' names, not following a link.
func xattrNames(path string) []string {
	n, err := unix.Llistxattr(path, nil)
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]byte, n)
	m, err := unix.Llistxattr(path, buf)
	if err != nil || m != n {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < m; i++ {
		if buf[i] == 0 {
			if i > start {
				out = append(out, string(buf[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

// getXattr reads a whole extended attribute, not following a link.
func getXattr(path, name string) ([]byte, bool) {
	size, err := unix.Lgetxattr(path, name, nil)
	if err != nil {
		return nil, false
	}
	if size == 0 {
		return []byte{}, true
	}
	buf := make([]byte, size)
	n, err := unix.Lgetxattr(path, name, buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// putXattr sets an extended attribute, not following a link (an empty value too).
func putXattr(path, name string, value []byte) error { return unix.Lsetxattr(path, name, value, 0) }

// removeXattr removes an extended attribute, not following a link.
func removeXattr(path, name string) { unix.Lremovexattr(path, name) }

// clonefile makes to an APFS clone of from, not following a link at from and not keeping from's owner.
func clonefile(from, to string) error {
	return unix.Clonefileat(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.CLONE_NOFOLLOW|unix.CLONE_NOOWNERCOPY)
}

// getattrlist fills buf with the attributes al asks for (x/sys has no wrapper for it).
func getattrlist(path string, al *unix.Attrlist, buf []byte, options int) error {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, e := unix.Syscall6(unix.SYS_GETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(al)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(options), 0)
	if e != 0 {
		return e
	}
	return nil
}

// getattrlistbulk fills buf with the attributes al asks for of the next entries of the folder open as dir and says
// how many entries it packed (0: no more). x/sys has no wrapper for it.
func getattrlistbulk(dir int, al *unix.Attrlist, buf []byte, options uint64) (int, error) {
	n, _, e := unix.Syscall6(unix.SYS_GETATTRLISTBULK, uintptr(dir), uintptr(unsafe.Pointer(al)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(options), 0)
	if e != 0 {
		return 0, e
	}
	return int(n), nil
}

// setattrlist sets the attributes al names from buf.
func setattrlist(path string, al *unix.Attrlist, buf []byte, options int) error {
	return unix.Setattrlist(path, al, buf, options)
}

// attrs is an attribute list asking for common attributes (and, with fork, fork attributes).
func attrs(common, fork uint32) *unix.Attrlist {
	return &unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: common, Forkattr: fork}
}

// VolumeID names the volume path is on, the same across restarts: its UUID (getattrlist ATTR_VOL_UUID of where it
// is mounted); where the volume has none, "dev:" and its device number (good while it stays mounted); "" when path
// is not there.
func VolumeID(path string) string {
	var fs unix.Statfs_t
	if unix.Statfs(path, &fs) != nil {
		return ""
	}
	mount := unix.ByteSliceToString(fs.Mntonname[:])
	var buf [4 + 16]byte // length, then the uuid_t
	al := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Volattr: unix.ATTR_VOL_INFO | unix.ATTR_VOL_UUID}
	if mount != "" && getattrlist(mount, &al, buf[:], 0) == nil && *(*uint32)(unsafe.Pointer(&buf[0])) >= 4+16 {
		const hex = "0123456789ABCDEF"
		out := make([]byte, 0, 32)
		zero := true
		for _, b := range buf[4:] {
			zero = zero && b == 0
			out = append(out, hex[b>>4], hex[b&15])
		}
		if !zero {
			return string(out)
		}
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil {
		return ""
	}
	return "dev:" + strconv.Itoa(int(st.Dev))
}

// procInfo is the proc_info call libproc's functions make (x/sys has no wrapper for it).
func procInfo(call, pid int, flavor uint32, arg uint64, buf []byte) (int, syscall.Errno) {
	var b uintptr
	if len(buf) > 0 {
		b = uintptr(unsafe.Pointer(&buf[0]))
	}
	n, _, e := unix.Syscall6(unix.SYS_PROC_INFO, uintptr(call), uintptr(pid), uintptr(flavor), uintptr(arg), b, uintptr(len(buf)))
	return int(int32(n)), syscall.Errno(e)
}

// Nice sets this process's nice value (setpriority PRIO_PROCESS); a user who is not root can only raise it. What the
// process starts afterwards inherits it.
func Nice(n int) error { return unix.Setpriority(unix.PRIO_PROCESS, 0, n) }

// The disk I/O policy, from <sys/resource.h>: x/sys names the system call but neither these values nor a wrapper.
// libc's setiopolicy_np and getiopolicy_np fill struct _iopol_param_t {scope, type, policy} and make this one call.
const (
	iopolCmdGet       = 1 // IOPOL_CMD_GET
	iopolCmdSet       = 2 // IOPOL_CMD_SET
	iopolTypeDisk     = 0 // IOPOL_TYPE_DISK
	iopolScopeProcess = 0 // IOPOL_SCOPE_PROCESS
	IOPolicyUtility   = 4 // IOPOL_UTILITY: below the user's apps, above the background tier (IOPOL_THROTTLE)
)

type iopolParam struct{ scope, iotype, policy int32 }

func iopolicysys(cmd int, p *iopolParam) error {
	_, _, e := unix.Syscall(unix.SYS_IOPOLICYSYS, uintptr(cmd), uintptr(unsafe.Pointer(p)), 0)
	if e != 0 {
		return e
	}
	return nil
}

// SetDiskPolicy is setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, policy): this process's disk I/O, and that of
// what it starts afterwards (inherited).
func SetDiskPolicy(policy int) error {
	return iopolicysys(iopolCmdSet, &iopolParam{scope: iopolScopeProcess, iotype: iopolTypeDisk, policy: int32(policy)})
}

// DiskPolicy is getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS).
func DiskPolicy() (int, error) {
	p := iopolParam{scope: iopolScopeProcess, iotype: iopolTypeDisk}
	if err := iopolicysys(iopolCmdGet, &p); err != nil {
		return 0, err
	}
	return int(p.policy), nil
}

// FDPath is where an open file or folder is (fcntl F_GETPATH).
func FDPath(fd int) (string, error) {
	buf := make([]byte, unix.PathMax)
	_, _, e := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0])))
	if e != 0 {
		return "", e
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf), nil
}

// OpenNoFollow opens a folder from "/" one name at a time following no link anywhere on the way; -1 when it cannot.
func OpenNoFollow(path string) int {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1
	}
	for _, part := range splitPath(path) {
		next, err := Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return -1
		}
		fd = next
	}
	return fd
}

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// RemoveNoFollow deletes the folder at path (its real path: no link anywhere on the way) and everything in it for good, following no link: its parent opened from
// "/" one name at a time, then each folder through the descriptor of the one it is in. A link inside is removed as a
// link; a disk mounted inside is not gone into. A folder of the user's own that its tool made read-only is made
// writable for the user first (its files can't be removed otherwise). An error when the way has a link or it is not a
// folder; a *RemoveLeft, with what stayed and why, when something stayed (what could go is gone).
func RemoveNoFollow(path string) error {
	parent := OpenNoFollow(dirOf(path))
	if parent < 0 {
		return syscall.ENOENT
	}
	defer syscall.Close(parent)
	var st syscall.Stat_t
	name := baseOf(path)
	if Fstatat(parent, name, &st, AtSymlinkNoFollow) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return syscall.ENOENT
	}
	left := &RemoveLeft{}
	if !removeTree(parent, name, st.Dev, left) {
		if left.Locked+left.NoPermission+left.Mounted+left.Other == 0 {
			left.Other = 1
		}
		return left
	}
	return nil
}

// RemoveLeft: what a removal left, by why, counted in files and folders.
type RemoveLeft struct {
	Locked       int // 「锁定」 in the Finder's Get Info (chflags uchg)
	NoPermission int // not the user's to change (another user's or the system's)
	Mounted      int // another disk mounted inside
	Other        int
}

func (l *RemoveLeft) Error() string { return l.Plain() }

// Plain: why, for a person, short: 「12 个文件已锁定」.
func (l *RemoveLeft) Plain() string {
	var out []string
	if l.Locked > 0 {
		out = append(out, strconv.Itoa(l.Locked)+" 个文件已锁定")
	}
	if l.NoPermission > 0 {
		out = append(out, strconv.Itoa(l.NoPermission)+" 个文件无权删除")
	}
	if l.Mounted > 0 {
		out = append(out, "里面挂着其他磁盘")
	}
	if l.Other > 0 && len(out) == 0 {
		out = append(out, strconv.Itoa(l.Other)+" 个文件删除出错")
	}
	return strings.Join(out, "，")
}

func (l *RemoveLeft) count(err error, st *syscall.Stat_t) {
	switch {
	case err == syscall.EPERM && st.Flags&(unix.UF_IMMUTABLE|unix.SF_IMMUTABLE) != 0:
		l.Locked++
	case err == syscall.EPERM || err == syscall.EACCES:
		l.NoPermission++
	default:
		l.Other++
	}
}

func removeTree(dir int, name string, device int32, left *RemoveLeft) bool {
	var st syscall.Stat_t
	if err := Fstatat(dir, name, &st, AtSymlinkNoFollow); err != nil {
		if err == syscall.ENOENT {
			return true
		}
		left.Other++
		return false
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		err := Unlinkat(dir, name, 0)
		if err == nil || err == syscall.ENOENT {
			return true
		}
		left.count(err, &st)
		return false
	}
	if st.Dev != device {
		left.Mounted++
		return false // another disk mounted here
	}
	// The user's own folder without write (or read, search) permission for them: a tool's read-only cache (Go's module
	// cache is r-x). Theirs to change; given back to them before going in.
	if st.Uid == uint32(os.Getuid()) && st.Mode&0o700 != 0o700 && st.Flags&(unix.UF_IMMUTABLE|unix.SF_IMMUTABLE) == 0 {
		_ = unix.Fchmodat(dir, name, uint32(st.Mode&0o7777)|0o700, unix.AT_SYMLINK_NOFOLLOW)
	}
	fd, err := Openat(dir, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		left.count(err, &st)
		return false
	}
	names, ok := readNames(fd)
	if !ok {
		left.Other++
	}
	for _, n := range names {
		if !removeTree(fd, n, device, left) {
			ok = false
		}
	}
	syscall.Close(fd)
	if !ok {
		return false // the folder stays with what is left in it
	}
	err = Unlinkat(dir, name, AtRemoveDir)
	if err == nil || err == syscall.ENOENT {
		return true
	}
	left.count(err, &st)
	return false
}

// readNames lists an open folder's names (not . and ..) without closing it.
func readNames(fd int) ([]string, bool) {
	d, err := syscall.Dup(fd)
	if err != nil {
		return nil, false
	}
	f := newFile(d)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	return names, err == nil
}

func dirOf(p string) string {
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "/"
}

func baseOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func newFile(fd int) *os.File { return os.NewFile(uintptr(fd), "") }

// DateCreated is when the file was made (its birth time), not following a link; ok false when not known.
func DateCreated(path string) (time.Time, bool) {
	var buf [4 + 16]byte // length, then crtime
	if getattrlist(path, attrs(unix.ATTR_CMN_CRTIME, 0), buf[:], unix.FSOPT_NOFOLLOW) != nil {
		return time.Time{}, false
	}
	created := time.Unix(*(*int64)(unsafe.Pointer(&buf[4])), *(*int64)(unsafe.Pointer(&buf[4+8])))
	return created, created.Unix() > 0
}

// DateAdded is when a file came into its folder (Finder's "date added"), else when it was made; not following a link.
func DateAdded(path string) (time.Time, bool) {
	var buf [4 + 2*16]byte // length, then crtime and addedtime (timespecs); the returned set is not asked for
	if getattrlist(path, attrs(unix.ATTR_CMN_CRTIME|unix.ATTR_CMN_ADDEDTIME, 0), buf[:], unix.FSOPT_NOFOLLOW) != nil {
		return time.Time{}, false
	}
	length := *(*uint32)(unsafe.Pointer(&buf[0]))
	ts := func(off int) time.Time {
		sec := *(*int64)(unsafe.Pointer(&buf[off]))
		nsec := *(*int64)(unsafe.Pointer(&buf[off+8]))
		return time.Unix(sec, nsec)
	}
	created := ts(4)
	if length >= 4+32 {
		if added := ts(4 + 16); added.Unix() > 0 {
			return added, true
		}
	}
	return created, created.Unix() > 0
}
