package core

import (
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The system calls the standard library does not wrap on macOS, through golang.org/x/sys/unix (11-05: no
// system call numbers written by hand). Where x/sys has no wrapper (getattrlist, getattrlistbulk, proc_info, fcntl F_GETPATH) the call
// goes through unix.Syscall6 with x/sys's own name for it. Everything is in this one file: the rest of the package
// calls these.

const (
	AtFDCWD           = unix.AT_FDCWD
	AtSymlinkNoFollow = unix.AT_SYMLINK_NOFOLLOW
	AtRemoveDir       = unix.AT_REMOVEDIR
	RenameExcl        = unix.RENAME_EXCL
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

// procInfo is the proc_info call libproc's functions make (x/sys has no wrapper for it).
func procInfo(call, pid int, flavor uint32, arg uint64, buf []byte) (int, syscall.Errno) {
	var b uintptr
	if len(buf) > 0 {
		b = uintptr(unsafe.Pointer(&buf[0]))
	}
	n, _, e := unix.Syscall6(unix.SYS_PROC_INFO, uintptr(call), uintptr(pid), uintptr(flavor), uintptr(arg), b, uintptr(len(buf)))
	return int(int32(n)), syscall.Errno(e)
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
// link; a disk mounted inside is not gone into. An error when the way has a link, it is not a folder, or something
// stayed (what could go is gone).
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
	if !removeTree(parent, name, st.Dev) {
		return syscall.EACCES
	}
	return nil
}

func removeTree(dir int, name string, device int32) bool {
	var st syscall.Stat_t
	if err := Fstatat(dir, name, &st, AtSymlinkNoFollow); err != nil {
		return err == syscall.ENOENT
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		err := Unlinkat(dir, name, 0)
		return err == nil || err == syscall.ENOENT
	}
	if st.Dev != device {
		return false // another disk mounted here
	}
	fd, err := Openat(dir, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	names, ok := readNames(fd)
	for _, n := range names {
		if !removeTree(fd, n, device) {
			ok = false
		}
	}
	syscall.Close(fd)
	err = Unlinkat(dir, name, AtRemoveDir)
	return ok && (err == nil || err == syscall.ENOENT)
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
