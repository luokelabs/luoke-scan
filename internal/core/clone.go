package core

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Turning a copy into a clone of the file it copies (APFS: both stay, the blocks are shared), and what has a file open.
// Raw system calls as in sysat.go.

const (
	ufImmutable  = 0x00000002
	ufAppend     = 0x00000004
	ufCompressed = 0x00000020
	sfImmutable  = 0x00020000
	sfAppend     = 0x00040000

	kauthFilesecNoACL = 0xffffffff
)

// Refused is why a copy was not turned into a clone.
type Refused struct{ Reason string }

func (r Refused) Error() string { return r.Reason }

// CloneTempPrefix starts the name of a clone made next to the copy before it takes the copy's place.
const CloneTempPrefix = ".luoke-scan-clone-"

// ReplaceWithClone replaces copy with a clone of original, keeping copy's own metadata (permissions, dates, flags,
// extended attributes, access control list). Only for plain files of this user, on one volume, still with the same
// contents (checked here, byte by byte), with no other names and no flags that make them special. The swap is one
// rename: copy is the old file or the clone, never missing.
func ReplaceWithClone(original, copy string) error {
	var so, sc syscall.Stat_t
	if syscall.Lstat(original, &so) != nil || syscall.Lstat(copy, &sc) != nil {
		return Refused{"已经不在了"}
	}
	if so.Mode&syscall.S_IFMT != syscall.S_IFREG || sc.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return Refused{"不是普通文件"}
	}
	if so.Dev != sc.Dev {
		return Refused{"两份不在同一个磁盘上，做不了克隆"}
	}
	if so.Ino == sc.Ino {
		return Refused{"本来就是同一个文件"}
	}
	if int(sc.Uid) != os.Getuid() {
		return Refused{"不是你的文件"}
	}
	if sc.Nlink != 1 {
		return Refused{"它还有别的名字（硬链接）"}
	}
	special := uint32(ufImmutable | sfImmutable | ufAppend | sfAppend | ufCompressed)
	if so.Flags&special != 0 || sc.Flags&special != 0 {
		return Refused{"带着锁定或压缩之类的标记"}
	}
	if so.Size != sc.Size || !SameContents(original, copy) {
		return Refused{"两份内容已经不一样了"}
	}
	// An app that has the copy open would go on writing to the old file once it is swapped out, and lose that.
	if apps := OpenBy(copy); len(apps) > 0 {
		return Refused{apps[0] + " 正开着它"}
	}
	dir := filepath.Dir(copy)
	removeCloneLeftovers(dir)
	b := make([]byte, 16)
	rand.Read(b)
	temp := filepath.Join(dir, CloneTempPrefix+strings.ToUpper(hex.EncodeToString(b)))
	if err := clonefile(original, temp); err != nil {
		return Refused{"克隆失败（" + err.Error() + "）"}
	}
	if err := copyMetadata(copy, temp, &sc); err != nil {
		syscall.Unlink(temp)
		return err
	}
	// Same contents still (the copy could have been written to meanwhile), then the swap.
	if !SameContents(temp, copy) {
		syscall.Unlink(temp)
		return Refused{"两份内容已经不一样了"}
	}
	if err := syscall.Rename(temp, copy); err != nil {
		syscall.Unlink(temp)
		return Refused{"换不过去（" + err.Error() + "）"}
	}
	return nil
}

// copyMetadata gives temp the copy's extended attributes (in place of the original's), access control list, group,
// permissions, flags and dates (what copyfile's XATTR | SECURITY | STAT carry), then its creation and date-added times.
func copyMetadata(copy, temp string, sc *syscall.Stat_t) error {
	failed := Refused{"元数据没能带过去"}
	for _, name := range xattrNames(temp) {
		removeXattr(temp, name)
	}
	for _, name := range xattrNames(copy) {
		v, ok := getXattr(copy, name)
		if !ok || putXattr(temp, name, v) != nil {
			return failed
		}
	}
	if acl, ok := extendedSecurity(copy); !ok {
		return failed
	} else if acl != nil && setExtendedSecurity(temp, acl) != nil {
		return failed
	}
	syscall.Lchown(temp, -1, int(sc.Gid)) // best effort, as copyfile: the group when this user may set it
	if syscall.Chmod(temp, uint32(sc.Mode&0o7777)) != nil {
		return failed
	}
	if syscall.Chflags(temp, int(sc.Flags)) != nil {
		return failed
	}
	if syscall.UtimesNano(temp, []syscall.Timespec{sc.Atimespec, sc.Mtimespec}) != nil {
		return failed
	}
	added, hasAdded := addedTimespec(copy)
	if setDates(temp, sc.Birthtimespec, added, hasAdded) != nil {
		return Refused{"日期没能带过去"}
	}
	return nil
}

// removeCloneLeftovers removes a temporary clone left by a swap that never finished (killed between clone and rename).
func removeCloneLeftovers(dir string) {
	old := time.Now().Add(-10 * time.Minute)
	names, _ := List(dir)
	for _, p := range names {
		if !strings.HasPrefix(filepath.Base(p), CloneTempPrefix) {
			continue
		}
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != os.Getuid() ||
			!time.Unix(st.Mtimespec.Sec, 0).Before(old) {
			continue
		}
		syscall.Unlink(p)
	}
}

// extendedSecurity is a file's kauth_filesec when it has an access control list, nil when it has none; ok false when
// it could not be read.
func extendedSecurity(path string) ([]byte, bool) {
	buf := make([]byte, 64<<10)
	if getattrlist(path, attrs(unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY, 0), buf, unix.FSOPT_NOFOLLOW) != nil {
		return nil, false
	}
	// u_int32_t length; attribute_set_t returned (5 × u_int32_t); attrreference_t {int32 offset; u_int32 length}.
	if binary.LittleEndian.Uint32(buf[4:8])&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		return nil, true
	}
	ref := 24
	off := int(int32(binary.LittleEndian.Uint32(buf[ref : ref+4])))
	n := int(binary.LittleEndian.Uint32(buf[ref+4 : ref+8]))
	if n == 0 {
		return nil, true
	}
	start := ref + off
	if start < 0 || start+n > len(buf) || n < 40 {
		return nil, false
	}
	data := append([]byte(nil), buf[start:start+n]...)
	// kauth_filesec: magic, owner and group GUIDs (16 each), then the ACL's entry count.
	if binary.LittleEndian.Uint32(data[36:40]) == kauthFilesecNoACL {
		return nil, true
	}
	return data, true
}

func setExtendedSecurity(path string, filesec []byte) error {
	buf := make([]byte, 8+len(filesec))
	binary.LittleEndian.PutUint32(buf[0:4], 8)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(filesec)))
	copy(buf[8:], filesec)
	return setattrlist(path, attrs(unix.ATTR_CMN_EXTENDED_SECURITY, 0), buf, unix.FSOPT_NOFOLLOW)
}

// addedTimespec is when a file came into its folder (Finder's date added), when the volume keeps it.
func addedTimespec(path string) (syscall.Timespec, bool) {
	var buf [64]byte
	if getattrlist(path, attrs(unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_ADDEDTIME, 0), buf[:], unix.FSOPT_NOFOLLOW) != nil ||
		binary.LittleEndian.Uint32(buf[4:8])&unix.ATTR_CMN_ADDEDTIME == 0 {
		return syscall.Timespec{}, false
	}
	return syscall.Timespec{Sec: int64(binary.LittleEndian.Uint64(buf[24:32])), Nsec: int64(binary.LittleEndian.Uint64(buf[32:40]))}, true
}

// setDates sets the creation and (when given) date-added times; copying the rest of the dates is utimes'.
func setDates(path string, created, added syscall.Timespec, hasAdded bool) error {
	common := uint32(unix.ATTR_CMN_CRTIME)
	values := []syscall.Timespec{created}
	if hasAdded {
		common |= unix.ATTR_CMN_ADDEDTIME
		values = append(values, added)
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&values[0])), uintptr(len(values))*unsafe.Sizeof(values[0]))
	return setattrlist(path, attrs(common, 0), buf, unix.FSOPT_NOFOLLOW)
}

const (
	procCallListPids  = 1
	procCallPidInfo   = 2
	procCallPidFDInfo = 3
	procAllPids       = 1
	procPidListFDs    = 1
	procPidPathInfo   = 11
	procPidFDVnodePI  = 2
	proxFDTypeVnode   = 1
	oEvtOnly          = 0x00008000
	vnodeFDInfoSize   = 1200 // struct vnode_fdinfowithpath
)

// OpenBy are the names of the processes (this user's: others' cannot be looked into) that have path open, as
// libproc's proc_listpidspath sees open files (descriptors opened only to watch for events not counted).
// TODO: proc_listpidspath also counts a process whose working directory, or a file it maps, is the file.
func OpenBy(path string) []string {
	var st syscall.Stat_t
	if syscall.Stat(path, &st) != nil {
		return nil
	}
	n, e := procInfo(procCallListPids, procAllPids, 0, 0, nil)
	if e != 0 || n <= 0 {
		return nil
	}
	pidBuf := make([]byte, n+64*4)
	n, e = procInfo(procCallListPids, procAllPids, 0, 0, pidBuf)
	if e != 0 || n <= 0 {
		return nil
	}
	var out []string
	fds := make([]byte, 8*4096)
	info := make([]byte, vnodeFDInfoSize)
	for i := 0; i+4 <= n; i += 4 {
		pid := int(int32(binary.LittleEndian.Uint32(pidBuf[i : i+4])))
		if pid <= 0 {
			continue
		}
		m, e := procInfo(procCallPidInfo, pid, procPidListFDs, 0, fds)
		if e != 0 || m <= 0 {
			continue
		}
		open := false
		for j := 0; j+8 <= m && !open; j += 8 {
			fd := int32(binary.LittleEndian.Uint32(fds[j : j+4]))
			if binary.LittleEndian.Uint32(fds[j+4:j+8]) != proxFDTypeVnode {
				continue
			}
			k, e := procInfo(procCallPidFDInfo, pid, procPidFDVnodePI, uint64(fd), info)
			if e != 0 || k < 24+16 {
				continue
			}
			// proc_fileinfo (fi_openflags first, 24 bytes), then vinfo_stat: vst_dev u32, mode u16, nlink u16, vst_ino u64.
			if binary.LittleEndian.Uint32(info[0:4])&oEvtOnly != 0 {
				continue
			}
			if int32(binary.LittleEndian.Uint32(info[24:28])) == st.Dev && binary.LittleEndian.Uint64(info[32:40]) == st.Ino {
				open = true
			}
		}
		if open {
			out = append(out, procName(pid))
		}
	}
	return out
}

func procName(pid int) string {
	buf := make([]byte, 4096)
	n, e := procInfo(procCallPidInfo, pid, procPidPathInfo, 0, buf)
	if e != 0 || n <= 0 {
		return "进程 " + strconv.Itoa(pid)
	}
	for i, c := range buf {
		if c == 0 {
			return filepath.Base(string(buf[:i]))
		}
	}
	return filepath.Base(string(buf))
}
