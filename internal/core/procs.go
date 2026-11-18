package core

import (
	"encoding/binary"
	"path/filepath"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// The process table of this Mac, read with sysctl and proc_info (no ps, no lsof, no cgo): every process with its
// parent, user, program and start; a process's program path; the arguments it was started with.

// ProcInfo is one process.
type ProcInfo struct {
	PID  int32
	PPID int32
	UID  uint32 // its effective user
	// Path is its program ("" when it cannot be read).
	Path    string
	Started time.Time // to the second
}

// ProcSnapshot is every process this user can see (kern.proc.all), with its program path; none when the list
// cannot be read (asked again when it grew between asking for its size and reading it).
func ProcSnapshot() []ProcInfo {
	var kps []unix.KinfoProc
	var err error
	for try := 0; try < 5; try++ {
		if kps, err = unix.SysctlKinfoProcSlice("kern.proc.all"); err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	var out []ProcInfo
	for _, k := range kps {
		pid := k.Proc.P_pid
		if pid <= 0 {
			continue
		}
		path, _ := ProcPath(pid)
		out = append(out, ProcInfo{PID: pid, PPID: k.Eproc.Ppid, UID: k.Eproc.Ucred.Uid, Path: path,
			Started: time.Unix(k.Proc.P_starttime.Sec, 0)})
	}
	return out
}

// ProcPath is a process's program (proc_pidpath); ok false when it cannot be read.
func ProcPath(pid int32) (string, bool) {
	buf := make([]byte, 4*unix.PathMax)
	r, e := procInfo(procCallPidInfo, int(pid), procPidPathInfo, 0, buf)
	if e != 0 || r < 0 {
		return "", false
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	if n == 0 {
		return "", false
	}
	return procText(buf[:n]), true
}

// ProcArguments are the arguments a process was started with (KERN_PROCARGS2: argc, the program path, then argv);
// ok false when they cannot be read.
func ProcArguments(pid int32) ([]string, bool) {
	buf, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil || len(buf) <= 4 {
		return nil, false
	}
	return parseProcargs2(buf), true
}

// ProcEnvironment is the environment a process was started with (KERN_PROCARGS2, after argv), and after it the
// loader's own apple[] strings (ptr_munge=…, executable_cdhash=…): nothing between them tells them apart, an empty
// string in the environment looks just like the zeros before apple[], so a check for a variable reads them all (no
// apple[] string starts with a variable's name). As the process was started, as far as it has not written over that
// part of its stack since. ok false when it cannot be read. macOS leaves it out for its own programs (an empty list),
// which take no DYLD_* variables anyway.
func ProcEnvironment(pid int32) ([]string, bool) {
	buf, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil || len(buf) <= 4 {
		return nil, false
	}
	_, env := splitProcargs2(buf)
	return env, true
}

// struct proc_vnodepathinfo (sys/proc_info.h): the working directory's vnode_info_path, then the root directory's;
// each a vnode_info (152 bytes) and a path of MAXPATHLEN.
const (
	procPidVnodePathInfo = 9 // PROC_PIDVNODEPATHINFO
	vnodeInfoSize        = 152
	vnodePathInfoSize    = 2 * (vnodeInfoSize + unix.PathMax)
)

// ProcCwd is a process's working directory (proc_pidinfo PROC_PIDVNODEPATHINFO); ok false when it cannot be read.
func ProcCwd(pid int32) (string, bool) {
	buf := make([]byte, vnodePathInfoSize)
	n, e := procInfo(procCallPidInfo, int(pid), procPidVnodePathInfo, 0, buf)
	if e != 0 || n != vnodePathInfoSize {
		return "", false
	}
	path := buf[vnodeInfoSize : vnodeInfoSize+unix.PathMax]
	end := 0
	for end < len(path) && path[end] != 0 {
		end++
	}
	if end == 0 {
		return "", false
	}
	return procText(path[:end]), true
}

// LoadedLibrary is a file a process has mapped as code, beside its own program: a library, a framework, a plugin.
type LoadedLibrary struct {
	Path string
	// Deleted: its file was removed after it was loaded (no link to it left); the code runs on.
	Deleted bool
}

// struct proc_regionwithpathinfo (sys/proc_info.h): a proc_regioninfo (96 bytes: the protection first, the region's
// address and size at 80 and 88), then a vnode_info_path (its vinfo_stat first: vst_nlink at 6; the path after the
// vnode_info).
const (
	procPidRegionPathInfo2 = 22 // PROC_PIDREGIONPATHINFO2: PROC_PIDREGIONPATHINFO's regions, only those a file backs
	regionInfoSize         = 96
	regionWithPathSize     = regionInfoSize + vnodeInfoSize + unix.PathMax
	vmProtExecute          = 4
)

// ProcLibraries are the files a process has mapped executable, each once, but its own program: its address space
// walked region by region with proc_pidinfo PROC_PIDREGIONPATHINFO2, which passes over memory no file backs and the
// shared cache, where macOS keeps its own libraries (so these are the others: an app's frameworks, Homebrew's, a
// Python module, anything pushed in). ok false when it cannot be read (another user's process, one gone).
func ProcLibraries(pid int32, program string) ([]LoadedLibrary, bool) {
	buf := make([]byte, regionWithPathSize)
	le := binary.LittleEndian
	var out []LoadedLibrary
	seen := map[string]bool{}
	addr := uint64(0)
	for try := 0; try < 100000; try++ {
		n, e := procInfo(procCallPidInfo, int(pid), procPidRegionPathInfo2, addr, buf)
		if e != 0 || n != regionWithPathSize {
			if try == 0 {
				return nil, false
			}
			break // past the last one
		}
		start, size := le.Uint64(buf[80:]), le.Uint64(buf[88:])
		path := buf[regionInfoSize+vnodeInfoSize:]
		end := 0
		for end < len(path) && path[end] != 0 {
			end++
		}
		if le.Uint32(buf[0:])&vmProtExecute != 0 && end > 0 {
			p := procText(path[:end])
			if p != program && !seen[p] {
				seen[p] = true
				out = append(out, LoadedLibrary{Path: p, Deleted: le.Uint16(buf[regionInfoSize+6:]) == 0})
			}
		}
		if start+size <= addr {
			break
		}
		addr = start + size
	}
	return out, true
}

// parseProcargs2 reads KERN_PROCARGS2's answer: argc, the program's path, its padding, then argc strings.
func parseProcargs2(b []byte) []string {
	args, _ := splitProcargs2(b)
	return args
}

// splitProcargs2 reads KERN_PROCARGS2's answer: argc, the program's path, its padding, argc strings, then every
// string after them but the empty ones: the environment's and the loader's apple[] strings (see ProcEnvironment).
func splitProcargs2(b []byte) (args, env []string) {
	size := len(b)
	args, env = []string{}, []string{}
	if size < 4 {
		return
	}
	argc := int(int32(binary.LittleEndian.Uint32(b)))
	i := 4
	for i < size && b[i] != 0 { // the program path
		i++
	}
	for i < size && b[i] == 0 { // its padding
		i++
	}
	next := func() string {
		j := i
		for j < size && b[j] != 0 {
			j++
		}
		s := procText(b[i:j])
		i = j + 1
		return s
	}
	for len(args) < argc && i < size {
		args = append(args, next())
	}
	if len(args) < argc {
		return // cut short: what follows is not the environment
	}
	for i < size {
		if s := next(); s != "" {
			env = append(env, s)
		}
	}
	return
}

// ScriptNames are the program a process runs when its executable is an interpreter: `python3.14
// /opt/homebrew/bin/pip3 install` is pip3, `python3 -m pip` is pip, `node /opt/homebrew/bin/npm` is npm.
func ScriptNames(args []string) map[string]bool {
	out := map[string]bool{}
	if len(args) > 1 && (len(args[1]) == 0 || args[1][0] != '-') {
		out[filepath.Base(args[1])] = true
	}
	for m, a := range args {
		if a == "-m" {
			if m+1 < len(args) {
				out[args[m+1]] = true
			}
			break
		}
	}
	return out
}

// KernelBootTime is when this Mac started (kern.boottime), to the second.
func KernelBootTime() (time.Time, bool) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(tv.Sec, 0), true
}

// procText is the text of b, each byte that is not UTF-8 replaced (as Swift's String(decoding:as:) does).
func procText(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]rune, 0, len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		out = append(out, r)
		b = b[n:]
	}
	return string(out)
}
