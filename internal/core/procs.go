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

// parseProcargs2 reads KERN_PROCARGS2's answer: argc, the program's path, its padding, then argc strings.
func parseProcargs2(b []byte) []string {
	size := len(b)
	if size < 4 {
		return []string{}
	}
	argc := int(int32(binary.LittleEndian.Uint32(b)))
	i := 4
	for i < size && b[i] != 0 { // the program path
		i++
	}
	for i < size && b[i] == 0 { // its padding
		i++
	}
	args := []string{}
	for len(args) < argc && i < size {
		j := i
		for j < size && b[j] != 0 {
			j++
		}
		args = append(args, procText(b[i:j]))
		i = j + 1
	}
	return args
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
