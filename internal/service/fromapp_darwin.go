//go:build darwin

package service

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <Security/Security.h>

// The kernel's audit token for the program the other end's process (LOCAL_PEERPID) runs now.
static int luoke_peer_token(int fd, audit_token_t *t) {
	socklen_t n = sizeof *t;
	return getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, t, &n) == 0 && n == sizeof *t ? 0 : -1;
}

// 0 when the program the token names is valid now and meets the requirement; 1 no such program (gone, or it ran exec
// since), 2 the requirement doesn't compile, 3 it doesn't meet it.
static int luoke_signed(const audit_token_t *t, const char *requirement) {
	CFDataRef data = CFDataCreate(NULL, (const UInt8 *)t, sizeof *t);
	const void *keys[] = {kSecGuestAttributeAudit};
	const void *values[] = {data};
	CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);
	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
	CFRelease(attributes);
	CFRelease(data);
	if (st != errSecSuccess || code == NULL) return 1;
	CFStringRef text = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
	SecRequirementRef req = NULL;
	st = text ? SecRequirementCreateWithString(text, kSecCSDefaultFlags, &req) : errSecParam;
	if (text) CFRelease(text);
	if (st != errSecSuccess || req == NULL) { CFRelease(code); return 2; }
	st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	CFRelease(req);
	CFRelease(code);
	return st == errSecSuccess ? 0 : 3;
}

// This program's own signing team (which = 0) or identifier (which = 1); NULL when it has none. The caller frees it.
static char *luoke_own(int which) {
	SecCodeRef self = NULL;
	SecStaticCodeRef code = NULL;
	CFDictionaryRef info = NULL;
	char *out = NULL;
	if (SecCodeCopySelf(kSecCSDefaultFlags, &self) != errSecSuccess) return NULL;
	if (SecCodeCopyStaticCode(self, kSecCSDefaultFlags, &code) == errSecSuccess &&
	    SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info) {
		CFTypeRef v = CFDictionaryGetValue(info, which == 0 ? kSecCodeInfoTeamIdentifier : kSecCodeInfoIdentifier);
		char buf[256];
		if (v && CFGetTypeID(v) == CFStringGetTypeID() && CFStringGetCString(v, buf, sizeof buf, kCFStringEncodingUTF8))
			out = strdup(buf);
	}
	if (info) CFRelease(info);
	if (code) CFRelease(code);
	CFRelease(self);
	return out;
}
*/
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/luokelabs/luoke-scan/internal/core"
	"golang.org/x/sys/unix"
)

// The installed luoke-scan runs under 螺壳's Full Disk Access whoever starts it (the system counts a program by where it
// is, in 螺壳.app), so it checks who did. 螺壳's main body starts it with a socket on descriptor 3: the channel of
// host.go for `mcp`, and one that answers every request with failed for the idle jobs (`螺壳 --run-tool`). The check:
//
//  1. descriptor 3 is a Unix stream socket;
//  2. the other end is held by this process's parent (LOCAL_PEERPID: the last process to read or write it), and the
//     parent runs, right now, the main program of this same app: its signature (by the kernel's audit token for it, so
//     the program running, not one on disk) is Apple-anchored, from luoke's release team (core.ReleaseTeam), with the
//     app's identifier, and its file (proc_pidpath) is Contents/MacOS/<CFBundleExecutable>. A build without a release
//     team (development and local trial builds, signed ad hoc) skips the signature and keeps the rest; the team is
//     compiled in, so nothing at run time (an environment variable, a re-signed copy) turns a release build into one;
//  3. only then a hello goes out whose id is new random bytes, and the line that comes back carries that id;
//  4. after it the other end is still the parent, and the parent still runs the same image (the audit token's pid
//     version, which changes with every exec).
//
// Why in this order: the audit token for a socket's other end is the one of the program its pid runs when asked, not
// when it wrote (measured on macOS 27), so checking after the answer alone lets a parent answer, then exec into the
// main body (same pid). Here the parent must already be the main body before there is anything to answer, the answer
// can't be written ahead (the id is new), and a process the parent left holding the other end answers under its own
// pid. A round the agent asks for (`scan --for-agent`) is started by `luoke-scan mcp`, which passed this check itself;
// for it the parent may also be this same program, signed as it is (StartDetached gives it a channel and answers on it).

// AppFD is the descriptor 螺壳 hands over.
const AppFD = 3

// helloWait is how long the other end may take to answer the one line.
var helloWait = 5 * time.Second

// FromApp is "" when 螺壳 started this process (allowSelf: or this same program did); otherwise why not, for a person.
// After it, descriptor 3 is closed unless it is the channel to the main body (LUOKE_HOST_FD=3), which children do not get.
func FromApp(allowSelf bool) string {
	self, err := pidPath(os.Getpid())
	if err != nil {
		return "读不到自己的程序路径"
	}
	main, identifier, err := appMain(self)
	if err != nil {
		return err.Error()
	}
	allowed, identifiers := []string{main}, []string{identifier}
	if allowSelf {
		allowed = append(allowed, self)
		if own := ownSigning(1); own != "" {
			identifiers = append(identifiers, own)
		}
	}
	why := checkLauncher(AppFD, os.Getppid, pidPath, allowed, signedCheck(core.ReleaseTeam, identifiers))
	if why == "" {
		if os.Getenv(HostFDEnv) == "3" {
			unix.CloseOnExec(AppFD)
		} else {
			unix.Close(AppFD)
		}
	}
	return why
}

// checkLauncher runs steps 1–4 on fd; ppid, path and signed ("" when the peer's program is signed as one allowed)
// are the system's, swapped in tests.
func checkLauncher(fd int, ppid func() int, path func(int) (string, error), allowed []string, signed func(peer) string) string {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return "不是螺壳起的（没有螺壳给的通道）"
	}
	if t, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || t != unix.SOCK_STREAM {
		return "不是螺壳起的（通道不对）"
	}
	if sa, err := unix.Getsockname(fd); err != nil {
		return "不是螺壳起的（通道不对）"
	} else if _, ok := sa.(*unix.SockaddrUnix); !ok {
		return "不是螺壳起的（通道不对）"
	}

	parent := ppid()
	before, ok := peerOf(fd)
	if !ok || parent <= 1 || before.pid != parent {
		return "不是螺壳起的（通道那头不是起它的进程）"
	}
	if why := signed(before); why != "" {
		return "不是螺壳起的（" + why + "）"
	}
	p, err := path(parent)
	if err != nil {
		return "不是螺壳起的（读不到起它的程序）"
	}
	found := false
	for _, a := range allowed {
		found = found || p == a
	}
	if !found {
		return "不是螺壳起的（起它的是 " + p + "）"
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "不是螺壳起的（取不到随机数）"
	}
	id := hex.EncodeToString(nonce)
	if fdWriteLine(fd, []byte(`{"id":"`+id+`","method":"hello"}`)) != nil {
		return "不是螺壳起的（通道写不进）"
	}
	line, err := fdReadLine(fd, helloWait)
	if err != nil {
		return "不是螺壳起的（通道那头没答）"
	}
	var reply struct {
		ID any `json:"id"`
	}
	if json.Unmarshal(line, &reply) != nil || reply.ID != id {
		return "不是螺壳起的（答的不是这一句）"
	}
	after, ok := peerOf(fd)
	if !ok || ppid() != parent || after.pid != parent || after.version != before.version {
		return "不是螺壳起的（答话的不是起它的进程）"
	}
	return ""
}

// peer is the process at the other end of a socket and the kernel's audit token for the program it runs now: its pid
// and pid version (changes with exec).
type peer struct {
	pid     int
	version uint32
	token   C.audit_token_t
}

func peerOf(fd int) (peer, bool) {
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return peer{}, false
	}
	var t C.audit_token_t
	if C.luoke_peer_token(C.int(fd), &t) != 0 || int(t.val[5]) != pid {
		return peer{}, false
	}
	return peer{pid: pid, version: uint32(t.val[7]), token: t}, true
}

// signedCheck is the signature step for a build with release team team: none ("") for a build without one, else
// signedAs.
func signedCheck(team string, identifiers []string) func(peer) string {
	if team == "" {
		return func(peer) string { return "" }
	}
	return func(p peer) string { return signedAs(team, identifiers, p) }
}

// signedAs is "" when the peer's program is valid now and signed as one of identifiers: Apple-anchored, from team.
func signedAs(team string, identifiers []string, p peer) string {
	if !plain(team) {
		return "认不出螺壳的标识"
	}
	var ors []string
	for _, id := range identifiers {
		if id == "" || !plain(id) {
			return "认不出螺壳的标识"
		}
		ors = append(ors, `identifier "`+id+`"`)
	}
	if len(ors) == 0 {
		return "认不出螺壳的标识"
	}
	requirement := C.CString(`anchor apple generic and certificate leaf[subject.OU] = "` + team + `" and (` +
		strings.Join(ors, " or ") + `)`)
	defer C.free(unsafe.Pointer(requirement))
	switch C.luoke_signed(&p.token, requirement) {
	case 0:
		return ""
	case 1:
		return "读不到起它的程序的签名"
	case 2:
		return "认不出螺壳的标识"
	default:
		return "起它的程序不是签好名的螺壳"
	}
}

// plain: letters, digits, dots and hyphens only (nothing that changes what a requirement says).
func plain(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return s != ""
}

// ownSigning is this program's signing team (0) or identifier (1); "" when it has none (unsigned).
func ownSigning(which int) string {
	c := C.luoke_own(C.int(which))
	if c == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(c))
	return C.GoString(c)
}

// appMain is the main program of the app this program is in and the app's identifier: <app>/Contents/Helpers/luoke-scan
// → <app>/Contents/MacOS/<CFBundleExecutable>, CFBundleIdentifier, both from <app>/Contents/Info.plist.
func appMain(self string) (string, string, error) {
	helpers := filepath.Dir(self)
	contents := filepath.Dir(helpers)
	if filepath.Base(helpers) != "Helpers" || filepath.Base(contents) != "Contents" {
		return "", "", errors.New("不在螺壳.app 里")
	}
	plist := filepath.Join(contents, "Info.plist")
	name, err := plistString(plist, "CFBundleExecutable")
	if err != nil || name == "" || filepath.Base(name) != name {
		return "", "", errors.New("读不到螺壳的 Info.plist")
	}
	identifier, err := plistString(plist, "CFBundleIdentifier")
	if err != nil || identifier == "" {
		return "", "", errors.New("读不到螺壳的 Info.plist")
	}
	return filepath.Join(contents, "MacOS", name), identifier, nil
}

// plistString reads one top-level string from an XML property list (what 螺壳's build writes).
func plistString(plist, want string) (string, error) {
	f, err := os.Open(plist)
	if err != nil {
		return "", err
	}
	defer f.Close()
	d := xml.NewDecoder(f)
	var key, text string
	next := false
	for {
		tok, err := d.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			text = ""
		case xml.CharData:
			text += string(t)
		case xml.EndElement:
			switch t.Name.Local {
			case "key":
				key, next = text, text == want
				continue
			case "string":
				if next {
					return text, nil
				}
			}
			if key != "" {
				next = false
			}
		}
	}
}

// pidPath is the file a process runs (proc_pidpath, through the proc_info system call; no cgo).
func pidPath(pid int) (string, error) {
	const procInfoCallPidinfo, procPidpathinfo = 2, 11
	buf := make([]byte, 4096) // PROC_PIDPATHINFO_MAXSIZE
	_, _, e := unix.Syscall6(unix.SYS_PROC_INFO, procInfoCallPidinfo, uintptr(pid), procPidpathinfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if e != 0 {
		return "", e
	}
	p := unix.ByteSliceToString(buf)
	if p == "" {
		return "", errors.New("empty path")
	}
	return p, nil
}

func fdWriteLine(fd int, b []byte) error {
	b = append(append([]byte{}, b...), '\n')
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// fdReadLine reads one line a byte at a time (nothing past it is taken from the channel), waiting at most wait.
func fdReadLine(fd int, wait time.Duration) ([]byte, error) {
	tv := unix.NsecToTimeval(wait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	defer unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{})
	var line []byte
	one := make([]byte, 1)
	for len(line) < 1<<16 {
		n, err := unix.Read(fd, one)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errors.New("closed")
		}
		if one[0] == '\n' {
			return line, nil
		}
		line = append(line, one[0])
	}
	return nil, errors.New("line too long")
}

// startVouched starts cmd with a channel on descriptor 3 and answers the one line it sends, so that FromApp(true) in it
// finds this process; then waits (up to helloWait) for it to close the channel, so that this process (`mcp`, which
// exits after its one request) is still its parent when it looks.
func startVouched(cmd *exec.Cmd) bool {
	syscall.ForkLock.RLock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return false
	}
	theirs := os.NewFile(uintptr(fds[1]), "luoke-scan-round")
	cmd.ExtraFiles = []*os.File{theirs} // descriptor 3 in the child
	err = cmd.Start()
	theirs.Close()
	mine := fds[0]
	defer unix.Close(mine)
	if err != nil {
		return false
	}
	if line, err := fdReadLine(mine, helloWait); err == nil {
		fdWriteLine(mine, answerLine(line, `{"status":"failed","why":"扫描自己起的这一轮不代办"}`))
		fdReadLine(mine, helloWait) // it closes its end once it has looked
	}
	return true
}

// answerLine is the answer to the request line: its id back, with result.
func answerLine(request []byte, result string) []byte {
	var r struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(request, &r) != nil || len(r.ID) == 0 {
		r.ID = json.RawMessage("null")
	}
	return []byte(`{"id":` + string(r.ID) + `,"result":` + result + `}`)
}
