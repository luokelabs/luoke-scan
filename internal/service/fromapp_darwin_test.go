//go:build darwin

package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The test binary also plays the other processes (helperRole picks which; see TestFromAppHelper).
const helperRole = "LUOKE_SCAN_FROMAPP_ROLE"

func pair(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	return fds[0], fds[1]
}

// answerOnce reads one line on fd and answers it with its id, as the main body does for a request it does not know.
func answerOnce(fd int) {
	if line, err := fdReadLine(fd, 5*time.Second); err == nil {
		fdWriteLine(fd, answerLine(line, `{"status":"failed","why":"不认识的请求"}`))
	}
}

func fixedPath(pid int, path string) func(int) (string, error) {
	return func(p int) (string, error) {
		if p == pid {
			return path, nil
		}
		return "/somewhere/else", nil
	}
}

func signedOK(peer) string { return "" }

// pending: something is waiting to be read on fd.
func pending(fd int) bool {
	n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 0)
	return err == nil && n > 0
}

// helper starts this test binary as the other process (role: see TestFromAppHelper) with fd as its descriptor 3.
func helper(t *testing.T, role string, fd int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFromAppHelper$")
	cmd.Env = append(os.Environ(), helperRole+"="+role)
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(fd), "body")}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

const appMainPath = "/Applications/螺壳.app/Contents/MacOS/LuokeCore"

func TestCheckLauncherTakesTheParentThatAnswers(t *testing.T) {
	scan, body := pair(t)
	go answerOnce(body)
	me := os.Getpid() // this process holds the other end and answers: it plays the parent
	if why := checkLauncher(scan, func() int { return me }, fixedPath(me, appMainPath), []string{appMainPath}, signedOK); why != "" {
		t.Fatalf("refused: %s", why)
	}
}

func TestCheckLauncherRefusesAnotherProgramBeforeSayingAnything(t *testing.T) {
	scan, body := pair(t)
	me := os.Getpid()
	why := checkLauncher(scan, func() int { return me }, fixedPath(me, "/tmp/x.app/Contents/MacOS/LuokeCore"),
		[]string{appMainPath}, signedOK)
	if !strings.Contains(why, "起它的是 /tmp/x.app") || pending(body) {
		t.Fatalf("got %q, said something: %v", why, pending(body))
	}
}

func TestCheckLauncherRefusesAParentNotSignedAsTheApp(t *testing.T) {
	scan, body := pair(t)
	me := os.Getpid()
	named := 0
	why := checkLauncher(scan, func() int { return me }, fixedPath(me, appMainPath), []string{appMainPath},
		func(p peer) string { named = p.pid; return "起它的程序不是签好名的螺壳" })
	if !strings.Contains(why, "不是签好名的螺壳") || named != me || pending(body) {
		t.Fatalf("got %q for pid %d, said something: %v", why, named, pending(body))
	}
}

func TestCheckLauncherRefusesWithoutASocket(t *testing.T) {
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	ok := func(int) (string, error) { return "/a", nil }
	if why := checkLauncher(p[0], os.Getpid, ok, []string{"/a"}, signedOK); !strings.Contains(why, "没有螺壳给的通道") {
		t.Fatalf("pipe: %q", why)
	}
	if why := checkLauncher(1000, os.Getpid, ok, []string{"/a"}, signedOK); !strings.Contains(why, "没有螺壳给的通道") {
		t.Fatalf("closed descriptor: %q", why)
	}
}

func TestCheckLauncherRefusesWhenNobodyAnswers(t *testing.T) {
	old := helloWait
	helloWait = 200 * time.Millisecond
	defer func() { helloWait = old }()
	scan, _ := pair(t)
	me := os.Getpid()
	if why := checkLauncher(scan, func() int { return me }, fixedPath(me, "/a"), []string{"/a"}, signedOK); !strings.Contains(why, "没答") {
		t.Fatalf("got %q", why)
	}
}

// A line put on the channel before the check (an answer written ahead, then exec) doesn't carry the new id.
func TestCheckLauncherRefusesAnAnswerWrittenAhead(t *testing.T) {
	scan, body := pair(t)
	fdWriteLine(body, []byte(`{"id":0,"result":{"status":"ok"}}`))
	me := os.Getpid()
	if why := checkLauncher(scan, func() int { return me }, fixedPath(me, "/a"), []string{"/a"}, signedOK); !strings.Contains(why, "答的不是这一句") {
		t.Fatalf("got %q", why)
	}
}

// Another process used the other end last: refused before the hello.
func TestCheckLauncherRefusesWhenAnotherProcessHoldsTheOtherEnd(t *testing.T) {
	scan, body := pair(t)
	helper(t, "poke", body)
	if line, err := fdReadLine(scan, 5*time.Second); err != nil || string(line) != "x" {
		t.Fatalf("helper: %q %v", line, err)
	}
	me := os.Getpid()
	if why := checkLauncher(scan, func() int { return me }, fixedPath(me, "/a"), []string{"/a"}, signedOK); !strings.Contains(why, "通道那头不是起它的进程") {
		t.Fatalf("got %q", why)
	}
}

// Another process answers the hello, with the right id (the parent turned itself into the main body with exec and
// left the talking to someone else): the answer names that process, not the parent.
func TestCheckLauncherRefusesAnAnswerFromAnotherProcess(t *testing.T) {
	scan, body := pair(t)
	helper(t, "answer-late", body)
	me := os.Getpid()
	if why := checkLauncher(scan, func() int { return me }, fixedPath(me, "/a"), []string{"/a"}, signedOK); !strings.Contains(why, "答话的不是起它的进程") {
		t.Fatalf("got %q", why)
	}
}

// The parent turns itself into the main body with exec (same pid, the right program, signed) and leaves the answering
// to a process of its own: refused (here /bin/sleep plays the main body).
func TestCheckLauncherRefusesAParentThatBecameTheMainBodyByExec(t *testing.T) {
	scan, body := pair(t)
	echo := `IFS= read -r l <&3; id=$(printf %s "$l" | sed 's/.*"id":"\([0-9a-f]*\)".*/\1/'); printf '{"id":"%s","result":{}}\n' "$id" >&3`
	cmd := exec.Command("/bin/sh", "-c", `printf 'x\n' >&3; (sleep 0.5; `+echo+`) & exec /bin/sleep 5`)
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(body), "body")}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	if line, err := fdReadLine(scan, 5*time.Second); err != nil || string(line) != "x" {
		t.Fatalf("shell: %q %v", line, err)
	}
	pid := cmd.Process.Pid
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if p, _ := pidPath(pid); p == "/bin/sleep" {
			break
		}
	}
	why := checkLauncher(scan, func() int { return pid }, pidPath, []string{"/bin/sleep"}, func(p peer) string {
		if path, _ := pidPath(p.pid); path == "/bin/sleep" {
			return ""
		}
		return "不是"
	})
	if !strings.Contains(why, "不是起它的进程") && !strings.Contains(why, "没答") {
		t.Fatalf("got %q", why)
	}
}

func TestPeerIsThisProcessForItsOwnPair(t *testing.T) {
	scan, _ := pair(t)
	p, ok := peerOf(scan)
	if !ok || p.pid != os.Getpid() || p.version == 0 {
		t.Fatalf("got %+v %v", p, ok)
	}
}

// A build without a release team checks no signature; one with a team takes only a program signed by it (this test
// binary is signed ad hoc), and never a team or identifier that would change what the requirement says.
func TestSignedCheckFollowsTheReleaseTeam(t *testing.T) {
	scan, _ := pair(t)
	p, _ := peerOf(scan)
	if why := signedCheck("", []string{"ai.luoke.core"})(p); why != "" {
		t.Fatalf("development build: %q", why)
	}
	if why := signedCheck("ABCDE12345", []string{"ai.luoke.core"})(p); !strings.Contains(why, "不是签好名的螺壳") {
		t.Fatalf("release build, ad hoc parent: %q", why)
	}
	if why := signedAs("ABCDE12345", []string{`ai.luoke.core" or anchor trusted or identifier "x`}, p); why != "认不出螺壳的标识" {
		t.Fatalf("identifier: %q", why)
	}
	if why := signedAs(`X" or anchor trusted or "`, []string{"ai.luoke.core"}, p); why != "认不出螺壳的标识" {
		t.Fatalf("team: %q", why)
	}
	if plain(`a"b`) || plain("") || !plain("ai.luoke.scan-2") {
		t.Fatal("plain")
	}
}

func TestAnswerLineEchoesTheID(t *testing.T) {
	for in, want := range map[string]string{
		`{"id":"9f2c","method":"hello"}`: `{"id":"9f2c","result":{}}`,
		`{"id":7,"method":"hello"}`:      `{"id":7,"result":{}}`,
		`not json`:                       `{"id":null,"result":{}}`,
	} {
		if got := string(answerLine([]byte(in), `{}`)); got != want {
			t.Errorf("%s: got %s", in, got)
		}
	}
}

// A round started the way `mcp` starts one (startVouched) finds its parent with the real system calls, even when the
// parent goes on at once; the round closes the channel after looking and the parent stops waiting.
func TestStartVouchedRoundFindsItsParent(t *testing.T) {
	out := filepath.Join(t.TempDir(), "round.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^TestFromAppHelper$")
	cmd.Env = append(os.Environ(), helperRole+"=round", "LUOKE_SCAN_FROMAPP_OUT="+out)
	started := time.Now()
	if !startVouched(cmd) {
		t.Fatal("not started")
	}
	if d := time.Since(started); d > 4*time.Second {
		t.Fatalf("waited %v for the round to look", d)
	}
	cmd.Wait()
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "ok" {
		t.Fatalf("round said %q", got)
	}
}

// TestFromAppHelper is not a test: it is the other process of the tests above.
func TestFromAppHelper(t *testing.T) {
	switch os.Getenv(helperRole) {
	case "poke":
		fdWriteLine(3, []byte("x"))
		time.Sleep(5 * time.Second)
	case "answer-late":
		time.Sleep(500 * time.Millisecond)
		answerOnce(3)
	case "round":
		self, _ := pidPath(os.Getppid()) // the parent is this same test binary (ad hoc signed: the signature isn't checked here)
		why := checkLauncher(AppFD, os.Getppid, pidPath, []string{self}, signedOK)
		unix.Close(AppFD)
		if why == "" {
			why = "ok"
		}
		os.WriteFile(os.Getenv("LUOKE_SCAN_FROMAPP_OUT"), []byte(why+"\n"), 0o600)
	default:
		t.Skip("helper for the FromApp tests")
	}
}

func TestAppMainReadsTheBundleExecutableAndIdentifier(t *testing.T) {
	app := filepath.Join(t.TempDir(), "螺壳.app", "Contents")
	os.MkdirAll(filepath.Join(app, "Helpers"), 0o755)
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>螺壳</string>
<key>LSUIElement</key><true/>
<key>CFBundleExecutable</key><string>LuokeCore</string>
<key>CFBundleIdentifier</key><string>ai.example.app</string>
</dict></plist>`
	os.WriteFile(filepath.Join(app, "Info.plist"), []byte(plist), 0o644)
	got, identifier, err := appMain(filepath.Join(app, "Helpers", "luoke-scan"))
	if err != nil || got != filepath.Join(app, "MacOS", "LuokeCore") || identifier != "ai.example.app" {
		t.Fatalf("got %q %q, %v", got, identifier, err)
	}
	if _, _, err := appMain("/usr/local/bin/luoke-scan"); err == nil {
		t.Fatal("outside an app")
	}
	os.WriteFile(filepath.Join(app, "Info.plist"), []byte(strings.Replace(plist, "<string>LuokeCore</string>", "<string>../x</string>", 1)), 0o644)
	if _, _, err := appMain(filepath.Join(app, "Helpers", "luoke-scan")); err == nil {
		t.Fatal("a path for a name")
	}
	os.WriteFile(filepath.Join(app, "Info.plist"), []byte(strings.Replace(plist, "<key>CFBundleIdentifier</key><string>ai.example.app</string>", "", 1)), 0o644)
	if _, _, err := appMain(filepath.Join(app, "Helpers", "luoke-scan")); err == nil {
		t.Fatal("no identifier")
	}
}

func TestPidPathIsTheRunningFile(t *testing.T) {
	p, err := pidPath(os.Getpid())
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if err != nil || p != exe {
		t.Fatalf("got %q, %v; want %q", p, err, exe)
	}
}
