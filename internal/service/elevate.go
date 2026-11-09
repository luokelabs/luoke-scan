package service

import (
	"bytes"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The step with administrator rights (luoke-scan-admin), from a terminal through sudo (luoke-scan system --trash).
// What runs as root is settled on root's side: the step is copied into a folder only root can write, its signature is
// checked there against luoke's release (Developer ID, identifier ai.luoke.scan.admin), and the copy runs with an
// empty environment. From the agent's card the dialog is 螺壳's main body's (Config.Elevate, set at integration).

const (
	adminIdentifier = "ai.luoke.scan.admin"
	badSignature    = 72
	stepFailed      = 73
)

// adminRequirement is Developer ID only, luoke's Team.
var adminRequirement = `=anchor apple generic and identifier "` + adminIdentifier + `" and certificate leaf[subject.OU] = "` +
	core.ReleaseTeam + `" and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]`

// ShellQuote quotes for sh.
func ShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// AdminHelperPath is luoke-scan-admin beside this program, from the kernel's record of what this process runs.
func AdminHelperPath() (string, bool) {
	me, ok := core.ProcPath(int32(os.Getpid()))
	if !ok {
		return "", false
	}
	return filepath.Join(filepath.Dir(me), "luoke-scan-admin"), true
}

// AdminCommand is what root runs, as one shell command: a folder of root's own, the step copied into it (never through
// a link) and checked there -- a plain file, its signature -- then run with nothing of this environment. A failed
// check exits 70-72, the step itself 73 (sudo's own 1: it ran nothing).
func AdminCommand(helper string, args []string) string {
	copy := `"$d/luoke-scan-admin"`
	h := ShellQuote(helper)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = ShellQuote(a)
	}
	return strings.Join([]string{
		"umask 077",
		"d=$(/usr/bin/mktemp -d /private/var/tmp/luoke-scan-admin.XXXXXXXX) || exit 70",
		`trap '/bin/rm -rf "$d"' EXIT`,
		"[ ! -L " + h + " ] && [ -f " + h + " ] && [ $(/usr/bin/stat -f %z " + h + ") -lt 104857600 ] || exit 71",
		"( ulimit -f 204800; /bin/cp -X -P " + h + " " + copy + " ) || exit 71",
		"[ ! -L " + copy + " ] && [ -f " + copy + " ] && [ $(/usr/bin/stat -f %z " + copy + ") -lt 104857600 ] || exit 71",
		"/usr/bin/codesign --verify --strict -R " + ShellQuote(adminRequirement) + " " + copy + " || exit " + strconv.Itoa(badSignature),
		"/usr/bin/env -i PATH=/usr/bin:/bin " + copy + " " + strings.Join(quoted, " ") + " || exit " + strconv.Itoa(stepFailed),
	}, "; ")
}

// SudoElevate: from a terminal, sudo asks for the password there, every time (-k), and root runs AdminCommand.
func SudoElevate(args []string, prompt string) Elevated {
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return Elevated{Kind: "failed", Why: "要在终端里跑：sudo 在终端里问密码"}
	}
	helper, ok := AdminHelperPath()
	if !ok {
		return Elevated{Kind: "failed", Why: "找不到扫描的删除程序"}
	}
	os.Stderr.WriteString(prompt + "\n")
	status, out := runSudo([]string{"-k", "-p", "这台 Mac 的登录密码：", "--", "/bin/sh", "-c", AdminCommand(helper, args)})
	switch status {
	case 0:
		return Elevated{Kind: "done", Output: out}
	case 1:
		return Elevated{Kind: "cancelled"}
	case badSignature:
		return Elevated{Kind: "failed", Why: "删除程序的签名不对，没有动任何东西"}
	case stepFailed:
		return Elevated{Kind: "failed", Why: "删除那一步出错了（原因在上面）"}
	case -1:
		return Elevated{Kind: "failed", Why: "中途停了，已经移走的照样记进清理记录"}
	case -2:
		return Elevated{Kind: "failed", Why: "起不了 sudo"}
	}
	return Elevated{Kind: "failed", Why: "sudo 出错了（" + strconv.Itoa(status) + "）"}
}

// runSudo runs /usr/bin/sudo with this terminal for its prompt and its standard output collected; a plain PATH; "/"
// to work in. This process ignores ^C meanwhile (sudo gets it). The exit status, -1 when it did not exit on its own,
// -2 when it did not start.
func runSudo(args []string) (int, string) {
	cmd := exec.Command("/usr/bin/sudo", args...)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGINT, syscall.SIGQUIT)
	if err := cmd.Start(); err != nil {
		return -2, ""
	}
	cmd.Wait()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Exited() {
		return -1, out.String()
	}
	return ws.ExitStatus(), out.String()
}
