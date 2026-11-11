package core

import (
	"bytes"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// ProcResult is what a tool that ran answered. Status -1: it did not finish on its own (killed, timed out, could
// not start), never taken as one of its own exit codes.
type ProcResult struct {
	Status    int
	Stdout    string
	Stderr    string
	TimedOut  bool
	Cancelled bool
}

// GitEnv is the environment git runs with: none of the user's settings, no prompts, no optional locks.
var GitEnv = map[string]string{
	"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
	"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C",
}

// RunOpts are a run's optional settings.
type RunOpts struct {
	Dir       string
	Env       map[string]string // nil: this process's environment
	Timeout   time.Duration     // 0: 20 s
	Stdin     []byte
	Cancelled func() bool
}

// Run starts tool with args, standard input empty (or Stdin), and waits for it within the timeout: then TERM, two
// seconds later KILL. A run cancelled meanwhile stops the same way. The tool stays in this program's process group:
// luoke's main app ends an idle job by killing that whole group (the job, and whatever it started) when it does not
// stop on TERM; a group of the tool's own would outlive it. A tool's own children that outlive it on a timeout go with
// that group too.
func Run(tool string, args []string, o RunOpts) ProcResult {
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	cmd := exec.Command(tool, args...)
	cmd.Dir = o.Dir
	if o.Env != nil {
		cmd.Env = []string{}
		for k, v := range o.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	if o.Stdin != nil {
		cmd.Stdin = bytes.NewReader(o.Stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Start(); err != nil {
		return ProcResult{Status: -1}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(o.Timeout)
	stopped := false
	for {
		wait := time.Until(deadline)
		if wait <= 0 {
			break
		}
		if wait > 500*time.Millisecond {
			wait = 500 * time.Millisecond
		}
		select {
		case <-done:
			return finished(cmd, &out, &errb, o)
		case <-time.After(wait):
		}
		if o.Cancelled != nil && o.Cancelled() {
			stopped = true
			break
		}
	}
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return ProcResult{Status: -1, TimedOut: true, Cancelled: stopped}
}

func finished(cmd *exec.Cmd, out, errb *bytes.Buffer, o RunOpts) ProcResult {
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if ws.Signaled() || ws.ExitStatus() == 128+int(syscall.SIGTERM) {
		if o.Cancelled != nil && o.Cancelled() {
			return ProcResult{Status: -1, TimedOut: true, Cancelled: true}
		}
		if ws.Signaled() {
			return ProcResult{Status: -1}
		}
	}
	return ProcResult{Status: ws.ExitStatus(), Stdout: out.String(), Stderr: errb.String()}
}

// LowerPriority is for the jobs nobody waits on while the user may be at the Mac (scan, its quick look, update, and
// the round scan_now starts): the CPU at nice 10 and disk I/O at the utility tier, for this process and what it starts
// afterwards (both are inherited). The user's apps come first and a round still finishes: the background tier made a
// round 3-30 times slower on a busy Mac and could outlast luoke-core's 60-minute limit. Not for mcp: it answers a
// click. Whether each took (nice fails when this process already runs nicer).
func LowerPriority() (cpu, disk bool) {
	return Nice(10) == nil, SetDiskPolicy(IOPolicyUtility) == nil
}

// IsExecutable says whether path is a file this user may run.
func IsExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir() && syscall.Access(path, 1) == nil // X_OK
}
