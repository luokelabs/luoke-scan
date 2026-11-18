package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// This test process, read back from the process table: its parent, user, program, start and arguments.
func TestProcSnapshotFindsThisProcess(t *testing.T) {
	all := ProcSnapshot()
	if len(all) < 2 {
		t.Fatalf("process list: %d", len(all))
	}
	var me *ProcInfo
	for i := range all {
		if all[i].PID == int32(os.Getpid()) {
			me = &all[i]
		}
	}
	if me == nil {
		t.Fatal("this process is not in the list")
	}
	if me.PPID != int32(os.Getppid()) || me.UID != uint32(os.Geteuid()) {
		t.Fatalf("ppid %d uid %d; want %d %d", me.PPID, me.UID, os.Getppid(), os.Geteuid())
	}
	exe, _ := os.Executable()
	if Canonical(me.Path) != Canonical(exe) {
		t.Fatalf("path %q; want %q", me.Path, exe)
	}
	if age := time.Since(me.Started); age < -2*time.Second || age > 10*time.Minute {
		t.Fatalf("started %v ago", age)
	}
	args, ok := ProcArguments(int32(os.Getpid()))
	if !ok || !reflect.DeepEqual(args, os.Args) {
		t.Fatalf("arguments %q %v; want %q", args, ok, os.Args)
	}
	if boot, ok := KernelBootTime(); !ok || boot.After(me.Started.Add(time.Second)) || time.Since(boot) > 5*365*24*time.Hour {
		t.Fatalf("boot time %v %v", boot, ok)
	}
}

func TestProcPathOfNoProcess(t *testing.T) {
	if p, ok := ProcPath(-5); ok || p != "" {
		t.Fatalf("%q %v", p, ok)
	}
	if a, ok := ProcArguments(999999); ok {
		t.Fatalf("%q", a)
	}
}

func TestParseProcargs2(t *testing.T) {
	b := []byte{3, 0, 0, 0}
	b = append(b, "/usr/bin/python3\x00\x00\x00\x00python3\x00-m\x00pip\x00HOME=/x\x00"...)
	got := parseProcargs2(b)
	if !reflect.DeepEqual(got, []string{"python3", "-m", "pip"}) {
		t.Fatalf("%q", got)
	}
	if !reflect.DeepEqual(ScriptNames(got), map[string]bool{"pip": true}) {
		t.Fatalf("%v", ScriptNames(got))
	}
	n := ScriptNames([]string{"python3.14", "/opt/homebrew/bin/pip3", "install"})
	if !n["pip3"] || len(n) != 1 {
		t.Fatalf("%v", n)
	}
}

func TestParseProcargs2Environment(t *testing.T) {
	b := []byte{2, 0, 0, 0}
	b = append(b, "/opt/bin/tool\x00\x00\x00tool\x00\x00HOME=/x\x00\x00DYLD_INSERT_LIBRARIES=/tmp/a.dylib\x00\x00\x00ptr_munge=\x00main_stack=\x00"...)
	args, env := splitProcargs2(b)
	if !reflect.DeepEqual(args, []string{"tool", ""}) { // an empty argument counts as one
		t.Fatalf("args %q", args)
	}
	// An empty string in the environment looks like the zeros before the loader's apple[] strings: all are read
	if !reflect.DeepEqual(env, []string{"HOME=/x", "DYLD_INSERT_LIBRARIES=/tmp/a.dylib", "ptr_munge=", "main_stack="}) {
		t.Fatalf("env %q", env)
	}
	// argc says more than there is: nothing after it is taken for the environment
	short := append([]byte{5, 0, 0, 0}, "/opt/bin/tool\x00tool\x00A=1\x00"...)
	if args, env := splitProcargs2(short); len(env) != 0 || len(args) != 2 {
		t.Fatalf("cut short: %q %q", args, env)
	}
	if args, env := splitProcargs2([]byte{1, 0}); len(args) != 0 || len(env) != 0 {
		t.Fatalf("too short: %q %q", args, env)
	}
}

const procHelperRole = "LUOKE_SCAN_PROC_HELPER"

// TestProcHelper is the other process of the tests below (this test binary started again): it waits to be looked at.
func TestProcHelper(t *testing.T) {
	if os.Getenv(procHelperRole) == "" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

// procHelper starts this test binary as a process to look at, with env and in dir ("" this one's).
func procHelper(t *testing.T, dir string, env ...string) *exec.Cmd {
	t.Helper()
	return procHelperFrom(t, os.Args[0], dir, env...)
}

// procHelperFrom is procHelper with program (a copy of this test binary).
func procHelperFrom(t *testing.T, program, dir string, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(program, "-test.run=^TestProcHelper$")
	cmd.Env = append([]string{procHelperRole + "=wait"}, env...)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// A process of this user started with an environment: read back as it was given, then the loader's apple[] strings
// (this test binary is not one of Apple's programs, whose environment macOS leaves out).
func TestProcEnvironmentOfAChild(t *testing.T) {
	cmd := procHelper(t, "", "LUOKE_SCAN_TEST_MARK=1")
	env := procEnvironmentOnceExeced(t, int32(cmd.Process.Pid), "LUOKE_SCAN_TEST_MARK=1")
	if len(env) < 2 || env[0] != procHelperRole+"=wait" || env[1] != "LUOKE_SCAN_TEST_MARK=1" {
		t.Fatalf("environment %q", env)
	}
	if _, ok := ProcEnvironment(999999); ok {
		t.Fatal("no such process")
	}
}

// A process's working directory, read back.
func TestProcCwdOfAChild(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := procHelper(t, dir)
	var cwd string
	var ok bool
	for try := 0; try < 100; try++ { // until the child has exec'd and changed into dir
		if cwd, ok = ProcCwd(int32(cmd.Process.Pid)); ok && cwd == dir {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok || cwd != dir {
		t.Fatalf("working directory %q %v; want %q", cwd, ok, dir)
	}
	if _, ok := ProcCwd(999999); ok {
		t.Fatal("no such process")
	}
}

// The files a process maps as code, read back: a copy of this test binary run as a process is its program, there and
// then deleted (its code runs on); asked with that program, it is left out.
func TestProcLibrariesOfAChild(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	copy := filepath.Join(dir, "helper-copy")
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copy, data, 0o755); err != nil {
		t.Fatal(err)
	}
	pid := int32(procHelperFrom(t, copy, "").Process.Pid)
	for try := 0; try < 100; try++ { // until the child has exec'd
		if p, _ := ProcPath(pid); p == copy {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	find := func(program string) (LoadedLibrary, bool) {
		t.Helper()
		libs, ok := ProcLibraries(pid, program)
		for try := 0; !ok && try < 100; try++ { // a busy machine: proc_info has answered nothing for a second in a full run
			time.Sleep(50 * time.Millisecond)
			libs, ok = ProcLibraries(pid, program)
		}
		if !ok {
			path, known := ProcPath(pid)
			t.Fatalf("not readable after 5 s: the child is alive: %v, its program: %q (known: %v)", syscall.Kill(int(pid), 0) == nil, path, known)
		}
		for _, l := range libs {
			if l.Path == copy {
				return l, true
			}
		}
		return LoadedLibrary{}, false
	}
	if l, ok := find(""); !ok || l.Deleted {
		t.Fatalf("the program's file: %+v %v", l, ok)
	}
	if err := os.Remove(copy); err != nil {
		t.Fatal(err)
	}
	if l, ok := find(""); !ok || !l.Deleted {
		t.Fatalf("deleted: %+v %v", l, ok)
	}
	if l, ok := find(copy); ok {
		t.Fatalf("its own program: %+v", l)
	}
	if _, ok := ProcLibraries(999999, ""); ok {
		t.Fatal("no such process")
	}
}

// An empty string in the environment (execve takes one; os/exec drops it) does not hide what comes after it.
func TestProcEnvironmentPastAnEmptyString(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	fds := []uintptr{devnull.Fd(), devnull.Fd(), devnull.Fd()}
	pid, err := syscall.ForkExec(os.Args[0], []string{os.Args[0], "-test.run=^TestProcHelper$"},
		&syscall.ProcAttr{Env: []string{procHelperRole + "=wait", "", "LUOKE_SCAN_TEST_MARK=after-empty"}, Files: fds})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Kill(pid, syscall.SIGKILL)
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, 0, nil)
	})
	env := procEnvironmentOnceExeced(t, int32(pid), "LUOKE_SCAN_TEST_MARK=after-empty")
	if len(env) < 2 || env[0] != procHelperRole+"=wait" || env[1] != "LUOKE_SCAN_TEST_MARK=after-empty" {
		t.Fatalf("environment %q", env)
	}
}

// procEnvironmentOnceExeced: the environment of pid once it has exec'd (before, it is a copy of this process), told by
// mark being in it.
func procEnvironmentOnceExeced(t *testing.T, pid int32, mark string) []string {
	t.Helper()
	var env []string
	for try := 0; try < 100; try++ {
		var ok bool
		if env, ok = ProcEnvironment(pid); ok {
			for _, e := range env {
				if e == mark {
					return env
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("environment of %d never had %s: %q", pid, mark, env)
	return nil
}
