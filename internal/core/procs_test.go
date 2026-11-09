package core

import (
	"os"
	"reflect"
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
