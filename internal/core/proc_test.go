package core

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A tool stays in this program's process group, so that ending the group (as luoke's main app ends an idle job that
// does not stop on TERM) ends the tool too.
func TestToolsStayInOurProcessGroup(t *testing.T) {
	r := Run("/bin/sh", []string{"-c", "ps -o pgid= -p $$"}, RunOpts{Timeout: 10 * time.Second})
	if r.Status != 0 {
		t.Fatalf("status %d: %s", r.Status, r.Stderr)
	}
	got, err := strconv.Atoi(strings.TrimSpace(r.Stdout))
	if err != nil {
		t.Fatalf("pgid %q", r.Stdout)
	}
	if got != syscall.Getpgrp() {
		t.Errorf("tool in process group %d, this program in %d", got, syscall.Getpgrp())
	}
}

func TestTimeoutStopsTheTool(t *testing.T) {
	start := time.Now()
	r := Run("/bin/sleep", []string{"30"}, RunOpts{Timeout: 300 * time.Millisecond})
	if !r.TimedOut || r.Cancelled || time.Since(start) > 2*time.Second {
		t.Errorf("sleep: %+v after %s", r, time.Since(start))
	}
	// One that ignores TERM is killed two seconds later.
	start = time.Now()
	r = Run("/bin/sh", []string{"-c", "trap '' TERM; while :; do :; done"}, RunOpts{Timeout: 300 * time.Millisecond})
	if took := time.Since(start); !r.TimedOut || took < 2*time.Second || took > 5*time.Second {
		t.Errorf("ignoring TERM: %+v after %s", r, took)
	}
}

func TestCancelledRunStops(t *testing.T) {
	start := time.Now()
	r := Run("/bin/sleep", []string{"30"}, RunOpts{Timeout: 30 * time.Second, Cancelled: func() bool { return time.Since(start) > 200*time.Millisecond }})
	if !r.Cancelled || time.Since(start) > 3*time.Second {
		t.Errorf("%+v after %s", r, time.Since(start))
	}
}
