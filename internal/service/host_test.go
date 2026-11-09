package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// A fake main body on the other end of a socket pair-like pipe pair: it answers the one request it reads.
func TestHostElevate(t *testing.T) {
	// Two pipes make the two directions; the host reads and writes one *os.File, so join them through a socketpair.
	fds, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "scan"), os.NewFile(uintptr(fds[1]), "body")
	defer mine.Close()
	defer theirs.Close()
	h := &host{w: mine, r: bufio.NewReader(mine)}
	go func() {
		line, _ := bufio.NewReader(theirs).ReadBytes('\n')
		var req struct {
			ID     int
			Method string
			Params struct {
				Args   []string
				Prompt string
			}
		}
		json.Unmarshal(line, &req)
		if req.Method != "elevate" || len(req.Params.Args) != 2 || req.Params.Prompt != "要删" {
			theirs.Write([]byte(`{"id": 1, "result": {"status": "failed", "why": "bad request"}}` + "\n"))
			return
		}
		theirs.Write([]byte(`{"id": 99, "result": {"status": "done"}}` + "\n")) // someone else's: skipped
		theirs.Write([]byte(`{"id": 1, "result": {"status": "done", "output": "{\"key\":\"a0\"}\n"}}` + "\n"))
	}()
	got := h.elevate([]string{"--plan", "p-0123456789ab"}, "要删")
	if got.Kind != "done" || got.Output != "{\"key\":\"a0\"}\n" {
		t.Fatalf("%+v", got)
	}
}

func TestHostElevateWithoutMainBody(t *testing.T) {
	if os.Getenv(HostFDEnv) != "" {
		t.Skip("run with a host channel")
	}
	if got := HostElevate(nil, ""); got.Kind != "failed" {
		t.Fatalf("%+v", got)
	}
}

func socketpair() ([2]int, error) { return sysSocketpair() }

// A long session is not cut off by what came before: many messages, together far past MaxMessage, each answered.
func TestServeLongSession(t *testing.T) {
	srv := NewServer("luoke-scan", "test")
	var in strings.Builder
	pad := strings.Repeat("x", 200_000)
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&in, `{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"pad":"%s"}}`+"\n", i, pad)
	}
	var out strings.Builder
	if code := srv.Serve(strings.NewReader(in.String()), &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := strings.Count(out.String(), "\n"); got != 12 {
		t.Fatalf("%d answers", got)
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("y", MaxMessage) + `"}}`
	if code := srv.Serve(strings.NewReader(big), &out); code != 3 {
		t.Fatalf("one message past the limit: exit %d", code)
	}
}

// The main app gave up waiting: failed, and it may have done part of it.
func TestHostElevateUncertain(t *testing.T) {
	fds, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "scan"), os.NewFile(uintptr(fds[1]), "body")
	defer mine.Close()
	defer theirs.Close()
	h := &host{w: mine, r: bufio.NewReader(mine)}
	go func() {
		bufio.NewReader(theirs).ReadBytes('\n')
		theirs.Write([]byte(`{"id": 1, "result": {"status": "failed", "why": "可能已经做了一部分", "uncertain": true}}` + "\n"))
	}()
	got := h.elevate([]string{"--plan", "p-0123456789ab"}, "要删")
	if got.Kind != "failed" || !got.Uncertain || got.Why != "可能已经做了一部分" {
		t.Fatalf("%+v", got)
	}
}

// When the step may still be running, the note it reconciles from stays for the next round; otherwise it goes.
func TestUncertainKeepsTheAdminNote(t *testing.T) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	os.MkdirAll(s.plansDir(), 0o700)
	note := func(plan string) string {
		d, _ := json.Marshal(adminPending{Plan: plan, Items: []adminPendingItem{{Path: "/nonexistent/x", Device: 1, Inode: 2}}})
		os.WriteFile(s.pendingPath(plan), d, 0o600)
		return s.pendingPath(plan)
	}
	kept := note("p-000000000001")
	other := note("p-000000000002")
	s.reconcileAdminNotes("p-000000000001", true)
	if _, err := os.Stat(kept); err != nil {
		t.Error("the held plan's note went")
	}
	if _, err := os.Stat(other); err == nil {
		t.Error("another plan's note stayed")
	}
	s.reconcileAdmin()
	if _, err := os.Stat(kept); err == nil {
		t.Error("the next round left the note")
	}
}
