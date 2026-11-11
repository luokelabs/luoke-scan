package service

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// reveal and open_settings go over the same channel as elevate, one line each way (docs/host-interface.md §3a).
func TestHostCallReveal(t *testing.T) {
	fds, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "scan"), os.NewFile(uintptr(fds[1]), "body")
	defer mine.Close()
	defer theirs.Close()
	h := &host{w: mine, r: bufio.NewReader(mine)}
	got := make(chan map[string]any, 1)
	go func() {
		line, _ := bufio.NewReader(theirs).ReadBytes('\n')
		var req map[string]any
		json.Unmarshal(line, &req)
		got <- req
		theirs.Write([]byte(`{"id": 7, "result": {"status": "failed"}}` + "\n")) // someone else's: skipped
		theirs.Write([]byte(`{"id": 1, "result": {"status": "done"}}` + "\n"))
	}()
	r, why := h.call("reveal", map[string]any{"path": "/Users/me/x.dmg"}, time.Second)
	if why != "" || r.Status != "done" {
		t.Fatalf("%+v %q", r, why)
	}
	req := <-got
	want := map[string]any{"id": float64(1), "method": "reveal", "params": map[string]any{"path": "/Users/me/x.dmg"}}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("%v", req)
	}
}

// The main body does not answer in time: no, and the caller opens it itself. The descriptor comes blocking, as the
// main body's socketpair end does; hostFile makes the time limit hold.
func TestHostCallGivesUp(t *testing.T) {
	fds, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := hostFile(fds[0]), os.NewFile(uintptr(fds[1]), "body")
	if mine == nil {
		t.Fatal("no host file")
	}
	defer mine.Close()
	defer theirs.Close()
	h := &host{w: mine, r: bufio.NewReader(mine)}
	start := time.Now()
	if r, why := h.call("open_settings", map[string]any{"pane": "Privacy_AllFiles"}, 200*time.Millisecond); why == "" || r.Status == "done" {
		t.Fatalf("%+v %q", r, why)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("gave up after %v", d)
	}
}

func TestHostFrontWithoutMainBody(t *testing.T) {
	if os.Getenv(HostFDEnv) != "" {
		t.Skip("run with a host channel")
	}
	if HostFront("reveal", map[string]any{"path": "/"}) {
		t.Fatal("no main body, yet done")
	}
}

type frontCalls struct {
	front    []string
	commands [][]string
}

func frontService(t *testing.T, done bool) (*Service, *frontCalls, string) {
	m := newModelSetup(t)
	s := m.service(nil, nil)
	growth := m.report.Findings[1] // a folder that is there
	if err := s.Store.SaveReport(core.Report{Findings: []core.Finding{growth}}); err != nil {
		t.Fatal(err)
	}
	c := &frontCalls{}
	s.Config.Front = func(method string, params map[string]any) bool {
		b, _ := json.Marshal(params)
		c.front = append(c.front, method+" "+string(b))
		return done
	}
	s.Config.Command = func(tool string, args []string) int {
		c.commands = append(c.commands, append([]string{tool}, args...))
		return 0
	}
	return s, c, s.fid(growth)
}

// 在访达里显示 asks the main body first, which is in front; opens it itself only when the main body did not.
func TestRevealAsksTheMainBodyFirst(t *testing.T) {
	s, c, id := frontService(t, true)
	path := s.Store.LastReport().Findings[0].Path
	out, err := s.reveal(O{"finding_id": id})
	if err != nil || out.Text == "" {
		t.Fatalf("%+v %v", out, err)
	}
	b, _ := json.Marshal(map[string]any{"path": path})
	if !reflect.DeepEqual(c.front, []string{"reveal " + string(b)}) || len(c.commands) != 0 {
		t.Fatalf("front %v commands %v", c.front, c.commands)
	}

	s, c, id = frontService(t, false)
	path = s.Store.LastReport().Findings[0].Path
	if out, err := s.reveal(O{"finding_id": id}); err != nil || out.Text == "" {
		t.Fatalf("%+v %v", out, err)
	}
	if len(c.front) != 1 || !reflect.DeepEqual(c.commands, [][]string{{"/usr/bin/open", "-R", path}}) {
		t.Fatalf("front %v commands %v", c.front, c.commands)
	}
}

// 打开设置 hands the main body the pane's name, never an address; without it, opens the address itself.
func TestOpenSettingsGivesThePaneName(t *testing.T) {
	s, c, _ := frontService(t, true)
	for _, g := range []string{"完全磁盘访问", loginItemsGrant} {
		if _, err := s.openSettings(O{"grant": g}); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(c.front, []string{`open_settings {"pane":"Privacy_AllFiles"}`, `open_settings {"pane":"LoginItems"}`}) || len(c.commands) != 0 {
		t.Fatalf("front %v commands %v", c.front, c.commands)
	}
	if _, err := s.openSettings(O{"grant": "不认识的"}); err == nil || len(c.front) != 2 {
		t.Fatalf("unknown grant: %v %v", err, c.front)
	}

	s, c, _ = frontService(t, false)
	if _, err := s.openSettings(O{"grant": "完全磁盘访问"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.commands, [][]string{{"/usr/bin/open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"}}) {
		t.Fatalf("commands %v", c.commands)
	}
}
