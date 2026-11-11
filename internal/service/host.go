package service

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// The channel to 螺壳's main body. The main body starts `luoke-scan mcp` and hands its standard input and output to
// the agent; for what only the main body can do it also passes one more descriptor, named by LUOKE_HOST_FD, carrying
// one JSON object per line each way. The requests:
//
//	→ {"id": 1, "method": "elevate", "params": {"args": ["--plan", "p-…", "--user", "501", "--keys", "a0,a1", "--apps", "…", "--homebrew"], "prompt": "螺壳扫描要把…移到废纸篓。"}}
//	← {"id": 1, "result": {"status": "done", "output": "<luoke-scan-admin's standard output>"}}
//	← {"id": 1, "result": {"status": "cancelled"}}
//	← {"id": 1, "result": {"status": "failed", "why": "…"}}
//	← {"id": 1, "result": {"status": "failed", "why": "…", "uncertain": true}}   (it may have done part of it)
//
// Only the arguments go: the main body checks them (a plan id, its own user id, item keys, bundle ids), shows its own
// password dialog (the dialog says 螺壳), and runs the luoke-scan-admin in its own bundle as root the way AdminCommand
// spells it (copied into a folder of root's, its signature checked there, then run with an empty environment). Nothing
// this process says becomes part of the command root runs.
//
//	→ {"id": 2, "method": "reveal", "params": {"path": "/Users/me/Downloads/x.dmg"}}
//	→ {"id": 3, "method": "open_settings", "params": {"pane": "Privacy_AllFiles"}}
//	← {"id": 2, "result": {"status": "done"}}
//	← {"id": 2, "result": {"status": "failed", "why": "…"}}
//
// macOS lets only the app in front bring another app forward. When the user clicks 在访达里显示 or 打开设置 in 螺壳,
// 螺壳 is in front and this process is not: `open -R` from here opens the Finder window, but it may stay behind
// 螺壳's. So the main body does it (in front, right after the click), and builds the Settings address itself from the
// pane name. On failed (not right after a click, no such pane, nothing there) this process opens it itself.

// HostFDEnv names the descriptor of the channel to the main body.
const HostFDEnv = "LUOKE_HOST_FD"

// hostWait is the most the password step may take, dialog included. The main body ends a request that has not answered
// in 300 s (luoke-scan#122): scan_apply gives it what is left of its own time (requestLimit), never more than this.
const hostWait = 280 * time.Second

// frontWait is how long bringing Finder or Settings forward may take.
const frontWait = 15 * time.Second

type host struct {
	mu   sync.Mutex
	w    *os.File
	r    *bufio.Reader
	next int
}

var (
	hostOnce sync.Once
	theHost  *host
)

// mainBody is the channel to the main body, nil when this process was not given one.
func mainBody() *host {
	hostOnce.Do(func() {
		fd, err := strconv.Atoi(os.Getenv(HostFDEnv))
		if err != nil || fd < 3 {
			return
		}
		f := hostFile(fd)
		if f == nil {
			return
		}
		theHost = &host{w: f, r: bufio.NewReader(f)}
	})
	return theHost
}

// hostFile wraps the channel's descriptor. The main body hands over a blocking socket; made non-blocking first, Go
// polls it and SetDeadline holds (on a blocking one SetDeadline fails and a read waits for as long as the main body
// does not answer). If that cannot be set it still works, only without the time limit.
func hostFile(fd int) *os.File {
	syscall.SetNonblock(fd, true)
	return os.NewFile(uintptr(fd), "luoke-host")
}

// HostElevate asks the main body to run the password step with these arguments, waiting at most wait (and hostWait).
func HostElevate(args []string, prompt string, wait time.Duration) Elevated {
	h := mainBody()
	if h == nil {
		return Elevated{Kind: "failed", Why: "这一步要在螺壳里点（终端里用 luoke-scan system）"}
	}
	return h.elevate(args, prompt, wait)
}

func (h *host) elevate(args []string, prompt string, wait time.Duration) Elevated {
	if wait <= 0 || wait > hostWait {
		wait = hostWait
	}
	r, err := h.call("elevate", map[string]any{"args": args, "prompt": prompt}, wait)
	if err != "" {
		return Elevated{Kind: "failed", Why: err}
	}
	switch r.Status {
	case "done":
		return Elevated{Kind: "done", Output: r.Output}
	case "cancelled":
		return Elevated{Kind: "cancelled"}
	}
	why := r.Why
	if why == "" {
		why = "螺壳说没做成"
	}
	return Elevated{Kind: "failed", Why: why, Uncertain: r.Uncertain}
}

// HostFront asks the main body to bring something forward ("reveal" with a path, "open_settings" with a pane). False
// when this process has no main body or the main body did not do it: the caller opens it itself.
func HostFront(method string, params map[string]any) bool {
	h := mainBody()
	if h == nil {
		return false
	}
	r, err := h.call(method, params, frontWait)
	return err == "" && r.Status == "done"
}

type hostResult struct {
	Status, Output, Why string
	Uncertain           bool
}

// call sends one request and reads lines until the answer with its id; err is why there is none.
func (h *host) call(method string, params map[string]any, wait time.Duration) (hostResult, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	id := h.next
	req, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	h.w.SetDeadline(time.Now().Add(wait)) // holds once hostFile made it non-blocking
	defer h.w.SetDeadline(time.Time{})
	if _, err := h.w.Write(append(req, '\n')); err != nil {
		return hostResult{}, "螺壳没接（" + err.Error() + "）"
	}
	for {
		line, err := h.r.ReadBytes('\n')
		if err != nil {
			return hostResult{}, "螺壳没回（" + err.Error() + "）"
		}
		var reply struct {
			ID     int        `json:"id"`
			Result hostResult `json:"result"`
		}
		if json.Unmarshal(line, &reply) != nil || reply.ID != id {
			continue // not the answer to this one
		}
		return reply.Result, ""
	}
}
