package service

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"time"
)

// The channel to 螺壳's main body. The main body starts `luoke-scan mcp` and hands its standard input and output to
// the agent; for what only the main body can do it also passes one more descriptor, named by LUOKE_HOST_FD, carrying
// one JSON object per line each way. The one request so far:
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

// HostFDEnv names the descriptor of the channel to the main body.
const HostFDEnv = "LUOKE_HOST_FD"

// hostWait is how long the password step may take, dialog included (the agent waits up to 5 minutes for a call).
const hostWait = 280 * time.Second

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
		f := os.NewFile(uintptr(fd), "luoke-host")
		if f == nil {
			return
		}
		theHost = &host{w: f, r: bufio.NewReader(f)}
	})
	return theHost
}

// HostElevate asks the main body to run the password step with these arguments.
func HostElevate(args []string, prompt string) Elevated {
	h := mainBody()
	if h == nil {
		return Elevated{Kind: "failed", Why: "这一步要在螺壳里点（终端里用 luoke-scan system）"}
	}
	return h.elevate(args, prompt)
}

func (h *host) elevate(args []string, prompt string) Elevated {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	id := h.next
	req, _ := json.Marshal(map[string]any{"id": id, "method": "elevate", "params": map[string]any{"args": args, "prompt": prompt}})
	h.w.SetDeadline(time.Now().Add(hostWait))
	defer h.w.SetDeadline(time.Time{})
	if _, err := h.w.Write(append(req, '\n')); err != nil {
		return Elevated{Kind: "failed", Why: "螺壳没接（" + err.Error() + "）"}
	}
	for {
		line, err := h.r.ReadBytes('\n')
		if err != nil {
			return Elevated{Kind: "failed", Why: "螺壳没回（" + err.Error() + "）"}
		}
		var reply struct {
			ID     int `json:"id"`
			Result struct {
				Status, Output, Why string
				Uncertain           bool
			} `json:"result"`
		}
		if json.Unmarshal(line, &reply) != nil || reply.ID != id {
			continue // not the answer to this one
		}
		switch reply.Result.Status {
		case "done":
			return Elevated{Kind: "done", Output: reply.Result.Output}
		case "cancelled":
			return Elevated{Kind: "cancelled"}
		}
		why := reply.Result.Why
		if why == "" {
			why = "螺壳说没做成"
		}
		return Elevated{Kind: "failed", Why: why, Uncertain: reply.Result.Uncertain}
	}
}
