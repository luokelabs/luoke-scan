package service

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The facts of the security settings (posture.*), of processes (process.*) and of who watches the keyboard
// (keyboard.*), for data/overview's attention list and data/finding (luoke-scan#212): codes, names, paths and numbers
// the window writes its own words from. Read back from what the rules keep in the evidence; no sentences.

// postureChecks: the names posture.partial lists (the rule's own words for what it could not ask), as codes.
var postureChecks = map[string]string{"FileVault": "filevault", "防火墙": "firewall", "防火墙隐身模式": "stealth", "SIP": "sip",
	"Gatekeeper": "gatekeeper", "锁屏": "screen-lock", "共享服务": "sharing"}

// postureGrants: the settings a posture finding is fixed in that scan_open_settings can open.
var postureGrants = map[string]string{"filevault": "FileVault"}

func postureFacts(f core.Finding) O {
	setting := strings.TrimPrefix(f.Rule, "posture.")
	out := O{"setting": setting, "grant": nilIfEmpty(postureGrants[setting])}
	ev := f.Evidence
	switch setting {
	case "screen-lock-delay":
		out["delaySeconds"] = intOrNil(ev, "delay_seconds")
	case "pending-updates":
		out["uptimeDays"], out["pending"] = intOrNil(ev, "uptime_days"), intOrNil(ev, "pending")
	case "xprotect-stale":
		out["updated"] = nilIfEmpty(ev["updated"])
	case "trusted-roots":
		certs := splitList(ev["certs"], "；")
		all := len(certs)
		if f.Key != "" {
			all = len(strings.Split(f.Key, "|"))
		}
		out["certs"], out["certsMore"] = certs, max(all-len(certs), 0)
	case "partial":
		skipped := A{}
		for _, n := range splitList(ev["skipped"], "、") {
			if c, ok := postureChecks[n.(string)]; ok {
				skipped = append(skipped, c)
			} else {
				skipped = append(skipped, n)
			}
		}
		out["skipped"] = skipped
	}
	return out
}

func processFacts(f core.Finding) O {
	ev := f.Evidence
	out := O{"count": intOrNil(ev, "count"), "pids": pidList(ev["pids"]), "started": nilIfEmpty(ev["started"])}
	switch f.Rule {
	case "process.deleted-binary":
		out["program"] = nilIfEmpty(f.Path)
	case "process.dyld-insert":
		out["library"] = nilIfEmpty(ev["library"])
		out["signature"] = signatureFacts(ev["signature"])
		out["programs"] = splitList(ev["programs"], "、")
	case "process.library-temp":
		out["program"] = nilIfEmpty(ev["program"])
		out["place"] = map[string]any{"临时文件夹": "temp", "下载文件夹": "downloads", "临时文件夹和下载文件夹": "temp-and-downloads"}[ev["place"]]
		libs := A{}
		for _, x := range splitList(ev["libraries"], "；") {
			path, label := cutLabel(x.(string))
			sig := any(nil)
			switch label {
			case "文件已经删掉":
				sig = O{"kind": "deleted", "team": nil}
			case "没查签名", "":
			default:
				sig = signatureFacts(label)
			}
			libs = append(libs, O{"path": path, "signature": sig})
		}
		out["libraries"], out["libraryCount"] = libs, intOrNil(ev, "library_count")
	case "process.library-deleted":
		out["program"] = nilIfEmpty(ev["program"])
		out["libraries"], out["libraryCount"] = splitList(ev["libraries"], "；"), intOrNil(ev, "library_count")
	case "process.pile-up":
		out["program"] = nilIfEmpty(f.Path)
		parent := ev["parent"]
		if parent == "?" {
			parent = ""
		}
		out["parent"], out["parentPid"] = nilIfEmpty(parent), intOrNil(ev, "parent_pid")
	case "process.orphan":
		// 「name（pid，N 小时）」 each, the oldest ten
		oldest := A{}
		for _, x := range splitList(ev["oldest"], "；") {
			name, inner := cutLabel(x.(string))
			pid, hours, _ := strings.Cut(inner, "，")
			oldest = append(oldest, O{"name": name, "pid": atoiOrNil(pid), "hours": atoiOrNil(strings.TrimSuffix(hours, " 小时"))})
		}
		out["oldest"] = oldest
	case "process.partial":
		return O{"skipped": "launchctl"}
	}
	return out
}

func keyboardFacts(f core.Finding) O {
	ev := f.Evidence
	if f.Rule == "keyboard.watchers" {
		return O{"programs": splitList(ev["programs"], "；")}
	}
	program := strings.TrimPrefix(f.Key, "keyboard/")
	label := ev["signature"]
	sig := signatureFacts(label)
	interpreter := false
	switch label {
	case "程序文件不在了":
		sig = O{"kind": "deleted", "team": nil}
	case "苹果签名的解释器，脚本没人担保":
		sig, interpreter = O{"kind": "apple", "team": nil}, true
	}
	return O{"program": nilIfEmpty(program), "signature": sig, "interpreter": interpreter}
}

// signatureFacts: a signature as Signature.Label says it, back as a code (apple, developer, adhoc, unsigned, invalid,
// script, missing, unknown) and the developer's team where there is one. nil: a label it does not know.
func signatureFacts(label string) any {
	kinds := map[string]string{core.Signature{Kind: core.SigApple}.Label(): "apple", core.Signature{Kind: core.SigAdhoc}.Label(): "adhoc",
		core.Signature{Kind: core.SigUnsigned}.Label(): "unsigned", core.Signature{Kind: core.SigInvalid}.Label(): "invalid",
		core.Signature{Kind: core.SigScript}.Label(): "script", core.Signature{Kind: core.SigMissing}.Label(): "missing",
		core.Signature{Kind: core.SigUnknown}.Label(): "unknown"}
	if k, ok := kinds[label]; ok {
		return O{"kind": k, "team": nil}
	}
	dev := core.Signature{Kind: core.SigDeveloper}.Label() // 开发者签名（）
	open := strings.TrimSuffix(dev, "）")
	if strings.HasPrefix(label, open) && strings.HasSuffix(label, "）") {
		return O{"kind": "developer", "team": nilIfEmpty(strings.TrimSuffix(strings.TrimPrefix(label, open), "）"))}
	}
	return nil
}

// cutLabel: 「path（label）」 as path and label; the last full-width parenthesis, so a path with one in it stays whole.
func cutLabel(s string) (string, string) {
	// The label may hold parentheses of its own (「临时签名（没有开发者担保）」): the one that opens it is the one the
	// last 「）」 closes, found by counting back
	if !strings.HasSuffix(s, "）") {
		return s, ""
	}
	depth := 0
	for i := len(s); i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		i -= size
		switch r {
		case '）':
			depth++
		case '（':
			depth--
			if depth == 0 {
				if i == 0 {
					return s, ""
				}
				return s[:i], strings.TrimSuffix(s[i+size:], "）")
			}
		}
	}
	return s, ""
}

func intOrNil(ev map[string]string, k string) any {
	if n, ok := evInt(ev, k); ok {
		return n
	}
	return nil
}

func atoiOrNil(s string) any {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return nil
}

func pidList(s string) A {
	out := A{}
	for _, x := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			out = append(out, n)
		}
	}
	return out
}
