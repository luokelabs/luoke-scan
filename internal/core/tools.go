package core

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	assets "github.com/luokelabs/luoke-scan"
)

// Tools are the external scanners. Empty: the packed ones next to this program (螺壳.app's Contents/Helpers; signed as
// luoke's, checked before use), and in a development build also in Homebrew's folders.
type Tools struct {
	Clamscan, Freshclam, Sigtool, Yara string
	XProtect                           string // XProtect's YARA rules; empty: this Mac's
	// Packed: this is the build that ships inside 螺壳 (never Homebrew's tools: they are the user's to change, and
	// would run with this program's Full Disk Access).
	Packed bool
}

// Path of a tool by name ("clamscan", "freshclam", "sigtool", "yara", "xprotect"), or "".
func (t Tools) Path(name string) string {
	set := map[string]string{"clamscan": t.Clamscan, "freshclam": t.Freshclam, "sigtool": t.Sigtool, "yara": t.Yara}[name]
	if name == "xprotect" {
		if t.XProtect != "" {
			return t.XProtect
		}
		return systemXProtect()
	}
	if set != "" {
		return set
	}
	return findTool(name, t.Packed)
}

func findTool(name string, packed bool) string {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	} else if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return findToolBeside(exe, name, packed)
}

// findToolBeside: the tool next to the program exe (a packed one must be signed as luoke's); in a development build
// also in Homebrew's folders.
func findToolBeside(exe, name string, packed bool) string {
	var dirs []string
	if exe != "" {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if !packed {
		dirs = append(dirs, "/opt/homebrew/bin", "/usr/local/bin")
	}
	for _, d := range dirs {
		if p := filepath.Join(d, name); IsExecutable(p) {
			if packed && !ToolSigned(p, name) {
				return ""
			}
			return p
		}
	}
	return ""
}

var toolChecks sync.Map // path -> bool: each tool is checked once a run

// ToolSigned: a packed tool is signed as luoke's (identifier ai.luoke.scan.<name>, and the release's Team when the
// build has one): it runs with the Full Disk Access luoke-scan was started with, and 螺壳.app may sit where the user's
// programs can change it (~/Applications).
func ToolSigned(path, name string) bool {
	if ok, seen := toolChecks.Load(path); seen {
		return ok.(bool)
	}
	ok := Run(codesign, []string{"--verify", "--strict", "-R=" + ToolRequirement(name, ReleaseTeam), path}, RunOpts{Timeout: 60 * time.Second}).Status == 0
	toolChecks.Store(path, ok)
	return ok
}

// ToolRequirement: identifier ai.luoke.scan.<name>, signed with the Developer ID of the given Team (none: any signature).
func ToolRequirement(name, team string) string {
	req := `identifier "ai.luoke.scan.` + name + `"`
	if team != "" {
		req += ` and anchor apple generic and certificate leaf[subject.OU] = "` + team + `"` +
			` and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]`
	}
	return req
}

// systemXProtect is the newest readable copy of macOS's own XProtect YARA rules.
func systemXProtect() string {
	best, bestVersion := "", -1
	for _, b := range []string{"/private/var/protected/xprotect/XProtect.bundle", "/Library/Apple/System/Library/CoreServices/XProtect.bundle"} {
		rules := b + "/Contents/Resources/XProtect.yara"
		if f, err := os.Open(rules); err == nil {
			f.Close()
			v := plistInt(b+"/Contents/Info.plist", "CFBundleShortVersionString")
			if v > bestVersion {
				best, bestVersion = rules, v
			}
		}
	}
	return best
}

// ClamAVCerts is --cvdcertsdir for the packed ClamAV tools (ClamAV 1.5 reads no database without its root
// certificate, and the folder it looks in by default is Homebrew's): the certificate luoke-scan carries, written to a
// folder of its own that done removes. Nothing in a development build (Homebrew's tools find their own). Run the tool
// with CertsEnv too: freshclam's test of what it downloaded does not take the option (luoke-scan#103).
var ClamAVCerts = func() (args []string, done func()) {
	if !Packed() {
		return nil, func() {}
	}
	return clamAVCertsFrom(assets.FS)
}

// CertsEnv is env (nil: this process's environment) with CVD_CERTS_DIR set to the folder certs (ClamAVCerts) points
// at; nil when certs points nowhere, so the tool keeps this process's environment. freshclam loads the database it has
// just downloaded to test it, and that load reads the certificate from CVD_CERTS_DIR, else from the folder compiled
// in (Homebrew's, missing on a Mac without Homebrew's ClamAV): without it every download fails its test (exit 8).
func CertsEnv(certs []string, env map[string]string) map[string]string {
	dir := ""
	for _, a := range certs {
		if strings.HasPrefix(a, "--cvdcertsdir=") {
			dir = strings.TrimPrefix(a, "--cvdcertsdir=")
		}
	}
	if dir == "" {
		return env
	}
	out := map[string]string{}
	if env == nil {
		for _, kv := range os.Environ() {
			if i := strings.Index(kv, "="); i > 0 {
				out[kv[:i]] = kv[i+1:]
			}
		}
	} else {
		for k, v := range env {
			out[k] = v
		}
	}
	out["CVD_CERTS_DIR"] = dir
	return out
}

func clamAVCertsFrom(fsys fs.FS) (args []string, done func()) {
	done = func() {}
	certs, _ := fs.Glob(fsys, "packaging/clamav-certs/*.crt")
	if len(certs) == 0 {
		return nil, done
	}
	dir, err := os.MkdirTemp("", "luoke-scan-certs.") // 700
	if err != nil {
		return nil, done
	}
	done = func() { os.RemoveAll(dir) }
	for _, c := range certs {
		b, err := fs.ReadFile(fsys, c)
		if err != nil || os.WriteFile(filepath.Join(dir, filepath.Base(c)), b, 0o600) != nil {
			done()
			return nil, func() {}
		}
	}
	return []string{"--cvdcertsdir=" + dir}, done
}
