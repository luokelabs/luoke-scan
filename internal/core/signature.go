package core

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SigKind is who vouches for a program.
type SigKind int

const (
	SigApple     SigKind = iota // part of macOS or signed by Apple
	SigDeveloper                // a valid signature from a developer, with their Team ID
	SigAdhoc                    // valid but nobody vouches for it
	SigUnsigned
	SigInvalid // signed, but changed after signing
	SigScript  // a text file run by an interpreter: nothing to check
	SigMissing
	SigUnknown // not read: in a folder macOS asks about, and no Full Disk Access
)

// Signature is a program's code signature as this tool tells it.
type Signature struct {
	Kind SigKind
	Team string
}

// Unvouched: no signature, an ad hoc one, or a script.
func (s Signature) Unvouched() bool {
	return s.Kind == SigUnsigned || s.Kind == SigAdhoc || s.Kind == SigScript
}

func (s Signature) Label() string {
	switch s.Kind {
	case SigApple:
		return "Apple"
	case SigDeveloper:
		return "开发者签名（" + s.Team + "）"
	case SigAdhoc:
		return "临时签名（没有开发者担保）"
	case SigUnsigned:
		return "没签名"
	case SigInvalid:
		return "签名和文件对不上（签名后被改过）"
	case SigScript:
		return "脚本"
	case SigMissing:
		return "不存在"
	}
	return "没看（在 macOS 要先问你的文件夹里，没有完全磁盘访问）"
}

// ParseSignature reads the fakes' spelling: apple, developer:<team>, adhoc, unsigned, invalid, script, missing.
func ParseSignature(s string) Signature {
	switch s {
	case "apple":
		return Signature{Kind: SigApple}
	case "adhoc":
		return Signature{Kind: SigAdhoc}
	case "unsigned":
		return Signature{Kind: SigUnsigned}
	case "invalid":
		return Signature{Kind: SigInvalid}
	case "script":
		return Signature{Kind: SigScript}
	case "missing":
		return Signature{Kind: SigMissing}
	}
	if strings.HasPrefix(s, "developer:") {
		return Signature{Kind: SigDeveloper, Team: strings.TrimPrefix(s, "developer:")}
	}
	return Signature{Kind: SigUnknown}
}

// SignatureSubject is what to check for a program path: the enclosing .app for a program inside one.
func SignatureSubject(path string) string {
	if i := strings.LastIndex(path, ".app/"); i >= 0 {
		return path[:i] + ".app"
	}
	return path
}

const codesign = "/usr/bin/codesign"

// SignatureOf checks a program's signature with codesign, offline and without hashing every resource of an app: it
// reads who signed it (codesign -d hashes nothing), then checks the signature and Apple's requirement in one run (exit 3:
// intact, not Apple's). Two codesign runs and one pass over the program instead of three and two.
func SignatureOf(path string) Signature {
	target := SignatureSubject(path)
	st, err := os.Stat(target)
	if err != nil {
		return Signature{Kind: SigMissing}
	}
	if st.Mode().IsRegular() {
		if f, err := os.Open(target); err == nil {
			head := make([]byte, 2)
			n, _ := f.Read(head)
			f.Close()
			if n == 2 && string(head) == "#!" {
				return Signature{Kind: SigScript}
			}
		}
	}
	shown := showSignature(target)
	switch {
	case shown.notSigned:
		return Signature{Kind: SigUnsigned}
	case !shown.ok:
		return signatureSlow(target)
	case shown.adhoc:
		if verifySignature(target, "") != 0 {
			return Signature{Kind: SigInvalid}
		}
		return Signature{Kind: SigAdhoc}
	}
	// Intact and Apple's in one check; intact but not Apple's (3) is a developer's or nobody's, as codesign -d said.
	switch verifySignature(target, "anchor apple") {
	case 0:
		return Signature{Kind: SigApple}
	case codesignUnmet:
		return shown.developerOrAdhoc()
	case -1:
		return signatureSlow(target) // codesign did not finish: one requirement at a time, as before
	}
	return Signature{Kind: SigInvalid}
}

// signatureSlow is the check one requirement at a time: is it intact, is it Apple's, then who signed it.
func signatureSlow(target string) Signature {
	v := Run(codesign, []string{"--verify", "--no-strict", "--ignore-resources", target}, RunOpts{Timeout: 60 * time.Second})
	if v.Status != 0 {
		if strings.Contains(v.Stderr, "not signed at all") {
			return Signature{Kind: SigUnsigned}
		}
		return Signature{Kind: SigInvalid}
	}
	if verifySignature(target, "anchor apple") == 0 {
		return Signature{Kind: SigApple}
	}
	shown := showSignature(target)
	if shown.adhoc {
		return Signature{Kind: SigAdhoc}
	}
	return shown.developerOrAdhoc()
}

// codesignUnmet is codesign --verify's exit status when the signature is intact but does not meet the requirement given.
const codesignUnmet = 3

// verifySignature checks target's signature (its program and Info.plist, not every resource), offline, against
// requirement when one is given: 0 intact (and meets it), codesignUnmet intact but does not meet it, else broken or not
// signed (-1: codesign did not finish).
func verifySignature(target, requirement string) int {
	args := []string{"--verify", "--no-strict", "--ignore-resources"}
	if requirement != "" {
		args = append(args, "-R="+requirement)
	}
	return Run(codesign, append(args, target), RunOpts{Timeout: 60 * time.Second}).Status
}

// The certificates that sign the App Store's apps and a developer's Developer ID apps (Apple's own programs are signed
// by several: "Software Signing", "macOS Software Signing", …; told by the requirement, not the name).
const (
	leafAppStore    = "Apple Mac OS Application Signing"
	leafDeveloperID = "Developer ID Application:"
)

// shownSignature is what codesign -dvv says of a signature, which it shows without checking it.
type shownSignature struct {
	ok        bool // codesign could show it
	notSigned bool
	adhoc     bool   // "Signature=adhoc"
	adhocDir  bool   // its CodeDirectory is flagged adhoc
	leaf      string // the signing certificate (the first Authority line); "" none shown
	team      string // "" none, or "not set"
}

func showSignature(target string) shownSignature {
	d := Run(codesign, []string{"-dvv", target}, RunOpts{Timeout: 60 * time.Second})
	out := shownSignature{ok: d.Status == 0}
	if d.Status != 0 {
		out.notSigned = strings.Contains(d.Stderr, "not signed at all")
		return out
	}
	for _, line := range strings.Split(d.Stdout+d.Stderr, "\n") {
		switch {
		case line == "Signature=adhoc":
			out.adhoc = true
		case strings.HasPrefix(line, "CodeDirectory ") && strings.Contains(line, "flags=0x2(adhoc)"):
			out.adhocDir = true
		case strings.HasPrefix(line, "Authority=") && out.leaf == "":
			out.leaf = strings.TrimPrefix(line, "Authority=")
		case strings.HasPrefix(line, "TeamIdentifier="):
			out.team = strings.TrimPrefix(line, "TeamIdentifier=")
		}
	}
	return out
}

func (s shownSignature) developerOrAdhoc() Signature {
	if s.team != "" && s.team != "not set" {
		return Signature{Kind: SigDeveloper, Team: s.team}
	}
	return Signature{Kind: SigAdhoc}
}

// SignatureIdentity is what a check of path depends on, to tell whether a kept result still holds: of the file
// checked (links resolved; for an app, its main program, Info.plist and signature record) the device, inode, size,
// modification and status-change times. "" when that cannot be told.
func SignatureIdentity(path string) string {
	target, err := filepath.EvalSymlinks(SignatureSubject(path))
	if err != nil {
		return ""
	}
	part := func(p string) string {
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil {
			return ""
		}
		return strconv.Itoa(int(st.Dev)) + ":" + strconv.FormatUint(st.Ino, 10) + ":" + strconv.FormatInt(st.Size, 10) + ":" +
			strconv.FormatInt(st.Mtimespec.Sec, 10) + "." + strconv.FormatInt(st.Mtimespec.Nsec, 10) + ":" +
			strconv.FormatInt(st.Ctimespec.Sec, 10) + "." + strconv.FormatInt(st.Ctimespec.Nsec, 10)
	}
	top := part(target)
	if top == "" {
		return ""
	}
	parts := []string{top}
	if strings.HasSuffix(target, ".app") {
		contents := target + "/Contents"
		exe := PlistString(ReadPlistDict(contents+"/Info.plist"), "CFBundleExecutable")
		main := ""
		if exe != "" {
			main = part(contents + "/MacOS/" + exe)
		}
		if main == "" {
			return ""
		}
		or := func(s string) string {
			if s == "" {
				return "-"
			}
			return s
		}
		parts = append(parts, main, or(part(contents+"/Info.plist")), or(part(contents+"/_CodeSignature/CodeResources")))
	}
	return strings.Join(parts, "|")
}
