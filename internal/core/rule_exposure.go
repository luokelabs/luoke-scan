package core

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// ExposureRule finds what is open to others: this user's programs listening on the network (not only on this Mac),
// passwords and tokens written on command lines, and SSH private keys others can read. No value of a secret is ever
// kept, only where it is and what kind it looks like.
type ExposureRule struct {
	// Pids are this user's processes; nil: this Mac's.
	Pids func() []int32
	// Look is a process's program, listening sockets and arguments; nil: this Mac's (ProcPath, ListeningSockets,
	// ProcArguments).
	Look func(pid int32) ProcLook
}

// ProcLook is what the exposure check sees of a process.
type ProcLook struct {
	Program      string
	HasProgram   bool // false: its program could not be read
	Listeners    []ListeningSocket
	Arguments    []string
	HasArguments bool // false: its arguments could not be read
}

// ListeningSocket is a TCP socket a process listens on.
type ListeningSocket struct {
	Port    int
	Address string
}

// Everywhere: 0.0.0.0 or ::, every network this Mac is on.
func (l ListeningSocket) Everywhere() bool { return l.Address == "0.0.0.0" || l.Address == "::" }

// Loopback: only this Mac can connect (127.x, ::1, and 127.x written as an IPv6 address).
func (l ListeningSocket) Loopback() bool {
	v4 := strings.TrimPrefix(l.Address, "::ffff:")
	return strings.HasPrefix(v4, "127.") || l.Address == "::1"
}

// ListeningSockets are the TCP sockets a process listens on, on this Mac: its descriptors (PROC_PIDLISTFDS), then each
// socket's information (PROC_PIDFDSOCKETINFO), as the Swift version reads them with libproc. A variable so a fake home
// answers from its fakes.
var ListeningSockets = procListeningSockets

func init() { Register("exposure", NewExposureRule) }

// NewExposureRule is the rule for this Mac (l nil) or a fake home: there this user's processes, their programs,
// what they listen on and their arguments are the fakes'.
func NewExposureRule(l *Layout, f *Fakes) Rule {
	r := &ExposureRule{}
	if l != nil {
		me := uint32(os.Getuid())
		var mine []FakeProcess
		for _, p := range f.Processes {
			if p.UID == me {
				mine = append(mine, p)
			}
		}
		r.Pids = func() []int32 {
			out := make([]int32, 0, len(mine))
			for _, p := range mine {
				out = append(out, p.PID)
			}
			return out
		}
		r.Look = func(pid int32) ProcLook {
			for _, p := range mine {
				if p.PID != pid {
					continue
				}
				look := ProcLook{Program: p.Path, HasProgram: true}
				for _, s := range p.Listening {
					look.Listeners = append(look.Listeners, ListeningSocket{Port: s.Port, Address: s.Address})
				}
				if p.Arguments != nil {
					look.Arguments, look.HasArguments = *p.Arguments, true
				}
				return look
			}
			return ProcLook{}
		}
	}
	return r
}

func (r *ExposureRule) ID() string { return "exposure" }
func (r *ExposureRule) Emits() []string {
	return []string{"exposure.listening", "exposure.argv-secret", "exposure.ssh-key-perm", "exposure.ssh-dir-perm",
		"exposure.ssh-key-plain", "exposure.ssh-key-weak", "exposure.ssh-authorized", "exposure.ssh-rc"}
}

func exposureOwnProcesses() []int32 {
	me := uint32(os.Getuid())
	var out []int32
	for _, p := range ProcSnapshot() {
		if p.UID == me {
			out = append(out, p.PID)
		}
	}
	return out
}

func exposureLookThisMac(pid int32) ProcLook {
	look := ProcLook{}
	look.Program, look.HasProgram = ProcPath(pid)
	look.Listeners = ListeningSockets(pid)
	look.Arguments, look.HasArguments = ProcArguments(pid)
	return look
}

// ---- secrets on command lines

var exposureSecretFlags = map[string]bool{"--password": true, "--passwd": true, "--token": true, "--auth-token": true,
	"--access-token": true, "--api-key": true, "--apikey": true, "--api-token": true, "--secret": true, "--client-secret": true,
	"--secret-key": true, "--private-key": true}

// exposureSpace is what the Swift version's regular expressions (ICU) take for \s: White_Space.
const exposureSpace = `\t\n\x0B\f\r \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}`

var exposureURLPassword = regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/` + exposureSpace + `:@]*:[^/` + exposureSpace + `@]+@`)

// exposureShapes: kind, the text every match contains (most arguments have none of them, and are not matched
// further), and whether an argument has one. The Swift version's patterns, with \b as ICU has it and the
// look-arounds written out:
//
//	AWS 访问密钥       \bAKIA[0-9A-Z]{16}\b
//	GitHub 令牌        \b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{40,}
//	GitLab 令牌        \bglpat-[A-Za-z0-9_-]{20,}
//	Slack 令牌         \bxox[abpr]-[A-Za-z0-9-]{10,}
//	API 密钥（sk-…）   (?<![A-Za-z0-9/_.-])sk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}
//	                   (not a path segment like /sk-learn-…, nor part of a longer name; real keys carry digits)
//	网址里的密码       [a-z][a-z0-9+.-]*://[^/\s:@]*:[^/\s@]+@
var exposureShapes = []struct {
	kind    string
	needles []string
	match   func(string) bool
}{
	{"AWS 访问密钥", []string{"AKIA"}, func(a string) bool {
		return exposureEach(a, "AKIA", func(i int) bool {
			end := i + 4 + 16
			return expICUBoundary(a, i) && end <= len(a) && expAll(a[i+4:end], expUpperOrDigit) && expICUBoundary(a, end)
		})
	}},
	{"GitHub 令牌", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, func(a string) bool {
		for _, pre := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
			if exposureEach(a, pre, func(i int) bool {
				end := i + 4 + 36
				return expICUBoundary(a, i) && end <= len(a) && expAll(a[i+4:end], expAlnum) && expICUBoundary(a, end)
			}) {
				return true
			}
		}
		return exposureEach(a, "github_pat_", func(i int) bool {
			return expICUBoundary(a, i) && expRun(a[i+11:], func(c byte) bool { return expAlnum(c) || c == '_' }) >= 40
		})
	}},
	{"GitLab 令牌", []string{"glpat-"}, func(a string) bool {
		return exposureEach(a, "glpat-", func(i int) bool {
			return expICUBoundary(a, i) && expRun(a[i+6:], expTokenChar) >= 20
		})
	}},
	{"Slack 令牌", []string{"xox"}, func(a string) bool {
		return exposureEach(a, "xox", func(i int) bool {
			if !expICUBoundary(a, i) || i+5 > len(a) || !strings.ContainsRune("abpr", rune(a[i+3])) || a[i+4] != '-' {
				return false
			}
			return expRun(a[i+5:], func(c byte) bool { return expAlnum(c) || c == '-' }) >= 10
		})
	}},
	{"API 密钥（sk-…）", []string{"sk-"}, func(a string) bool {
		return exposureEach(a, "sk-", func(i int) bool {
			if i > 0 && (expAlnum(a[i-1]) || strings.IndexByte("/_.-", a[i-1]) >= 0) {
				return false
			}
			n := expRun(a[i+3:], expTokenChar)
			return n >= 20 && strings.IndexAny(a[i+3:i+3+n], "0123456789") >= 0
		})
	}},
	{"网址里的密码", []string{"://"}, exposureURLPassword.MatchString},
}

// exposureEach says whether at for some place needle starts in a.
func exposureEach(a, needle string, at func(int) bool) bool {
	for from := 0; ; {
		i := strings.Index(a[from:], needle)
		if i < 0 {
			return false
		}
		if at(from + i) {
			return true
		}
		from += i + 1
	}
}

func expAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
func expUpperOrDigit(c byte) bool { return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
func expTokenChar(c byte) bool    { return expAlnum(c) || c == '_' || c == '-' }

func expAll(s string, in func(byte) bool) bool { return expRun(s, in) == len(s) }

// expRun is how many bytes s starts with that are in the set.
func expRun(s string, in func(byte) bool) int {
	n := 0
	for n < len(s) && in(s[n]) {
		n++
	}
	return n
}

// expICUWord is ICU's \w: [\p{Alphabetic}\p{M}\p{Nd}\p{Pc}‌‍].
func expICUWord(r rune) bool {
	return unicode.IsLetter(r) || unicode.Is(unicode.Nl, r) || unicode.Is(unicode.Other_Alphabetic, r) || unicode.IsMark(r) ||
		unicode.Is(unicode.Nd, r) || unicode.Is(unicode.Pc, r) || r == 0x200c || r == 0x200d
}

// expICUIgnored: what ICU's \b steps over, grapheme extenders and format characters.
func expICUIgnored(r rune) bool {
	return unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Other_Grapheme_Extend, r) || unicode.Is(unicode.Cf, r)
}

// expICUBoundary is ICU's \b at byte i of s: never before a combining character; else a word character on one side
// only (looking back past combining characters).
func expICUBoundary(s string, i int) bool {
	cur := false
	if i < len(s) {
		r, _ := utf8.DecodeRuneInString(s[i:])
		if expICUIgnored(r) {
			return false
		}
		cur = expICUWord(r)
	}
	prev := false
	for j := i; j > 0; {
		r, n := utf8.DecodeLastRuneInString(s[:j])
		j -= n
		if !expICUIgnored(r) {
			prev = expICUWord(r)
			break
		}
	}
	return cur != prev
}

// exposureSecretValue: a flag's value that is a secret itself, not where one is kept (a path, @file, $VARIABLE,
// nothing).
func exposureSecretValue(v string) bool {
	if v == "" {
		return false
	}
	for _, p := range []string{"/", "~", "./", "../", "@", "$", "-"} {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	return true
}

// SecretKinds are the kinds of secrets a command line carries: a flag like --password with a value, a value shaped
// like a known token, and what some programs take in their own way (`mysql -pSECRET`, `curl -u user:pass`). Only
// the kind, never the value; sorted. program: the program's file name ("" none).
func SecretKinds(args []string, program string) []string {
	kinds := map[string]bool{}
	for i, a := range args {
		lower := strings.ToLower(a)
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		if eq := strings.IndexByte(lower, '='); eq >= 0 && exposureSecretFlags[lower[:eq]] && eq < len(a) && exposureSecretValue(a[eq+1:]) {
			kinds["参数 "+lower[:eq]] = true
		} else if exposureSecretFlags[lower] && exposureSecretValue(next) {
			kinds["参数 "+lower] = true
		}
		switch program {
		case "mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump":
			if strings.HasPrefix(a, "-p") && !strings.HasPrefix(a, "--") && utf8.RuneCountInString(a) > 2 {
				kinds["参数 -p（数据库密码）"] = true
			}
		}
		if program == "curl" {
			creds := ""
			if a == "-u" || a == "--user" {
				creds = next
			} else if strings.HasPrefix(a, "-u") && !strings.HasPrefix(a, "--") {
				creds = a[2:]
			}
			if colon := strings.IndexByte(creds, ':'); colon >= 0 && exposureSecretValue(creds[colon+1:]) {
				kinds["参数 -u（用户名:密码）"] = true
			}
		}
		for _, s := range exposureShapes {
			has := false
			for _, n := range s.needles {
				if strings.Contains(a, n) {
					has = true
					break
				}
			}
			if has && s.match(a) {
				kinds[s.kind] = true
			}
		}
	}
	out := make([]string, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- SSH

// exposureSSH: private keys in ~/.ssh others can read, kept without a passphrase, or of an algorithm too weak now;
// a ~/.ssh others can write to. Keys are read to tell how they are kept; nothing of them is written down but the
// file name, type and size.
func exposureSSH(home string) []Finding {
	dir := filepath.Join(home, ".ssh")
	var st syscall.Stat_t
	if syscall.Lstat(dir, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil
	}
	var out []Finding
	if st.Mode&0o022 != 0 {
		out = append(out, Finding{Rule: "exposure.ssh-dir-perm", Category: CatPosture, Severity: Medium, Verdict: Info, Path: dir,
			Title: "~/.ssh 别人也能往里写", Evidence: map[string]string{"mode": strconv.FormatUint(uint64(st.Mode&0o777), 8),
				"why": "能写进去就能换掉 authorized_keys 或 config", "how": "终端里运行 chmod 700 ~/.ssh"}})
	}
	for _, f := range Children(dir) {
		var fs syscall.Stat_t
		if syscall.Lstat(f, &fs) != nil || fs.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.Size >= 64<<10 || !exposureIsPrivateKey(f) {
			continue
		}
		name := filepath.Base(f)
		if k, ok := exposureKeyFacts(f); ok {
			// A key on a security key (FIDO, sk-…) needs that key plugged in: the file alone does not log in.
			if !k.encrypted && !strings.HasPrefix(k.kind, "sk-") {
				out = append(out, Finding{Rule: "exposure.ssh-key-plain", Category: CatPosture, Severity: Low, Verdict: Info, Path: f,
					Title: "SSH 私钥 " + name + " 没设口令：谁拿到这个文件就能用它登录",
					Evidence: map[string]string{"type": k.kind, "why": "备份、同步盘、被偷走的电脑里的这个文件，都能直接拿去用",
						"how": "ssh-keygen -p -f ~/.ssh/" + name + " 加一个口令；~/.ssh/config 里写 UseKeychain yes 和 AddKeysToAgent yes，平时用时不用每次输"}})
			}
			if k.weak != "" {
				out = append(out, Finding{Rule: "exposure.ssh-key-weak", Category: CatPosture, Severity: Medium, Verdict: Info, Path: f,
					Title:    "SSH 私钥 " + name + " 是" + k.weak + "，现在已经不够安全",
					Evidence: map[string]string{"type": k.kind, "how": "换一把新的：ssh-keygen -t ed25519，把新公钥加到用它的服务器上，再删掉旧的"}})
			}
		}
		if fs.Mode&0o077 == 0 {
			continue
		}
		out = append(out, Finding{Rule: "exposure.ssh-key-perm", Category: CatPosture, Severity: Medium, Verdict: Info, Path: f,
			Title: "SSH 私钥 " + name + " 别的用户也能读",
			Evidence: map[string]string{"mode": strconv.FormatUint(uint64(fs.Mode&0o777), 8), "why": "私钥只该你自己能读；ssh 也会因此拒绝用它",
				"how": "终端里运行 chmod 600 ~/.ssh/" + name}})
	}
	return out
}

type exposureKey struct {
	kind      string
	encrypted bool
	weak      string // "" not weak
}

var exposurePEMHeader = regexp.MustCompile(`^-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----$`)

// exposureKeyFacts: how a private key is kept, its type, whether a passphrase protects it, and why it is weak (DSA,
// RSA under 2048 bits). ok false when it cannot be told.
func exposureKeyFacts(path string) (exposureKey, bool) {
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) {
		return exposureKey{}, false
	}
	lines := exposureLines(string(data))
	if len(lines) == 0 {
		return exposureKey{}, false
	}
	first := lines[0]
	// The headers are put together here so that this source holds no literal key header for leak scanners.
	begin, key := "-----BEGIN ", "PRIVATE KEY-----"
	switch first {
	case begin + "OPENSSH " + key:
		var body strings.Builder
		for _, l := range lines[1:] {
			if strings.HasPrefix(l, "-----END") {
				break
			}
			body.WriteString(l)
		}
		d, err := base64.StdEncoding.DecodeString(body.String())
		if err != nil {
			return exposureKey{}, false
		}
		return exposureOpenSSHKey(d)
	case begin + "ENCRYPTED " + key:
		return exposureKey{kind: "PKCS#8", encrypted: true}, true
	case begin + key:
		return exposureKey{kind: "PKCS#8"}, true
	}
	m := exposurePEMHeader.FindStringSubmatch(first)
	if m == nil {
		return exposureKey{}, false
	}
	k := exposureKey{kind: m[1]}
	for i, l := range lines {
		if i == 3 {
			break
		}
		if strings.HasPrefix(l, "Proc-Type:") && strings.Contains(l, "ENCRYPTED") {
			k.encrypted = true
		}
	}
	if k.kind == "DSA" {
		k.weak = " DSA 的"
	}
	return k, true
}

// exposureOpenSSHKey reads the OpenSSH format ("openssh-key-v1"): the cipher ("none": no passphrase), then the public
// key, which says the type and, for RSA, the size of its modulus.
func exposureOpenSSHKey(b []byte) (exposureKey, bool) {
	magic := "openssh-key-v1\x00"
	if len(b) <= len(magic) || string(b[:len(magic)]) != magic {
		return exposureKey{}, false
	}
	i := len(magic)
	u32 := func() (int, bool) {
		if i+4 > len(b) {
			return 0, false
		}
		v := int(b[i])<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
		i += 4
		return v, true
	}
	field := func() ([]byte, bool) {
		n, ok := u32()
		if !ok || i+n > len(b) {
			return nil, false
		}
		v := b[i : i+n]
		i += n
		return v, true
	}
	cipher, ok := field()
	if !ok {
		return exposureKey{}, false
	}
	if _, ok := field(); !ok { // the key derivation's name
		return exposureKey{}, false
	}
	if _, ok := field(); !ok { // and its options
		return exposureKey{}, false
	}
	if n, ok := u32(); !ok || n < 1 {
		return exposureKey{}, false
	}
	pub, ok := field()
	if !ok {
		return exposureKey{}, false
	}
	// The public key: string type, then for RSA mpint e, mpint n.
	j := 0
	pubField := func() ([]byte, bool) {
		if j+4 > len(pub) {
			return nil, false
		}
		n := int(pub[j])<<24 | int(pub[j+1])<<16 | int(pub[j+2])<<8 | int(pub[j+3])
		if j+4+n > len(pub) {
			return nil, false
		}
		v := pub[j+4 : j+4+n]
		j += 4 + n
		return v, true
	}
	t, ok := pubField()
	if !ok {
		return exposureKey{}, false
	}
	k := exposureKey{kind: procText(t), encrypted: procText(cipher) != "none"}
	if k.kind == "ssh-dss" {
		k.weak = " DSA 的"
	}
	if k.kind == "ssh-rsa" {
		if _, ok := pubField(); ok {
			if modulus, ok := pubField(); ok {
				z := 0
				for z < len(modulus) && modulus[z] == 0 {
					z++
				}
				if bits := (len(modulus) - z) * 8; bits < 2048 {
					k.weak = " " + strconv.Itoa(bits) + " 位的 RSA"
				}
			}
		}
	}
	return k, true
}

// exposureIsPrivateKey: the first line of a PEM or OpenSSH private key; only the first bytes are read.
func exposureIsPrivateKey(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := expReadFull(f, buf)
	head := procText(buf[:n])
	return strings.HasPrefix(head, "-----BEGIN") && strings.Contains(head, "PRIVATE KEY")
}

func expReadFull(f *os.File, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			return n, err
		}
	}
	return n, nil
}

// exposureSSHLogins: who can log in with a key while remote login is on, and what every SSH login runs.
func exposureSSHLogins(dir string) []Finding {
	var out []Finding
	authorized := filepath.Join(dir, "authorized_keys")
	if text, ok := exposureHead(authorized, 64<<10); ok {
		var lines []string
		for _, l := range exposureLines(text) {
			if l = sysTrimSpaces(l); l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		if len(lines) > 0 {
			sorted := append([]string{}, lines...)
			sort.Strings(sorted)
			out = append(out, Finding{Rule: "exposure.ssh-authorized", Category: CatPosture, Severity: Low, Verdict: Info, Path: authorized,
				Title:    "有 " + strconv.Itoa(len(lines)) + " 把钥匙能用 SSH 登录这台 Mac（「远程登录」开着时）",
				Evidence: map[string]string{"keys": strconv.Itoa(len(lines)), "how": "认得每一把就留着；不认得的从 ~/.ssh/authorized_keys 里删掉那一行"},
				// Keyed on the keys themselves (public): one added later is a new finding.
				Key: dir + "|" + strings.Join(sorted, "|")})
		}
	}
	rc := filepath.Join(dir, "rc")
	var st syscall.Stat_t
	if syscall.Lstat(rc, &st) == nil {
		out = append(out, Finding{Rule: "exposure.ssh-rc", Category: CatPersistence, Severity: Medium, Verdict: Info, Path: rc,
			Title:    "每次有人用 SSH 登录这台 Mac，都会先运行 ~/.ssh/rc",
			Evidence: map[string]string{"how": "是你自己写的就留着；不是的话打开看看它做了什么，不认得就删掉"}})
	}
	return out
}

// exposureHead is the first bytes of a small regular file (not following a link, not one kept only in iCloud:
// reading it would download it); ok false for anything else.
func exposureHead(path string, limit int) (string, bool) {
	const sfDataless = 0x40000000
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size > int64(limit) || st.Flags&sfDataless != 0 {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, _ := expReadFull(f, buf)
	return procText(buf[:n]), true
}

// exposureLines are the lines of a text as Swift's split(whereSeparator: \.isNewline) gives them: empty ones left out.
func exposureLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case '\n', '\r', '\v', '\f', 0x85, 0x2028, 0x2029:
			return true
		}
		return false
	})
}

// sysTrimSpaces is Swift's trimmingCharacters(in: .whitespaces): spaces (Zs) and tabs off both ends.
func sysTrimSpaces(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r == '\t' || unicode.Is(unicode.Zs, r) })
}

// ---- run

// exposureSystem: part of macOS (AirPlay receiver, Handoff and the like listen everywhere by design).
func exposureSystem(path string) bool {
	return strings.HasPrefix(path, "/System/") || strings.HasPrefix(path, "/usr/libexec/") || strings.HasPrefix(path, "/usr/sbin/")
}

type exposureListening struct {
	ports      map[int]bool
	everywhere bool
	addresses  map[string]bool
}

func (r *ExposureRule) Run(ctx *Context) ([]Finding, error) {
	pids, look := r.Pids, r.Look
	if pids == nil {
		pids = exposureOwnProcesses
	}
	if look == nil {
		look = exposureLookThisMac
	}
	var out []Finding
	listening := map[string]*exposureListening{}
	secrets := map[string]map[string]bool{}
	for _, pid := range pids() {
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, out...)
		}
		seen := look(pid)
		if !seen.HasProgram || exposureSystem(seen.Program) {
			continue
		}
		program := seen.Program
		for _, l := range seen.Listeners {
			if l.Loopback() {
				continue
			}
			e := listening[program]
			if e == nil {
				e = &exposureListening{ports: map[int]bool{}, addresses: map[string]bool{}}
				listening[program] = e
			}
			e.ports[l.Port] = true
			e.everywhere = e.everywhere || l.Everywhere()
			e.addresses[l.Address] = true
		}
		if seen.HasArguments {
			args := seen.Arguments
			if len(args) > 0 {
				args = args[1:]
			}
			if kinds := SecretKinds(args, filepath.Base(program)); len(kinds) > 0 {
				if secrets[program] == nil {
					secrets[program] = map[string]bool{}
				}
				for _, k := range kinds {
					secrets[program][k] = true
				}
			}
		}
	}
	for _, program := range exposureSortedKeys(listening) {
		l := listening[program]
		var ports []int
		for p := range l.ports {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		var portText []string
		for _, p := range ports {
			portText = append(portText, strconv.Itoa(p))
		}
		var addresses []string
		for a := range l.addresses {
			addresses = append(addresses, a)
		}
		sort.Strings(addresses)
		where := "局域网地址上"
		if l.everywhere {
			where = "所有网络上"
		}
		joined := strings.Join(portText, "、")
		out = append(out, Finding{Rule: "exposure.listening", Category: CatPosture, Severity: Low, Verdict: Info, Path: program,
			Title: filepath.Base(program) + " 在" + where + "监听 " + joined + " 端口：同一个网络里的人能连进来",
			Evidence: map[string]string{"ports": joined, "addresses": strings.Join(addresses, "、"),
				"how": "开发用的服务改成只听 127.0.0.1（多数工具有 --host 127.0.0.1 之类的选项）；不需要就关掉。防火墙打开时会先问你放不放行"},
			Key: "exposure.listening:" + program})
	}
	for _, program := range exposureSortedKeys(secrets) {
		var kinds []string
		for k := range secrets[program] {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds) // the same words every round
		joined := strings.Join(kinds, "、")
		out = append(out, Finding{Rule: "exposure.argv-secret", Category: CatProcess, Severity: Medium, Verdict: Info, Path: program,
			Title: "正在运行的 " + filepath.Base(program) + " 命令行里带着" + joined,
			Evidence: map[string]string{"kinds": joined,
				"why": "命令行参数这台 Mac 上以你身份运行的程序都能看到，也常被记进 shell 历史、日志和崩溃报告",
				"how": "改用环境变量、配置文件或钥匙串传；已经露出去的令牌最好换一个"},
			Key: "exposure.argv-secret:" + program})
	}
	out = append(out, exposureSSH(ctx.Home)...)
	out = append(out, exposureSSHLogins(filepath.Join(ctx.Home, ".ssh"))...)
	return out, nil
}

func exposureSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
