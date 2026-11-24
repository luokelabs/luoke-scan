package core

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The checks of a dependency's install script: what npm runs by itself when a package is installed (preinstall,
// install, postinstall in its package.json, and the files those commands run), and a Python source package's
// setup.py. The skills' patterns (skillcheck.go) do most of the work; on top of them a few that only make sense for
// an install script, and a stricter idea of what counts: an install script is code nobody reads, run with the user's
// rights on every install, so only what an install script has no business doing is reported, never what the common
// legitimate ones do (build native code, download their own prebuilt binary, print a banner).
//
// A script is read line by line. A command continued over several lines (a backslash at the end of a line: a shell's
// command, a string in JavaScript or Python) is read a second time joined on its first line (installReadings), so
// nothing the lines show one by one is lost. A download piped into a shell is also found by the pipeline's stages
// (shellPiped, skillcommands.go): behind xargs, env, nohup and the like, in a shell script and in a string handed to
// exec or os.system.

// InstallSignal is one thing an install script was found to do: a fixed phrase, never the text that matched.
type InstallSignal struct {
	Kind     SignalKind `json:"kind"`
	Severity Severity   `json:"severity"`
	Label    string     `json:"label"`
	// Phrase is what the title says it does ("把 SSH 私钥发出去").
	Phrase string `json:"phrase"`
	Lines  []int  `json:"lines"`
}

// Roles of the install checks' own patterns, beyond the skills'.
const (
	// roleRecon: who and where this Mac is (user name, host name); sent away it is a dependency-confusion probe.
	roleRecon skillRole = 100 + iota
	// roleDNS: a DNS lookup; with data in the name it carries what a probe found.
	roleDNS
)

type installChecks struct {
	patterns []skillPattern
	runner   *icuRegexp
	home     *icuRegexp
}

var (
	installChecksOnce  sync.Once
	installChecksBuilt *installChecks
)

func ic() *installChecks {
	installChecksOnce.Do(func() { installChecksBuilt = buildInstallChecks() })
	return installChecksBuilt
}

// Environment variables that hold a token for a registry, GitHub or a cloud.
const installTokenVars = `(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_CONFIG__AUTH\w*|GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GITLAB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|PYPI_TOKEN|TWINE_PASSWORD|CIRCLE_TOKEN|SLACK_TOKEN)`

func buildInstallChecks() *installChecks {
	c := &installChecks{}
	c.home = icuCI(`\bhomedir\b|\bHOME\b|\bUSERPROFILE\b|~/|expanduser|Path\.home\(`)
	// What runs the text it is given: an encoded blob next to one of these is code that is decoded to run.
	c.runner = icuCS(`\b(?:node|nodejs|bun|deno|python[0-9.]*|perl|ruby)\s+(?:-\S+\s+)*-(?:e|c|p|-eval|-print)\b|\beval\b|\bFunction\s*\(|\bexec(?:Sync|File|FileSync)?\s*\(|\bspawn(?:Sync)?\s*\(|\brunIn(?:This|New)?Context\s*\(|\b_compile\s*\(|\bcompile\s*\(|\bvm\.Script\b|\bimport\s*\(\s*['"\x{60}]data:`)
	homeTest := func(line []rune, _ []int) bool { return c.home.hasRunes(line) && skillReadsLine(line) }
	c.patterns = []skillPattern{
		// npm's and PyPI's token files, read from the home: with anything sent, that is the classic.
		skillPat(SignalExfil, "", "npm 的登录令牌（~/.npmrc）", needleList("npmrc"), `\.npmrc\b`, spRole(roleSecretStrong), spTest(homeTest)),
		skillPat(SignalExfil, "", "PyPI 的上传令牌（~/.pypirc）", needleList("pypirc"), `\.pypirc\b`, spRole(roleSecretStrong), spTest(homeTest)),
		skillPat(SignalExfil, "", "yarn 的登录令牌", needleList("yarnrc"), `\.yarnrc(?:\.yml)?\b`, spRole(roleSecretWeak), spTest(homeTest)),
		// A token in the environment is used legitimately (a download from GitHub with a token): only sent to a
		// place that collects data does it count.
		skillPat(SignalExfil, "", "环境变量里的 npm、GitHub 或云服务令牌", needleList("env"),
			`\bprocess\.env\.`+installTokenVars+`\b|\bprocess\.env\[\s*['"]`+installTokenVars+`['"]|\bos\.(?:environ(?:\.get)?|getenv)\s*[\[(]\s*['"]`+installTokenVars+`['"]|\$\{?`+installTokenVars+`\b`,
			spRole(roleSecretWeak)),
		skillPat(SignalExfil, "", "全部环境变量（里面常有密钥）", needleList("process.env"),
			`\bObject\.(?:keys|entries|assign)\s*\(\s*(?:\{\s*\}\s*,\s*)?process\.env\s*\)|\.\.\.process\.env\b`, spRole(roleSecretStrong)),
		skillPat(SignalExfil, "", "这台电脑的用户名、主机名", needleList("hostname", "userinfo", "whoami", "getuser", "platform.node"),
			`\bos\.(?:hostname|userInfo)\s*\(|\bsocket\.gethostname\s*\(|\bgetpass\.getuser\s*\(|\bplatform\.node\s*\(|\$\(\s*(?:whoami|hostname)\s*\)|\x{60}(?:whoami|hostname)\x{60}|\bexec\w*\s*\(\s*['"](?:whoami|hostname)['"]|^\s*(?:whoami|hostname)\s*(?:$|[|>;&])`,
			spRole(roleRecon)),
		skillPat(SignalExfil, "", "查域名（数据可以藏在域名里发出去）", needleList("dns", "nslookup", "dig "),
			`\bdns\.(?:lookup|resolve\w*)\s*\(|\bdns\.promises\.\w+\s*\(|\bdns\.resolver\.(?:resolve|query)\s*\(|(?:^|[\s;&|(\x{60}])(?:nslookup|dig)\s+\S`,
			spRole(roleDNS)),
		skillPat(SignalExfil, High, "跑找密钥的工具，把这台电脑上的密钥都找出来", needleList("trufflehog", "gitleaks", "detect-secrets", "ggshield", "noseyparker"),
			`\b(?:trufflehog|gitleaks|detect-secrets|ggshield|noseyparker)\b`),
		skillPat(SignalPersistence, High, "往代码仓库里加 GitHub Actions 工作流", needleList(".github/workflows", "workflows"),
			`\.github/workflows\b|['"]\.github['"]\s*,\s*['"]workflows['"]`),
		skillPat(SignalExfil, High, "用你的 GitHub 令牌建仓库或登记运行器", needleList("repos", "runners"),
			`/user/repos\b|\brepos\.createForAuthenticatedUser\b|/actions/runners/registration-token\b|\bgh\s+repo\s+create\b`),
		skillPat(SignalSupplyChain, High, "用你的 npm 令牌发布包（会传到你发布的包里）", needleList("npm publish", "npm", "/-/"),
			`(?:^|[\s;&|(\x{60}'"])npm\s+(?:publish|token\s+create|version\s+patch[^\n]*&&\s*npm\s+publish)\b|/-/(?:npm/v1/tokens|user/org\.couchdb\.user)\b`),
		skillPat(SignalDownloadExec, High, "把编码过的内容解开直接运行", needleList("buffer.from", "atob"),
			`\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|runInThisContext|runInNewContext|_compile)\s*\(\s*(?:Buffer\.from|atob)\s*\(`),
		skillPat(SignalDownloadExec, High, "把这台电脑的命令行交给别人远程控制（反弹 shell）", needleList("/dev/tcp", "nc ", "ncat", "socat"),
			`\b(?:bash|sh|zsh)\s+-i\b[^\n]*/dev/(?:tcp|udp)/|\b(?:nc|ncat)\s+(?:-\S+\s+)*-[ec]\s*/bin/|\bsocat\b[^\n]*\bexec:`),
	}
	return c
}

// installSegment is a piece of a line to scan, with the line it is on.
type installSegment struct {
	text string
	line int
}

// installSegments cuts a file into pieces the checks can take: a line as it is, a long one (minified code) cut at
// statement boundaries into pieces of at most max characters, all keeping the line number.
func installSegments(text string, max int) []installSegment {
	var out []installSegment
	for i, raw := range strings.Split(text, "\n") {
		line := []rune(strings.TrimSuffix(raw, "\r"))
		for len(line) > max {
			cut := -1
			for j := max; j > max/2; j-- {
				if r := line[j-1]; r == ';' || r == '}' || r == '{' || r == ',' {
					cut = j
					break
				}
			}
			if cut < 0 {
				cut = max
			}
			out = append(out, installSegment{string(line[:cut]), i + 1})
			line = line[cut:]
		}
		out = append(out, installSegment{string(line), i + 1})
	}
	return out
}

// installLang is how a script's comments are written, which says what of a line is only a comment.
type installLang int

const (
	// installShell: sh's (also a hook's commands, and a file run without a #! line): # to the end of the line.
	installShell installLang = iota
	// installJS: // to the end of the line, /* … */ (a line starting with * only inside one opened at a line's start).
	installJS
	// installPython: # to the end of the line.
	installPython
	// installAny: not known (a text given without its file's name): any of these.
	installAny
)

var installJSExt = aiSet("js", "cjs", "mjs", "jsx", "ts", "cts", "mts", "tsx")

// installLangOf is a script's language by its extension, else by its #! line; a file with neither is run by sh.
// Without a name (path ""), a text without a #! line is any of them.
func installLangOf(path, text string) installLang {
	ext := strings.ToLower(aiNSExt(path))
	switch {
	case installJSExt[ext]:
		return installJS
	case ext == "py":
		return installPython
	case ext == "sh" || ext == "bash" || ext == "zsh" || ext == "command":
		return installShell
	}
	first := text
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if strings.HasPrefix(first, "#!") {
		switch {
		case strings.Contains(first, "node") || strings.Contains(first, "bun") || strings.Contains(first, "deno") || strings.Contains(first, "tsx") ||
			strings.Contains(first, "ts-node"):
			return installJS
		case strings.Contains(first, "python"):
			return installPython
		}
		return installShell
	}
	if path == "" {
		return installAny
	}
	return installShell
}

// installCodeReader reads a script's lines in order: each line's code and whether it is only a comment, in the
// script's own language. Unlike scriptCode (which does not know the language) a line is not taken for a comment by
// what would be code in this one: REM, -- and # (a field in JavaScript) start code in a JavaScript file, and a line
// starting with * is a comment only inside a /* opened at the start of an earlier line (otherwise it continues an
// expression: "a\n* run()").
func installCodeReader(lang installLang) func(line string) (code string, only bool) {
	inBlock := false
	return func(line string) (string, bool) {
		s := aiTrimWS(line)
		if s == "" {
			return "", false
		}
		for {
			switch lang {
			case installJS, installAny:
				if lang == installAny && strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "#!") && !inBlock {
					return "", true
				}
				if inBlock {
					i := strings.Index(s, "*/")
					if i < 0 {
						if strings.HasPrefix(s, "*") {
							return "", true
						}
						return s, false // not a comment's usual line: read as code, as before
					}
					inBlock = false
					s = aiTrimWS(s[i+2:])
				} else if strings.HasPrefix(s, "/*") {
					i := strings.Index(s[2:], "*/")
					if i < 0 {
						inBlock = true
						return "", true
					}
					s = aiTrimWS(s[2+i+2:])
				} else if strings.HasPrefix(s, "//") {
					return "", true
				} else {
					return s, false
				}
			default:
				if strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "#!") {
					return "", true
				}
				return s, false
			}
			if s == "" {
				return "", true
			}
		}
	}
}

// installTalks: whether a match is only a pattern describing such things rather than code doing them: it sits inside a
// JS regex literal (/…/), or inside a string handed straight to a regex constructor (RegExp(, re.compile(, re.search(, …).
// Words never excuse a match, wherever they stand: a variable named flags, "never" or a regex escape in the same string,
// a word in another statement. Any of them is one word an install script could add to hide a command run through a
// variable. Comments are blanked first, so nothing in them makes a pattern. A pattern taken apart and run
// (/… | sh/.source handed to exec) is not seen (docs/install-scripts.md, 看不到的). sh has no pattern literals.
func installTalks(s []rune, m []int, lang installLang) bool {
	if lang == installShell {
		return false
	}
	ls, le, q := installLiteralAt(s, m[0], lang)
	if ls < 0 || m[1] > le {
		return false
	}
	if q == '/' {
		return true
	}
	from := ls - 48
	if from < 0 {
		from = 0
	}
	return installRegexCall.MatchString(string(s[from:ls]))
}

// installRegexCall: what a string handed straight to a regex constructor follows (a Python raw or bytes prefix allowed).
var installRegexCall = regexp.MustCompile(`(?:\bnew\s+RegExp|\bRegExp|\bre\.(?:compile|search|match|fullmatch|findall|finditer|sub|subn|split))\s*\(\s*[rRbBuU]{0,2}$`)

// installLiteralAt: the string or regex literal the rune at pos is inside (start, end past the closing quote, and its
// quote; '/' is a JS regex literal), or -1 when pos is in code or in a comment. Read as the language does, left to
// right: quotes ', ", and ` (not in Python), with backslash escapes; outside them a comment (// and /* … */ in JS,
// # in Python, both when the language is not known) is not code; a / opens a regex only where an expression starts
// (after ( , = : [ ! & | ? { } ; and operators, or at the start), else it divides.
func installLiteralAt(t []rune, pos int, lang installLang) (int, int, rune) {
	n := len(t)
	js, hash := lang != installPython, lang != installJS
	prev := func(i int) rune {
		for j := i - 1; j >= 0; j-- {
			if t[j] != ' ' && t[j] != '\t' {
				return t[j]
			}
		}
		return 0
	}
	var q rune
	start := -1
	for i := 0; i < n; i++ {
		c := t[i]
		if q != 0 {
			switch {
			case c == '\\':
				i++
			case c == q || (q == '/' && c == '\n'):
				if start < pos && pos < i {
					return start, i + 1, q
				}
				q, start = 0, -1
			}
			continue
		}
		if i > pos {
			return -1, -1, 0
		}
		switch {
		case js && c == '/' && i+1 < n && t[i+1] == '/', hash && c == '#' && (i == 0 || t[i-1] == ' ' || t[i-1] == '\t'):
			return -1, -1, 0 // the rest of the line is a comment
		case js && c == '/' && i+1 < n && t[i+1] == '*':
			j := i + 2
			for j+1 < n && !(t[j] == '*' && t[j+1] == '/') {
				j++
			}
			if pos < j+2 {
				return -1, -1, 0 // in the comment
			}
			i = j + 1
		case c == '\'' || c == '"' || (c == '`' && js):
			q, start = c, i
		case js && c == '/' && (prev(i) == 0 || strings.ContainsRune("(,=:[!&|?{};+-*%<>~^", prev(i))):
			q, start = '/', i
		}
	}
	return -1, -1, 0
}

// installHit is a hit, with where it is in the file.
type installHit struct {
	skillHit
	// encoded: found in what an encoded blob decodes to.
	encoded bool
}

// installHits are the skills' and the install checks' hits in some segments.
func installHits(segs []installSegment, encoded bool, lang installLang, cancelled func() bool) []installHit {
	c, sc := ic(), skc()
	var lines []string
	for _, s := range segs {
		lines = append(lines, s.text)
	}
	var out []installHit
	opts := skillScanOpts{
		code:      installCodeReader(lang),
		talks:     func(s []rune, m []int) bool { return installTalks(s, m, lang) },
		cancelled: cancelled,
	}
	for _, h := range skillScanFileWith(strings.Join(lines, "\n"), "install.js", true, nil, opts).hits {
		h.line = segs[h.line-1].line
		out = append(out, installHit{h, encoded})
	}
	reader := installCodeReader(lang)
	for i, s := range segs {
		if cancelled != nil && i%64 == 0 && cancelled() {
			return out
		}
		code, only := reader(s.text)
		if only {
			continue
		}
		r := []rune(code)
		// Joined path pieces (".ssh", "id_rsa") read as one path, as the skills' checks read them.
		r = sc.joined.replaceAll(r, "/")
		lower := aiLower(string(r))
		for _, p := range c.patterns {
			if !aiContainsAny(lower, p.needles) {
				continue
			}
			m := p.re.find(r, 0)
			if m == nil || (p.unless != nil && p.unless.hasRunes(r)) || (p.test != nil && !p.test(r, m)) {
				continue
			}
			if installTalks(r, m, lang) {
				continue // about such things (a list of what to look for), not doing them
			}
			out = append(out, installHit{skillHit{label: p.label, kind: p.kind, severity: p.severity, role: p.role, line: s.line}, encoded})
		}
	}
	return out
}

// installReadings are a script's hits: its lines as they are, and, when a command is continued over several lines,
// the text with those put on their first line as well (skillJoinContinued; what it leaves empty is in the first
// reading). The joined lines are cut where the skills' checks stop reading a line, not shorter: a continued command
// is not minified code.
func installReadings(text string, encoded bool, lang installLang, cancelled func() bool) (segs []installSegment, hits []installHit) {
	segs = installSegments(text, 2000)
	hits = installHits(segs, encoded, lang, cancelled)
	if joined := skillJoinContinued(text, true); joined != text && !(cancelled != nil && cancelled()) {
		hits = append(hits, installHits(installSegments(joined, skillLineMax), encoded, lang, cancelled)...)
	}
	return segs, hits
}

// installBlobs: the long encoded runs in the segments. Each that decodes to text is checked like the rest (its hits
// marked encoded); one next to something that runs code is itself a hit: code decoded to run.
func installBlobs(segs []installSegment, lang installLang, cancelled func() bool) []installHit {
	c := ic()
	var out []installHit
	reader := installCodeReader(lang)
	for i, s := range segs {
		if cancelled != nil && i%64 == 0 && cancelled() {
			return out
		}
		r := []rune(s.text)
		code, only := reader(s.text)
		blobs := skillBlobs(r)
		if len(blobs) == 0 {
			continue
		}
		if !only && c.runner.has(code) {
			out = append(out, installHit{skillHit{label: "把一大段编码过的内容解开直接运行", kind: SignalDownloadExec, severity: High,
				role: rolePlain, line: s.line}, false})
		}
		for _, b := range blobs {
			if b == nil {
				continue
			}
			_, inner := installReadings(*b, true, lang, cancelled)
			for _, h := range inner {
				h.line = s.line
				out = append(out, h)
			}
		}
	}
	return out
}

// installSecretPhrase is how the title says a secret is sent: 把 <what> 发出去.
func installSecretPhrase(label string) string {
	what := label
	if i := strings.Index(what, "（"); i > 0 && !strings.Contains(what, "~/") {
		what = what[:i]
	}
	return "把" + installSpaced(what) + "发出去"
}

// installSpaced puts a space between Chinese and a Latin word or path at either end.
func installSpaced(what string) string {
	if what == "" {
		return what
	}
	if r := aiFirstRune(what); r < 0x80 {
		what = " " + what
	}
	if r := []rune(what); r[len(r)-1] < 0x80 {
		what += " "
	}
	return what
}

// InstallScriptSignals: what the text of an install script does that an install script has no business doing. Each
// signal's lines are the file's. Without the file's name its comments are read by its #! line, else as any language's.
func InstallScriptSignals(text string) []InstallSignal {
	s, _ := installSignals(text, installLangOf("", text), nil)
	return s
}

// InstallFileSignals: InstallScriptSignals for a file of the given name, which (its extension, else its #! line)
// says how its comments are written; ok false when cancelled says to stop (what was found so far is then not the
// whole file's).
func InstallFileSignals(name, text string, cancelled func() bool) ([]InstallSignal, bool) {
	return installSignals(text, installLangOf(name, text), cancelled)
}

func installSignals(text string, lang installLang, cancelled func() bool) ([]InstallSignal, bool) {
	segs, hits := installReadings(text, false, lang, cancelled)
	hits = append(hits, installBlobs(segs, lang, cancelled)...)
	if cancelled != nil && cancelled() {
		return nil, false
	}
	var out []InstallSignal
	add := func(kind SignalKind, sev Severity, label, phrase string, lines ...int) {
		out = append(out, InstallSignal{Kind: kind, Severity: sev, Label: label, Phrase: phrase, Lines: lines})
	}
	hidden := func(h installHit, label string) string {
		if h.encoded {
			return label + "（藏在编码里）"
		}
		return label
	}
	var sending, dns, drops []installHit
	for _, h := range hits {
		switch h.role {
		case roleSend:
			sending = append(sending, h)
		case roleDrop:
			sending = append(sending, h)
			drops = append(drops, h)
		case roleDNS:
			dns = append(dns, h)
		}
	}
	// A secret read and sent from the same file. A strong one with anything sent; a weak one (a token in the
	// environment, a project's .env) only to a place that collects data.
	paired := map[string]bool{}
	sendingOrDNS := append(append([]installHit{}, sending...), dns...)
	for _, h := range hits {
		strong := h.role == roleSecretStrong
		if !strong && h.role != roleSecretWeak {
			continue
		}
		with := drops
		if strong {
			with = sendingOrDNS
		}
		if len(with) == 0 || paired[h.label] {
			continue
		}
		paired[h.label] = true
		add(SignalExfil, High, hidden(h, "读"+installSpaced(h.label)+"再发到网上"), installSecretPhrase(h.label), h.line, with[0].line)
	}
	// Who and where this Mac is, sent away: what a dependency-confusion probe does.
	for _, h := range hits {
		if h.role != roleRecon {
			continue
		}
		if with := sendingOrDNS; len(with) > 0 {
			add(SignalExfil, Medium, hidden(h, "把这台电脑的用户名、主机名发到网上"), "把这台电脑的用户名、主机名发出去", h.line, with[0].line)
			break
		}
	}
	// A download made executable, as the skills' check pairs them.
	var downloads, chmods []installHit
	verified := false
	for _, h := range hits {
		switch h.role {
		case roleDownload:
			downloads = append(downloads, h)
		case roleChmodX:
			chmods = append(chmods, h)
		case roleChecksum:
			verified = true
		}
	}
	if !verified && len(downloads) > 0 && len(chmods) > 0 {
		// By line, each line's words once: minified code has thousands of each on one line.
		segText := map[int]*strings.Builder{}
		for _, s := range segs {
			b := segText[s.line]
			if b == nil {
				b = &strings.Builder{}
				segText[s.line] = b
			}
			b.WriteString(s.text)
		}
		mentioned := map[int]map[string]bool{}
		words := func(line int) map[string]bool {
			m, ok := mentioned[line]
			if !ok {
				m = skillMentioned(segText[line].String())
				mentioned[line] = m
			}
			return m
		}
		lines := func(hs []installHit) []int {
			var out []int
			for _, h := range hs {
				out = append(out, h.line)
			}
			return aiUniqueInts(out)
		}
		dl, cl := lines(downloads), lines(chmods)
	pairs:
		for _, d := range dl {
			for _, ch := range cl {
				if aiAbs(ch-d) > 15 {
					continue
				}
				a, b := words(ch), words(d)
				for k := range a {
					if b[k] {
						add(SignalDownloadExec, High, "下载程序、加上执行权限再运行", "下载程序来运行", d, ch)
						break pairs
					}
				}
			}
		}
	}
	for _, h := range hits {
		if !installCounts(h) {
			continue
		}
		label := h.label
		phrase := label
		if h.role == roleSecretStrong {
			if paired[h.label] {
				continue
			}
			label, phrase = "读"+installSpaced(h.label), "读"+installSpaced(h.label)
		}
		sev := h.severity
		if sev == "" {
			sev = Medium
		}
		add(h.kind, sev, hidden(h, label), phrase, h.line)
	}
	// A blob next to code that runs it, where the decoding itself was recognised on the same lines: said once.
	decoded := map[int]bool{}
	for _, x := range out {
		if x.Label == "把编码过的内容解开直接运行" {
			for _, l := range x.Lines {
				decoded[l] = true
			}
		}
	}
	kept := out[:0]
	for _, x := range out {
		if x.Label == "把一大段编码过的内容解开直接运行" && len(x.Lines) == 1 && decoded[x.Lines[0]] {
			continue
		}
		kept = append(kept, x)
	}
	return mergeInstallSignals(kept), true
}

// installCounts: whether a hit counts on its own in an install script.
func installCounts(h installHit) bool {
	switch h.role {
	case roleSend, roleDownload, roleChmodX, roleChecksum, roleDelete, roleSecretWeak, roleRecon, roleDNS:
		return false
	case roleSecretStrong:
		// Reading it is reported; the environment as a whole (often passed on to a child process) only when sent.
		return !strings.HasPrefix(h.label, "全部环境变量")
	case roleDrop:
		return h.severity == Medium || h.severity == High
	case roleInjection, roleConceal:
		return false
	}
	switch h.kind {
	case SignalSupplyChain:
		return h.severity == High // the install checks' own (publishing with your token); not unpinned installs
	case SignalPermission, SignalInjection, SignalUnreadable:
		return false
	case SignalEscalation:
		// A prebuilt binary's installer may take the quarantine flag off what it downloaded; a lone sudo is weak.
		return h.severity.Rank() >= Medium.Rank() && !strings.Contains(h.label, "隔离")
	}
	return h.severity.Rank() >= Medium.Rank()
}

// mergeInstallSignals: one per label, with its lines, the most serious first (then by the skills' priority).
func mergeInstallSignals(signals []InstallSignal) []InstallSignal {
	var order []string
	by := map[string]*InstallSignal{}
	for _, s := range signals {
		if e, ok := by[s.Label]; ok {
			// Lines gathered, made unique once at the end: a minified file can have thousands of the same.
			e.Lines = append(e.Lines, s.Lines...)
			if s.Severity.Rank() > e.Severity.Rank() {
				e.Severity = s.Severity
			}
			continue
		}
		order = append(order, s.Label)
		s.Lines = append([]int{}, s.Lines...)
		by[s.Label] = &s
	}
	out := make([]InstallSignal, 0, len(order))
	for _, k := range order {
		e := *by[k]
		e.Lines = aiUniqueInts(e.Lines)
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return signalRank(a.Kind) < signalRank(b.Kind)
	})
	return out
}

// ---------------------------------------------------------------- package.json

// InstallHooks are the scripts npm runs by itself when it installs a package, in the order it runs them.
var InstallHooks = []string{"preinstall", "install", "postinstall"}

// InstallPackage is what a package.json says about installing it.
type InstallPackage struct {
	Name, Version string
	// Hooks: hook → command, for the install hooks it has.
	Hooks map[string]string
	// Lines: hook → the line of package.json it is on.
	Lines map[string]int
	// Scripts are all its scripts (an install hook may run another: npm run build).
	Scripts map[string]string
}

// ParseInstallPackage reads a package.json's name, version and scripts; ok false when it is not one.
// Keys are taken exactly as npm takes them ("scripts", not "SCRIPTS": Go's decoder would match either), the last of
// a key given twice, as JSON.parse does; a leading byte order mark is dropped, as npm drops it.
func ParseInstallPackage(data []byte) (InstallPackage, bool) {
	data = bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil || raw == nil {
		return InstallPackage{}, false
	}
	p := InstallPackage{Hooks: map[string]string{}, Lines: map[string]int{}, Scripts: map[string]string{}}
	json.Unmarshal(raw["name"], &p.Name)
	json.Unmarshal(raw["version"], &p.Version)
	var scripts map[string]json.RawMessage
	json.Unmarshal(raw["scripts"], &scripts)
	for k, v := range scripts {
		var s string
		if json.Unmarshal(v, &s) == nil {
			p.Scripts[k] = s
		}
	}
	for _, h := range InstallHooks {
		if s, ok := p.Scripts[h]; ok && aiTrimWS(s) != "" {
			p.Hooks[h] = s
		}
	}
	// The line each hook is on: the first "<hook>": after "scripts".
	lines := strings.Split(string(data), "\n")
	start := 0
	for i, l := range lines {
		if strings.Contains(l, `"scripts"`) {
			start = i
			break
		}
	}
	for h := range p.Hooks {
		p.Lines[h] = 1
		for i := start; i < len(lines); i++ {
			if strings.Contains(lines[i], `"`+h+`"`) {
				p.Lines[h] = i + 1
				break
			}
		}
	}
	return p, true
}

// installCommands splits a hook's command into its commands (at new lines, && || ; | & and parentheses outside
// quotes, a # comment left out), each as its words with the quotes taken off.
func installCommands(line string) [][]string {
	var out [][]string
	var words []string
	var word strings.Builder
	inWord := false
	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endCommand := func() {
		endWord()
		if len(words) > 0 {
			out = append(out, words)
		}
		words = nil
	}
	var quote rune
	comment := false
	for _, r := range line {
		if comment {
			if r == '\n' || r == '\r' {
				comment = false
				endCommand()
			}
			continue
		}
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == '"' || r == '\'' || r == '`':
			quote, inWord = r, true
		case r == '#' && !inWord:
			comment = true // sh: a comment to the end of the line
		case r == ' ' || r == '\t':
			endWord()
		case r == '\n' || r == '\r' || r == '&' || r == '|' || r == ';' || r == '(' || r == ')':
			endCommand() // npm runs a hook with sh -c: a new line is a new command
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	endCommand()
	return out
}

// installInterpreters: the programs whose first argument that is not an option is the file they run.
var installInterpreters = aiSet("node", "nodejs", "bun", "tsx", "ts-node", "sh", "bash", "zsh", "dash", "python", "python3", "python2")

// installInline: an option that makes an interpreter run the text that follows instead of a file.
var installInline = aiSet("-e", "--eval", "-p", "--print", "-c", "-m")

// installShells run the file that follows their options, or with -c the commands that follow it.
var installShells = aiSet("sh", "bash", "zsh", "dash")

// installShellTakesValue: a shell's options followed by their value (-o pipefail), not by the file.
var installShellTakesValue = aiSet("-o", "+o", "-O", "+O", "--rcfile", "--init-file")

// installRequireRx: a file of the package required by inline code.
var installRequireRx = icuCS(`\brequire\s*\(\s*['"](\.{1,2}/[^'"\s]+)['"]\s*\)`)

// installTakesValue: an option followed by its value, not by the file.
var installTakesValue = aiSet("-r", "--require", "--import", "--loader", "--experimental-loader", "--input-type", "-W", "-X", "--conditions", "-C")

// installPreloads: node's options whose value is code it loads first.
var installPreloads = aiSet("-r", "--require", "--import", "--loader", "--experimental-loader")

// installPrefixWords: shell words before the command itself.
var installPrefixWords = aiSet("cross-env", "env", "exec", "nohup", "time", "command", "builtin", "then", "do", "else", "if", "while", "until",
	"{", "!", "!!")

// installPreloaded are the package's files node options load first (-r ./x.js, --require=./x.js, --import ./x.mjs).
func installPreloaded(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a, v := args[i], ""
		if j := strings.Index(a, "="); j > 0 && installPreloads[a[:j]] {
			v = a[j+1:]
		} else if installPreloads[a] && i+1 < len(args) {
			v = args[i+1]
			i++
		}
		if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
			out = append(out, v)
		}
	}
	return out
}

// InstallCommandTargets are the files of the package a hook command runs ("node install.js", "sh ./setup.sh",
// "./bin/postinstall", what node -r and NODE_OPTIONS load first), as written, and the scripts it runs by name ("npm
// run build"). A program that is not a file of the package (node-gyp, prebuild-install, husky) is not followed: it is
// not the package's own code.
func InstallCommandTargets(command string) (files []string, scripts []string) {
	refs, scripts := installCommandTargets(command)
	for _, r := range refs {
		files = append(files, r.path)
	}
	return files, scripts
}

// installRef is a file a hook command runs, and whether it runs it itself (./bin/x: the system decides how to run it)
// rather than through an interpreter (node x, sh x), which reads it as a script whatever it starts with.
type installRef struct {
	path   string
	direct bool
}

// installCommandTargets reads a command as written and, when a line of it is continued on the next (a backslash at
// its end), joined as well: `node \` and `evil.js` on the next line run evil.js through node.
func installCommandTargets(command string) (files []installRef, scripts []string) {
	files, scripts = installTargetsIn(command)
	if joined := skillJoinContinued(command, true); joined != command {
		f, s := installTargetsIn(joined)
		files, scripts = append(files, f...), append(scripts, s...)
	}
	return files, scripts
}

func installTargetsIn(command string) (files []installRef, scripts []string) {
	via := func(paths ...string) {
		for _, p := range paths {
			files = append(files, installRef{path: p})
		}
	}
	for _, words := range installCommands(command) {
		// Leading variables, and the words that only lead up to the command.
		for len(words) > 0 {
			w := words[0]
			if j := strings.Index(w, "="); j > 0 && !strings.HasPrefix(w, "-") {
				if w[:j] == "NODE_OPTIONS" {
					via(installPreloaded(strings.Fields(w[j+1:]))...)
				}
				words = words[1:]
				continue
			}
			if !installPrefixWords[filepath.Base(w)] {
				break
			}
			words = words[1:]
		}
		if len(words) == 0 {
			continue
		}
		first := words[0]
		base := filepath.Base(first)
		switch {
		case installShells[base]:
			// sh [options] file, or sh -c '…' (-c alone or among one-letter options: -ec). -e, -x, -o pipefail are
			// options: the file still follows them.
			for i := 1; i < len(words); i++ {
				w := words[i]
				if w == "--" {
					if i+1 < len(words) {
						via(words[i+1])
					}
					break
				}
				if installShellTakesValue[w] {
					i++
					continue
				}
				if len(w) > 1 && (w[0] == '-' || w[0] == '+') {
					if w[0] == '-' && !strings.HasPrefix(w, "--") && strings.ContainsRune(w[1:], 'c') {
						// sh -c '…': the commands in it.
						if i+1 < len(words) {
							f, s := installCommandTargets(words[i+1])
							files, scripts = append(files, f...), append(scripts, s...)
						}
						break
					}
					continue
				}
				via(w)
				break
			}
		case installInterpreters[base]:
			via(installPreloaded(words[1:])...)
			for i := 1; i < len(words); i++ {
				w := words[i]
				if installInline[w] {
					if i+1 < len(words) && (w == "-e" || w == "--eval" || w == "-p" || w == "--print") {
						// node -e "try{require('./postinstall')}catch(e){}": the files it requires.
						r := []rune(words[i+1])
						for _, m := range installRequireRx.findAll(r) {
							via(string(r[m[2]:m[3]]))
						}
					}
					break
				}
				if installTakesValue[w] {
					i++
					continue
				}
				if strings.HasPrefix(w, "-") {
					continue
				}
				via(w)
				break
			}
		case (first == "npm" || first == "pnpm" || first == "yarn" || first == "bun") && len(words) >= 2:
			if (words[1] == "run" || words[1] == "run-script") && len(words) >= 3 {
				scripts = append(scripts, words[2])
			} else if first == "yarn" && !strings.HasPrefix(words[1], "-") && words[1] != "install" && words[1] != "add" {
				scripts = append(scripts, words[1])
			}
		case strings.HasPrefix(first, "./") || strings.HasPrefix(first, "../") || scriptExt[strings.ToLower(aiNSExt(first))]:
			files = append(files, installRef{path: first, direct: true})
		}
	}
	return files, scripts
}

// InstallTargetFile is where a target written in a hook is in the package, by its path relative to the package:
// only a regular file inside it (no link, nothing outside); node's way of finding a file without its extension. ok
// false: not a file of the package.
func InstallTargetFile(pkg, written string) (string, bool) {
	if strings.HasPrefix(written, "/") || strings.HasPrefix(written, "~") || strings.Contains(written, "$") {
		return "", false
	}
	rel := filepath.Clean(written)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	for _, cand := range []string{rel, rel + ".js", rel + ".cjs", rel + ".mjs", rel + "/index.js"} {
		// Not through a link on the way: each folder on the way is a folder.
		ok := true
		dir := pkg
		parts := strings.Split(cand, "/")
		for _, p := range parts[:len(parts)-1] {
			dir = filepath.Join(dir, p)
			if !aiIsDir(dir) {
				ok = false
				break
			}
		}
		if ok && aiIsReg(filepath.Join(pkg, cand)) {
			return cand, true
		}
	}
	return "", false
}

// installHookLines is a package's hook commands as text to check, one line of a command to a line (a hook's command
// can have several: sh runs each), followed by the scripts they run by name, each once; and for each line of that
// text, the line of package.json its hook is on.
func installHookLines(p InstallPackage) (string, []int) {
	var text []string
	var at []int
	put := func(line int, cmd string) {
		for _, l := range strings.FieldsFunc(cmd, func(r rune) bool { return r == '\n' || r == '\r' }) {
			text = append(text, l)
			at = append(at, line)
		}
	}
	named := map[string]bool{}
	for _, h := range InstallHooks {
		cmd, ok := p.Hooks[h]
		if !ok {
			continue
		}
		put(p.Lines[h], cmd)
		_, scripts := InstallCommandTargets(cmd)
		for _, n := range scripts {
			if s, ok := p.Scripts[n]; ok && !named[n] {
				named[n] = true
				put(p.Lines[h], s)
			}
		}
	}
	return strings.Join(text, "\n"), at
}

// InstallHookSignals: what a package's hook commands themselves do, by the lines of package.json they are on.
func InstallHookSignals(p InstallPackage) []InstallSignal {
	text, at := installHookLines(p)
	signals, _ := installSignals(text, installShell, nil) // npm runs a hook with sh -c
	for i := range signals {
		var lines []int
		for _, l := range signals[i].Lines {
			if l >= 1 && l <= len(at) {
				lines = append(lines, at[l-1])
			}
		}
		signals[i].Lines = aiUniqueInts(lines)
	}
	return signals
}

// InstallTarget is a file a hook runs.
type InstallTarget struct {
	Hook string `json:"hook"`
	// Path is relative to the package.
	Path string `json:"path"`
	// Direct: only ever run by itself (./bin/x), never through an interpreter (node x, sh x).
	Direct bool `json:"direct,omitempty"`
}

// InstallPackageTargets are the files of the package its hooks run (directly, or through a script run by name, one
// level), each once, in the order npm runs them.
func InstallPackageTargets(pkg string, p InstallPackage) []InstallTarget {
	var out []InstallTarget
	seen := map[string]int{}
	for _, h := range InstallHooks {
		cmd, ok := p.Hooks[h]
		if !ok {
			continue
		}
		files, named := installCommandTargets(cmd)
		for _, n := range named {
			if s, ok := p.Scripts[n]; ok && n != h {
				more, _ := installCommandTargets(s)
				files = append(files, more...)
			}
		}
		for _, f := range files {
			rel, ok := InstallTargetFile(pkg, f.path)
			if !ok {
				continue
			}
			if i, ok := seen[rel]; ok {
				out[i].Direct = out[i].Direct && f.direct
				continue
			}
			seen[rel] = len(out)
			out = append(out, InstallTarget{Hook: h, Path: rel, Direct: f.direct})
		}
	}
	return out
}

// installNameOK: an npm package name as npm allows it; anything else (from a package.json nobody checked) is not shown.
var installNameRx = icuCS(`^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$`)

func installNameOK(n string) bool { return len(n) <= 214 && installNameRx.has(n) }

var installVersionRx = icuCS(`^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]{1,40})?$`)

// installFolderName is a package's name as npm installed it: the folder under node_modules (@scope/name or name);
// "" when that is not a name npm allows.
func installFolderName(pkg string) string {
	i := strings.LastIndex(pkg, "/node_modules/")
	if i < 0 {
		return ""
	}
	name := pkg[i+len("/node_modules/"):]
	if !installNameOK(name) {
		return ""
	}
	return name
}

// installWho is a package as shown: its name by the folder npm put it in (not the name its package.json claims: a
// look-alike can claim any), with its version when that is one.
func installWho(p InstallPackage, pkg string) string {
	name := installFolderName(pkg)
	if name == "" {
		name = "一个名字不合规矩的包"
	}
	if installVersionRx.has(p.Version) {
		return name + "@" + p.Version
	}
	return name
}

// installSegmentRx: a folder or file name safe to show: letters, digits, _ and -, at most one dot.
var installSegmentRx = icuCS(`^[A-Za-z0-9_-]{1,60}(?:\.[A-Za-z0-9_-]{1,10})?$`)

// installShownFile is a file of a package as shown on a card: as written when it is plainly a path to a script, else
// only what it is. A file name comes from the package and could read as a web address or an instruction.
func installShownFile(rel string) string {
	parts := strings.Split(rel, "/")
	ok := len(rel) <= 100 && len(parts) <= 6
	for i, p := range parts {
		if !ok {
			break
		}
		ext := aiNSExt(p)
		last := i == len(parts)-1
		ok = installSegmentRx.has(p) && (ext == "" || (last && (scriptExt[strings.ToLower(ext)] || ext == "json")))
	}
	if ok {
		return rel
	}
	return "钩子运行的一个脚本"
}

// installLinesText is "第 3、9 行".
func installLinesText(lines []int) string {
	var ls []string
	for i, l := range lines {
		if i >= 4 {
			break
		}
		ls = append(ls, strconv.Itoa(l))
	}
	more := ""
	if len(lines) > 4 {
		more = "等"
	}
	return "第 " + strings.Join(ls, "、") + " 行" + more
}
