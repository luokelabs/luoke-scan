package core

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// McpRule: what AI tools are set up to start: the MCP servers in their configuration files, each a program that runs
// with the user's rights whenever the tool does, and the keys written into those files as plain text. Only names,
// commands and the kinds of keys are kept, never a value.
type McpRule struct{}

func init() { Register("mcp", NewMcpRule) }

// NewMcpRule is the same for this Mac and a fake home: it only reads the home's files.
func NewMcpRule(l *Layout, f *Fakes) Rule { return &McpRule{} }

func (r *McpRule) ID() string      { return "mcp" }
func (r *McpRule) Emits() []string { return []string{"mcp.servers", "mcp.secrets"} }

// mcpConfigs: where each tool keeps its servers, relative to the home, and under which key (rules/settings-files.json).
var mcpConfigs []mcpConfig

// mcpSecretNames: names that say a value is a key.
var mcpSecretNames = []string{"key", "token", "secret", "password", "passwd", "auth", "credential", "bearer"}

// ---------------------------------------------------------------- secrets on command lines (as the exposure check
// tells them; a copy of its own until that check is here)

var mcpSecretFlags = aiSet("--password", "--passwd", "--token", "--auth-token", "--access-token",
	"--api-key", "--apikey", "--api-token", "--secret", "--client-secret", "--secret-key", "--private-key")

// mcpSecretShapes: kind, the text every match contains, pattern.
var mcpSecretShapes = []struct {
	kind    string
	needles []string
	re      *icuRegexp
}{
	{"AWS 访问密钥", []string{"AKIA"}, icuCS(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub 令牌", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, icuCS(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{40,}`)},
	{"GitLab 令牌", []string{"glpat-"}, icuCS(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{"Slack 令牌", []string{"xox"}, icuCS(`\bxox[abpr]-[A-Za-z0-9-]{10,}`)},
	// Not a path segment (/sk-learn-…) or part of a longer name; real keys carry digits.
	{"API 密钥（sk-…）", []string{"sk-"}, icuCS(`(?<![A-Za-z0-9/_.-])sk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}`)},
	{"网址里的密码", []string{"://"}, icuCS(`[a-z][a-z0-9+.-]*://[^/\s:@]*:[^/\s@]+@`)},
}

// mcpSecretValue: a flag's value that is a secret itself, not where one is kept: a path, @file, $VARIABLE, nothing.
func mcpSecretValue(v string) bool {
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

// mcpCommandSecretKinds: what kinds of secrets a command line carries (only the kind, never the value). program: the
// program's file name.
func mcpCommandSecretKinds(args []string, program string) []string {
	var kinds []string
	for i, a := range args {
		lower := aiLower(a)
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		if eq := strings.Index(lower, "="); eq >= 0 && mcpSecretFlags[lower[:eq]] && mcpSecretValue(mcpAfterEquals(a, lower, eq)) {
			kinds = append(kinds, "参数 "+lower[:eq])
		} else if mcpSecretFlags[lower] && mcpSecretValue(next) {
			kinds = append(kinds, "参数 "+lower)
		}
		switch program {
		case "mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump":
			if strings.HasPrefix(a, "-p") && !strings.HasPrefix(a, "--") && graphemeCount(a) > 2 {
				kinds = append(kinds, "参数 -p（数据库密码）")
			}
		}
		if program == "curl" {
			creds := ""
			if a == "-u" || a == "--user" {
				creds = next
			} else if strings.HasPrefix(a, "-u") && !strings.HasPrefix(a, "--") {
				creds = a[2:]
			}
			if c := strings.Index(creds, ":"); c >= 0 && mcpSecretValue(creds[c+1:]) {
				kinds = append(kinds, "参数 -u（用户名:密码）")
			}
		}
		for _, s := range mcpSecretShapes {
			if aiContainsAny(a, s.needles) && s.re.has(a) {
				kinds = append(kinds, s.kind)
			}
		}
	}
	return aiSortedUnique(kinds)
}

// mcpAfterEquals is what follows the = that is at eq in lower, in a itself.
func mcpAfterEquals(a, lower string, eq int) string {
	if len(a) == len(lower) {
		return a[eq+1:]
	}
	if i := strings.Index(a, "="); i >= 0 {
		return a[i+1:]
	}
	return ""
}

// mcpIsSecret: whether a value written next to name is a key itself: shaped like a known token, or a key-like name
// with a literal value that looks like one -- not a reference to one kept elsewhere, not a path or a socket, not a
// plain word or a placeholder: letters and digits mixed, or long.
func mcpIsSecret(name, value string) bool {
	v := aiTrimWS(value)
	if len(mcpCommandSecretKinds([]string{v}, "")) > 0 {
		return true
	}
	// An Authorization header's scheme ("Bearer abc…") goes before the value itself.
	for _, scheme := range []string{"Bearer ", "Basic ", "Token ", "token "} {
		v = strings.TrimPrefix(v, scheme)
	}
	if graphemeCount(v) < 8 || !mcpSecretValue(v) || strings.HasPrefix(aiLower(v), "env:") || strings.HasPrefix(v, "op://") ||
		strings.Contains(v, " ") || (strings.Contains(v, "/") && !strings.Contains(v, "+")) {
		return false
	}
	letter, digit := false, false
	for _, r := range v {
		if unicode.IsLetter(r) {
			letter = true
		}
		if unicode.IsNumber(r) {
			digit = true
		}
	}
	n := aiLower(name)
	named := false
	for _, s := range mcpSecretNames {
		if strings.Contains(n, s) {
			named = true
		}
	}
	return named && ((letter && digit) || graphemeCount(v) >= 24)
}

type mcpServer struct {
	name, command string
	// fetched: started from a package fetched at launch, unpinned (npx -y pkg, uvx pkg): whatever is newest then.
	fetched bool
	secrets int
}

// mcpProgramName is URL(fileURLWithPath:).lastPathComponent of a command.
func mcpProgramName(p string) string {
	if p == "" {
		wd, _ := os.Getwd()
		return filepath.Base(wd)
	}
	return filepath.Base(p)
}

func mcpServerOf(name string, e map[string]any) mcpServer {
	command, ok := e["command"].(string)
	if !ok {
		if _, isURL := e["url"].(string); isURL {
			command = "（网址）"
		} else {
			command = "?"
		}
	}
	args, _ := aiJSStrings(e["args"])
	program := mcpProgramName(command)
	// Shown: the program, and for a package runner the package -- only when it is a plain package name.
	first := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			first = a
			break
		}
	}
	plain := !strings.Contains(first, "=") && !strings.Contains(first, "://") && !strings.Contains(first, " ") &&
		!strings.Contains(first, ":") && len(mcpCommandSecretKinds([]string{first}, "")) == 0
	runner := program == "npx" || program == "bunx" || program == "uvx" || program == "pnpx"
	pkg := ""
	if runner && plain {
		pkg = first
	}
	rest := pkg
	if strings.HasPrefix(pkg, "@") {
		rest = pkg[1:]
	}
	pinned := strings.Contains(rest, "@") || strings.Contains(pkg, "==")
	secrets := len(mcpCommandSecretKinds(args, program))
	for _, k := range []string{"env", "headers"} {
		m, _ := aiJSMap(e[k])
		for n, v := range m {
			if s, ok := v.(string); ok && mcpIsSecret(n, s) {
				secrets++
			}
		}
	}
	if url, ok := e["url"].(string); ok && (len(mcpCommandSecretKinds([]string{url}, "")) > 0 || strings.Contains(url, "key=") || strings.Contains(url, "token=")) {
		secrets++
	}
	shown := program
	if pkg != "" {
		shown += " " + pkg
	}
	return mcpServer{name: name, command: shown, fetched: runner && !pinned && pkg != "", secrets: secrets}
}

// mcpOthersCanRead: whether accounts other than the owner can read path: the file readable by its group or by anyone,
// and every folder above it up to the home passable by them.
func mcpOthersCanRead(path, home string) bool {
	st, ok := aiLstat(path)
	if !ok || st.Mode&0o044 == 0 {
		return false
	}
	dir := filepath.Clean(filepath.Dir(path))
	top := filepath.Clean(home)
	for utf8.RuneCountInString(dir) >= utf8.RuneCountInString(top) {
		var s syscall.Stat_t
		if syscall.Stat(dir, &s) != nil || s.Mode&0o011 == 0 {
			return false
		}
		if dir == top {
			break
		}
		dir = filepath.Dir(dir)
	}
	return true
}

// mcpServers: the servers a tool's file names, under key, and for Claude Code also each project's own.
func mcpServers(j map[string]any, key string) []mcpServer {
	var out []mcpServer
	add := func(m map[string]any) {
		for n, v := range m {
			if e, ok := aiJSMap(v); ok {
				out = append(out, mcpServerOf(n, e))
			}
		}
	}
	top, _ := aiJSMap(j[key])
	add(top)
	projects, _ := aiJSMap(j["projects"])
	for _, p := range projects {
		if pm, ok := aiJSMap(p); ok {
			servers, _ := aiJSMap(pm["mcpServers"])
			add(servers)
		}
	}
	sort.SliceStable(out, func(i, k int) bool {
		if out[i].name != out[k].name {
			return out[i].name < out[k].name
		}
		return out[i].command < out[k].command
	})
	return out
}

func (r *McpRule) Run(ctx *Context) ([]Finding, error) {
	if settingsErr != nil {
		return nil, rulesMissing("settings-files.json")
	}
	out := []Finding{}
	for _, c := range mcpConfigs {
		u := filepath.Join(ctx.Home, c.path)
		st, ok := aiLstat(u)
		if !ok || !aiStReg(st) || st.Size >= 64<<20 {
			continue
		}
		j, ok := aiReadJSON(u)
		if !ok {
			continue
		}
		servers := mcpServers(j, c.key)
		if len(servers) == 0 {
			continue
		}
		var fetched, shown, keyParts []string
		for i, s := range servers {
			if s.fetched {
				fetched = append(fetched, s.name)
			}
			if i < 15 {
				shown = append(shown, s.name+"（"+s.command+"）")
			}
			keyParts = append(keyParts, s.name+" "+s.command)
		}
		ev := map[string]string{"tool": c.tool, "servers": strings.Join(shown, "；"),
			"why": "每个都是一个程序，" + c.tool + " 开着时以你的身份运行，能读你能读的文件",
			"how": "只留认得、还在用的"}
		if len(fetched) > 0 {
			ev["fetched"] = strings.Join(fetched, "、")
			ev["how"] = "只留认得、还在用的；" + strings.Join(fetched, "、") + " 每次启动都从网上取最新版，写上版本号（例如 包名@1.2.3）更稳"
		}
		// Keyed on what is set up: one added later is a new finding, not hidden by a "以后别提" for these.
		out = append(out, Finding{Rule: "mcp.servers", Category: CatPersistence, Severity: Low, Verdict: Info, Path: u,
			Title: c.tool + " 设了 " + strconv.Itoa(len(servers)) + " 个 MCP 服务器，用它时会启动", Evidence: ev,
			Key: u + "|" + strings.Join(keyParts, "|")})
		var leaky, leakyKey []string
		n := 0
		for _, s := range servers {
			if s.secrets > 0 {
				leaky = append(leaky, s.name)
				leakyKey = append(leakyKey, s.name+":"+strconv.Itoa(s.secrets))
				n += s.secrets
			}
		}
		if len(leaky) == 0 {
			continue
		}
		others := mcpOthersCanRead(u, ctx.Home)
		sev, title, how := Medium, c.tool+" 的 MCP 设置里明文写着 "+strconv.Itoa(n)+" 个密钥",
			"把密钥放进环境变量或钥匙串，设置里写成引用（例如 ${env:名字}）；已经写过的密钥最好换新的"
		if others {
			sev = High
			title += "，这台 Mac 上别的账户也能读到"
			how += "；终端里运行 chmod 600 \"$HOME/" + c.path + "\""
		}
		out = append(out, Finding{Rule: "mcp.secrets", Category: CatPosture, Severity: sev, Verdict: Info, Path: u, Title: title,
			Evidence: map[string]string{"tool": c.tool, "servers": strings.Join(leaky, "、"), "count": strconv.Itoa(n),
				"why": "这个文件常被同步、备份，或贴给别人看", "how": how},
			Key: u + "|" + strings.Join(leakyKey, "|")})
	}
	return out, nil
}
