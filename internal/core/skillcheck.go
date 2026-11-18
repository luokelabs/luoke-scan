package core

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// The static checks of a skill: patterns over its instructions and scripts, a few facts that only count together (a
// key read and data sent from the same script), what could not be read, and its front matter. Precision first: what a
// skill says about a risky command (never…, a list of what to flag) does not count, and the common legitimate forms
// (an API called with curl, a pinned install, an official installer) stay low or silent. The patterns are ICU's
// (skillre.go), as written for the Swift version.

// SignalKind is what kind of risk a signal is.
type SignalKind string

const (
	SignalExfil        SignalKind = "exfil"
	SignalDownloadExec SignalKind = "download-exec"
	SignalPersistence  SignalKind = "persistence"
	SignalAgentTamper  SignalKind = "agent-tamper"
	SignalEscalation   SignalKind = "escalation"
	SignalDestructive  SignalKind = "destructive"
	SignalInjection    SignalKind = "injection"
	SignalPermission   SignalKind = "permission"
	SignalSupplyChain  SignalKind = "supply-chain"
	SignalUnreadable   SignalKind = "unreadable"
)

// SkillSignal is one thing the checks found: what kind, how serious ("" only counts together with something else),
// what (a fixed phrase, never the text that matched), where.
type SkillSignal struct {
	Kind     SignalKind
	Severity Severity
	Label    string
	// File is relative to the skill's folder; several are joined with "、".
	File  string
	Lines []int
}

type skillRole int

const (
	rolePlain skillRole = iota
	roleInjection
	roleConceal
	roleSecretStrong
	roleSecretWeak
	roleSend
	roleDrop
	roleDownload
	roleChmodX
	roleChecksum
	roleDelete
)

type patScope int

const (
	scopeAny patScope = iota
	scopeCode
	scopeProse
)

type skillPattern struct {
	kind     SignalKind
	severity Severity
	// In prose, when proseSet: proseSev instead ("" there: only counts with something else).
	proseSet    bool
	proseSev    Severity
	label       string
	role        skillRole
	scope       patScope
	needles     []string
	re          *icuRegexp
	unless      *icuRegexp
	test        func(line []rune, m []int) bool
	outsideCode bool
}

func (p skillPattern) sev(prose bool) Severity {
	if prose && p.proseSet {
		return p.proseSev
	}
	return p.severity
}

type spOpt func(*skillPattern)

func spRole(r skillRole) spOpt                { return func(p *skillPattern) { p.role = r } }
func spScope(s patScope) spOpt                { return func(p *skillPattern) { p.scope = s } }
func spUnless(u string) spOpt                 { return func(p *skillPattern) { p.unless = icuCI(u) } }
func spOutsideCode() spOpt                    { return func(p *skillPattern) { p.outsideCode = true } }
func spProse(s Severity) spOpt                { return func(p *skillPattern) { p.proseSet, p.proseSev = true, s } }
func spTest(t func([]rune, []int) bool) spOpt { return func(p *skillPattern) { p.test = t } }

func skillPat(kind SignalKind, sev Severity, label string, needles []string, re string, opts ...spOpt) skillPattern {
	p := skillPattern{kind: kind, severity: sev, label: label, needles: needles, re: icuCI(re)}
	for _, o := range opts {
		o(&p)
	}
	if p.test == nil && (p.role == roleSecretStrong || p.role == roleSecretWeak) {
		p.test = func(line []rune, _ []int) bool { return skillReadsLine(line) }
	}
	return p
}

func rxGroupText(line []rune, m []int, g int) string {
	if m[2*g] < 0 {
		return ""
	}
	return string(line[m[2*g]:m[2*g+1]])
}

type skillChecks struct {
	existence, message, readVerb, packs                              *icuRegexp
	patterns                                                         []skillPattern
	targets                                                          []skillTarget
	varRedirect, writeCall                                           *icuRegexp
	negation, topic, notWorry, patternLine, heading, listItem, fence *icuRegexp
	aiAddressed, imperative, action, readOnlyClaim                   *icuRegexp
	base64Blob, hexBlob, joined, dataURI, assign, assignStrip, forIn *icuRegexp
	forStrip, allowedShell, rmRecursive, rmForce, fromPinned         *icuRegexp
}

var (
	skillChecksOnce  sync.Once
	skillChecksBuilt *skillChecks
)

// The patterns are built once, on first use.
func skc() *skillChecks {
	skillChecksOnce.Do(func() { skillChecksBuilt = buildSkillChecks() })
	return skillChecksBuilt
}

// skillReadsLine says whether a line that names a place holding keys reads it, rather than checks that it is there or
// prints a message.
func skillReadsLine(line []rune) bool {
	c := skc()
	if c.existence.hasRunes(line) {
		return false
	}
	if c.message.hasRunes(line) && !c.readVerb.hasRunes(line) {
		return false
	}
	return true
}

// Hosts of well-known official installers: piping their script into a shell is how they are meant to be installed.
const officialInstaller = `https?://(?:astral\.sh/uv/|sh\.rustup\.rs|static\.rust-lang\.org/rustup|raw\.githubusercontent\.com/(?:Homebrew/install|nvm-sh/nvm|pyenv/pyenv-installer)/|bun\.(?:sh|com)/install|deno\.land/install|install\.python-poetry\.org|get\.pnpm\.io/install|claude\.ai/install|ollama\.com/install|get\.sdkman\.io|pyenv\.run|starship\.rs/install|tailscale\.com/install|fnm\.vercel\.app/install|install\.determinate\.systems|mise\.run|get\.volta\.sh)`

// A shell or interpreter that runs what comes in on standard input (not python -c …, which reads it as data); a
// comment may follow it (| sh # …).
const stdinRunner = `(?:sudo\s+(?:-\S+\s+)*)?(?:/\S*/)?(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|perl|ruby|node|php|osascript)(?=\s*$|\s*[;&|)'"\x{60}]|\s+-s\b|\s+-(?=$|[\s;&|)'"\x{60}])|\s+--\s|\s+#)`

// Using an SSH key, or the public half: not reading the private one.
const sshUse = `\.ssh/(?:config|known_hosts)\b|\.pub\b|\bssh-(?:keygen|add|copy-id)\b|(?:^|\s)-i\s+\S*\.ssh/|IdentityFile|GIT_SSH_COMMAND|ssh\s+-o\b`

func needleList(words ...string) []string { return words }

func buildSkillChecks() *skillChecks {
	c := &skillChecks{}
	c.existence = icuCI(`\[\s+-[efdrsL]\s|\btest\s+-[efd]\b|\bos\.path\.(?:exists|isfile|isdir)\b|\bexistsSync\b|\.exists\(\)|\bis_file\(\)`)
	c.message = icuCI(`\becho\b|\bprintf\b|\bprint\s*\(|\bconsole\.(?:log|error|warn)\b|\blog(?:ger)?\.\w+\s*\(`)
	c.readVerb = icuCI(`\bcat\b|<\s*\S|\$\(|\bopen\s*\(|\bread\w*\b|\bbase64\b|\btar\b|\bzip\b|\bcp\b|\bxxd\b|\bsecurity\b`)
	// Packing up or reading a whole folder.
	c.packs = icuCI(`\b(?:tar|zip|7z|ditto|cp|cat|base64|rsync|scp|xxd|open|read\w*|walk|glob|listdir|readdir\w*|copytree|make_archive)\b`)
	skillChecksBuilt = c // the secret patterns' tests read it while it is being built

	injection := []skillPattern{
		skillPat(SignalInjection, Medium, "让 AI 忽略原来的指令或规矩", needleList("ignor", "disregard", "forget", "override", "bypass"),
			`\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|earlier|above|preceding|system|original|existing|safety|developer)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules|guidelines|directives|messages|context|constraints|polic(?:y|ies)|guardrails)\b|\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:above|before|you(?:'ve|\s+have)\s+been\s+told)`,
			spRole(roleInjection)),
		skillPat(SignalInjection, Medium, "让 AI 忽略原来的指令或规矩", needleList("忽略", "无视", "忘掉", "忘记", "不用管", "不要管"),
			`(?:忽略|无视|忘掉|忘记|不用管|不要管)[^。\n]{0,12}(?:之前|以前|上面|前面|先前|原来|原有|所有|系统|开发者)[^。\n]{0,8}(?:指令|指示|规则|提示|要求|设定|限制)`,
			spRole(roleInjection)),
		// Chat-template markers, by shape rather than a list of names.
		skillPat(SignalInjection, Medium, "冒充系统或开发者说话",
			needleList("<|", "|>", "_of_turn", "tool_call", "tool_response", "[inst]", "[/inst]", "[system_prompt]", "[available_tools]", "[tool_",
				"<<sys>>", "<system", "</system", "<｜"),
			`<\|[a-z][a-z0-9_]{1,31}\|?>|<[a-z][a-z0-9_]{1,31}\|>|<(?:start|end)_of_turn>|</?tool_(?:call|response)>|`+
				`\[/?(?:INST|SYSTEM_PROMPT|AVAILABLE_TOOLS|TOOL_CALLS|TOOL_RESULTS)\]|<<SYS>>|<｜[^｜<>\n]{1,40}｜>|`+
				`</?system(?:[-_](?:reminder|prompt|message))?>`,
			spRole(roleInjection), spScope(scopeProse), spOutsideCode()),
		skillPat(SignalInjection, Medium, "冒充系统或开发者说话", needleList("from the", "from anthropic", "from openai", "already", "pre-approved", "preapproved", "mode", "override"),
			`\b(?:this|the\s+following|these)\s+(?:is|are)\s+(?:an?\s+)?(?:official\s+)?(?:message|instruction|notice|update|directive)s?\s+from\s+(?:the\s+)?(?:system|developers?|administrator|admin|anthropic|openai|operator)\b|\buser\s+has\s+already\s+(?:authorized|approved|consented|agreed)\b|\bpre-?approved\s+by\s+the\s+user\b|\byou\s+are\s+(?:now\s+)?in\s+(?:developer|god|admin|unrestricted|jailbreak)\s+mode\b|\b(?:system|developer|admin)\s+override\b`,
			spRole(roleInjection)),
		skillPat(SignalInjection, Medium, "冒充系统或开发者说话", needleList("系统", "开发者", "管理员", "官方", "用户"),
			`(?:这是|以下是|来自)(?:系统|开发者|管理员|官方)(?:的)?(?:指令|消息|通知|要求)|用户(?:已经|早已|已)(?:授权|同意|批准)(?:了)?(?:所有|全部|一切)`,
			spRole(roleInjection)),
		skillPat(SignalInjection, Low, "让 AI 瞒着你", needleList("tell", "inform", "notify", "alert", "mention", "secret", "covert", "stealth", "knowledge", "knowing", "noticing", "hide", "conceal", "hidden"),
			`\b(?:do\s*n[o']?t|never|without)\s+(?:telling|tell|informing|inform|notifying|notify|alerting|alert|mentioning\s+(?:this|it)\s+to|mention\s+(?:this|it)\s+to)\s+(?:the\s+)?(?:user|human|operator)\b|\b(?:secretly|covertly|stealthily)\b|\bwithout\s+(?:the\s+)?user'?s?\s+(?:knowledge|knowing|noticing|awareness)\b|\b(?:hide|conceal)\s+(?:this|these|it|them|the\s+\w+)\s+(?:\w+\s+)?from\s+(?:the\s+)?user\b|\bkeep\s+(?:this|it)\s+(?:hidden|secret)\s+from\s+(?:the\s+)?user\b`,
			spRole(roleConceal), spUnless(`\b(?:never|do\s*n[o']?t|must\s+not)\b[^.\n]{0,60}\bwithout\b`)),
		// \x{4E3B}\x{4EBA} is the Chinese for "owner", written as escapes: the word is on the leak scan's list.
		skillPat(SignalInjection, Low, "让 AI 瞒着你", needleList("告诉", "通知", "提醒", "告知", "让用户", "悄悄", "偷偷", "暗中", "秘密", "私下", "瞒着", "背着", "隐瞒", "保密"),
			`(?:不要|别|不用|无需|切勿|不必)(?:告诉|通知|提醒|告知|让)(?:用户|使用者|\x{4E3B}\x{4EBA})|(?:悄悄|偷偷|暗中|秘密|私下)(?:地)?(?:上传|发送|发到|执行|运行|安装|删除|复制|读取|下载|修改)|(?:瞒着|背着)(?:用户|使用者)|(?:对|向)(?:用户|使用者)(?:隐瞒|保密)`,
			spRole(roleConceal)),
	}

	secrets := []skillPattern{
		skillPat(SignalExfil, "", "SSH 私钥", needleList("ssh", "id_"),
			`\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\.ssh/(?:id_\w+|\w*_key|identity)\b(?!\.pub)`, spRole(roleSecretStrong), spUnless(sshUse)),
		skillPat(SignalExfil, "", "SSH 私钥", needleList("ssh"), `\.ssh(?:/\*?)?(?=$|[\s'")])`, spRole(roleSecretStrong), spUnless(sshUse),
			spTest(func(line []rune, _ []int) bool { return skc().packs.hasRunes(line) })),
		skillPat(SignalExfil, "", "SSH 私钥", needleList("ssh"), `\.ssh(?:/|['"]|\b(?![\w.-]))`, spRole(roleSecretWeak), spUnless(sshUse)),
		skillPat(SignalExfil, "", "AWS 的凭证", needleList("aws"), `\.aws/credentials\b|\.aws['"]?\s*[,)]`, spRole(roleSecretStrong)),
		skillPat(SignalExfil, "", "AWS 的设置", needleList("aws"), `\.aws/config\b`, spRole(roleSecretWeak)),
		skillPat(SignalExfil, "", "GitHub CLI 的令牌", needleList("gh"), `\.config/gh/hosts\.yml|\.config/gh['"]?\s*[,)]`, spRole(roleSecretStrong)),
		skillPat(SignalExfil, "", "netrc 或 git 保存的密码", needleList("netrc", "git-credentials"), `\.netrc\b|\.git-credentials\b`, spRole(roleSecretStrong)),
		skillPat(SignalExfil, "", "云和容器的登录凭证", needleList("gcloud", "kube", "docker", "azure", "application_default"),
			`\.config/gcloud\b|application_default_credentials\.json|\.kube/config\b|\.docker/config\.json|\.azure/(?:accessTokens|msal_token_cache|azureProfile)`,
			spRole(roleSecretStrong)),
		skillPat(SignalExfil, Medium, "AI 工具的登录凭证", needleList("credentials", "auth.json", "copilot", "oauth_creds"),
			`\.claude/\.credentials\.json|\.codex/auth\.json|\.config/github-copilot/(?:hosts|apps)\.json|\.gemini/oauth_creds\.json`,
			spRole(roleSecretStrong)),
		skillPat(SignalExfil, Medium, "钥匙串里的密码", needleList("security", "safe storage"),
			`\bsecurity\s+(?:dump-keychain|find-internet-password|export)\b|\bSafe\s+Storage\b`, spRole(roleSecretStrong)),
		skillPat(SignalExfil, "", "钥匙串里的一项密码", needleList("find-generic-password"), `\bsecurity\s+find-generic-password\b`, spRole(roleSecretWeak)),
		skillPat(SignalExfil, Medium, "浏览器保存的密码或 Cookie", needleList("login data", "web data", "logins.json", "key4.db", "cookies", "local state"),
			`\bLogin\s+Data\b|\bWeb\s+Data\b|logins\.json|key4\.db|cookies\.sqlite|Cookies\.binarycookies|(?:Chrome|Chromium|Brave|Edge|Firefox|Safari|Arc|Vivaldi|Opera)\S*[^\n]{0,80}\b(?:Cookies|Local\s+State)\b`,
			spRole(roleSecretStrong)),
		skillPat(SignalExfil, Medium, "加密货币钱包", needleList("wallet", "electrum", "exodus", "mnemonic", "seed phrase", "keystore", "助记词", "nkbihfbeogaeaoehlefnkodbefgpgknn", "ledger live"),
			`wallet\.dat|\.electrum\b|exodus\.wallet|Application Support/(?:Exodus|Electrum|atomic|Ledger Live|Bitcoin|Ethereum)\b|keystore/UTC--|\bseed\s+phrases?\b|\bmnemonic\s+(?:phrase|words?|seed)\b|助记词|nkbihfbeogaeaoehlefnkodbefgpgknn`,
			spRole(roleSecretStrong)),
		skillPat(SignalExfil, Medium, "信息、邮件、通讯录这类私人数据", needleList("chat.db", "library/mail", "addressbook", "callhistory"),
			`Library/Messages/chat\.db|Library/Mail/V\d|AddressBook-v22\.abcddb|CallHistoryDB`, spRole(roleSecretStrong)),
		skillPat(SignalExfil, "", "全部环境变量（里面常有密钥）", needleList("environ", "process.env", "printenv", "env"),
			`json\.dumps\(\s*(?:dict\(\s*)?os\.environ|\bstr\(\s*os\.environ\s*\)|JSON\.stringify\(\s*process\.env\s*\)|(?:^|[\s;&(])(?:printenv|env)\s*>`,
			spRole(roleSecretStrong)),
		skillPat(SignalExfil, "", ".env 文件", needleList(".env"), `(?:^|[\s'"/=(\x{60}])\.env(?:\.[a-z]+)?(?![\w-])`, spRole(roleSecretWeak),
			spUnless(`\.env\.(?:example|sample|template|dist)\b`)),
		skillPat(SignalExfil, "", "npm 或 PyPI 的令牌文件", needleList("npmrc", "pypirc"), `\.npmrc\b|\.pypirc\b`, spRole(roleSecretWeak)),
	}

	sending := []skillPattern{
		skillPat(SignalExfil, "", "往外发数据", needleList("curl"),
			`\bcurl\b[^\n|;]*?\s(?:-d|--data(?:-binary|-raw|-urlencode|-ascii)?|-F|--form(?:-string)?|-T|--upload-file|--json|-X\s*(?:POST|PUT|PATCH))(?=[\s='"@]|$)`,
			spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("wget"), `\bwget\b[^\n]*--(?:post-data|post-file|body-data|body-file|method[= ]?(?:POST|PUT))`, spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("nc ", "ncat", "netcat"),
			`(?:\||<)\s*(?:nc|ncat|netcat)\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\b|\b(?:nc|ncat|netcat)\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\s*<`, spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("/dev/"), `/dev/(?:tcp|udp)/`, spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("post", "put", "patch", "urlopen", "request"),
			`\b(?:requests|httpx|session|client|aiohttp)\.(?:post|put|patch)\s*\(|\burlopen\s*\([^\n]*\bdata\s*=|urllib\.request\.Request\s*\([^\n]*\bdata\s*=|\.request\s*\(\s*['"](?:POST|PUT)['"]`,
			spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("post", "put", "patch", "axios", "request", "sendbeacon"),
			`\bmethod\s*:\s*['"](?:POST|PUT|PATCH)['"]|\baxios\.(?:post|put|patch)\s*\(|\bhttps?\.request\s*\(|\bgot\.(?:post|put)\s*\(|\bsendBeacon\s*\(`,
			spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("scp", "rsync", "sftp", "ftp"), `\b(?:scp|rsync)\b[^\n]*\s[\w.-]+@[\w.-]+:|\b(?:sftp|ftp)\s+[\w.-]+@`, spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("smtp", "sendmail", "mail -s"), `smtplib\.SMTP|\bsendmail\b|\bmail\s+-s\b`, spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("gist"), `\bgh\s+gist\s+create\b|api\.github\.com/gists`, spRole(roleSend)),
		skillPat(SignalExfil, "", "往外发数据", needleList("socket", "connect"), `\bsocket\.socket\s*\(|\bsocket\.create_connection\s*\(|\bnet\.(?:connect|createConnection)\s*\(`, spRole(roleSend)),
		skillPat(SignalExfil, Medium, "把数据发到专门收集数据的网站", needleList("webhook.site", "requestbin", "requestcatcher", "pipedream", "beeceptor", "hookbin", "mockbin", "postb.in", "ptsv", "webhook.cool", "requestrepo", "burpcollaborator", "oastify", "interact.sh", "oast.", "dnslog", "ceye.io", "canarytokens"),
			`(?:^|[^\w-])(?:[\w-]+\.)*(?:webhook\.site|requestbin\.(?:net|com)|requestcatcher\.com|pipedream\.net|beeceptor\.com|hookbin\.com|mockbin\.org|postb\.in|ptsv[23]\.com|webhook\.cool|requestrepo\.com|burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|dnslog\.cn|ceye\.io|canarytokens\.(?:com|org))\b`,
			spRole(roleDrop)),
		skillPat(SignalExfil, Medium, "连到临时隧道（外面能连进来、数据能发出去）", needleList("ngrok", "trycloudflare", "loca.lt", "localtunnel", "serveo", "localhost.run", "pagekite", "bore.pub"),
			`(?:[\w-]+\.)*(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|localhost\.run|pagekite\.me|bore\.pub)\b`,
			spRole(roleDrop)),
		skillPat(SignalExfil, Medium, "把东西传到公开的贴文本、传文件网站", needleList("pastebin", "paste.ee", "hastebin", "ghostbin", "rentry", "dpaste", "termbin", "ix.io", "0x0.st", "transfer.sh", "file.io", "bashupload", "tmpfiles", "catbox", "filebin", "gofile", "temp.sh", "oshi.at"),
			`(?:^|[^\w-])(?:[\w-]+\.)*(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|rentry\.(?:co|org)|dpaste\.(?:com|org)|termbin\.com|ix\.io|0x0\.st|transfer\.sh|file\.io|bashupload\.com|tmpfiles\.org|catbox\.moe|filebin\.net|gofile\.io|temp\.sh|oshi\.at)\b`,
			spRole(roleDrop)),
		skillPat(SignalExfil, Low, "发消息给聊天机器人", needleList("discord", "telegram", "hooks.slack", "webhook.office", "outlook.office", "dingtalk", "qyapi.weixin", "feishu", "larksuite"),
			`discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/(?:services|workflows|triggers)|webhook\.office\.com|outlook\.office\.com/webhook|oapi\.dingtalk\.com/robot|qyapi\.weixin\.qq\.com/cgi-bin/webhook|open\.(?:feishu\.cn|larksuite\.com)/open-apis/bot`,
			spRole(roleDrop)),
		skillPat(SignalExfil, Low, "连到直接写 IP 地址的服务器", needleList("://", "/dev/"),
			`(?:https?|ftp|wss?|tcp|udp)://(\d{1,3}(?:\.\d{1,3}){3})\b|/dev/(?:tcp|udp)/(\d{1,3}(?:\.\d{1,3}){3})`, spRole(roleDrop),
			spTest(func(line []rune, m []int) bool {
				g := 1
				if m[2] < 0 {
					g = 2
				}
				return m[2*g] >= 0 && skillPublicIP(rxGroupText(line, m, g))
			})),
		skillPat(SignalExfil, High, "把全部环境变量直接发出去（里面常有密钥）", needleList("env", "printenv"),
			`(?:^|[\s;&(])(?:printenv|env|set)\s*\|\s*(?:\S+\s*\|\s*)?(?:curl|wget|nc|ncat|netcat)\b`),
	}

	downloadExec := []skillPattern{
		skillPat(SignalDownloadExec, High, "从网上下载代码直接运行", needleList("curl", "wget"),
			`\b(?:curl|wget)\b[^\n|]*(?:\|[^|\n]*){0,2}\|\s*`+stdinRunner, spUnless(officialInstaller)),
		skillPat(SignalDownloadExec, High, "从网上下载代码直接运行", needleList("curl", "wget"),
			`(?:^|[\s;&|(\x{60}])(?:/\S*/)?(?:sh|bash|zsh|source|\.)\s+<\(\s*(?:curl|wget)\b|(?:^|[\s;&|(\x{60}])(?:/\S*/)?(?:sh|bash|zsh|python[0-9.]*)\s+-c\s+["']?\$\(\s*(?:curl|wget)\b|\beval\s+["']?(?:\$\(|\x{60})\s*(?:curl|wget)\b|\bosascript\s+-e\s+["']?\$\(\s*(?:curl|wget)\b`,
			spUnless(officialInstaller)),
		skillPat(SignalSupplyChain, Low, "运行官方网站上的安装脚本", needleList("curl", "wget"),
			`\b(?:curl|wget)\b[^\n]*`+officialInstaller+`[^\n]*(?:\|\s*`+stdinRunner+`|\))`),
		skillPat(SignalDownloadExec, High, "把编码过的内容解开直接运行", needleList("base64", "openssl", "xxd"),
			`\b(?:base64\s+(?:-d|-D|--decode)|openssl\s+(?:base64|enc)\b[^|\n]*\s-d\b|xxd\s+-r)[^|\n]*\|\s*`+stdinRunner),
		skillPat(SignalDownloadExec, High, "把编码过的内容解开直接运行", needleList("exec", "eval"),
			`\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.|codecs\.|zlib\.|marshal\.|bytes\.)?(?:b64decode|b32decode|b85decode|a85decode|decodebytes|fromhex|decode|decompress|loads)\s*\(|\b(?:exec|eval)\s*\(\s*__import__\s*\(\s*['"](?:base64|zlib|marshal|codecs)`),
		skillPat(SignalDownloadExec, High, "从网上下载代码直接运行", needleList("exec", "eval"),
			`\b(?:exec|eval)\s*\([^\n]*\b(?:urlopen|requests\.get|httpx\.get|urllib\.request|fetch)\s*\(`),
		skillPat(SignalDownloadExec, High, "把编码过的内容解开直接运行", needleList("eval", "function"),
			`\beval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)\s*\(|\bnew\s+Function\s*\(\s*(?:atob|Buffer\.from)\s*\(`),
		skillPat(SignalDownloadExec, "", "下载程序", needleList("curl", "wget", "urlretrieve"),
			`\bcurl\b[^\n|]*\s(?:-o|-O|--output|--remote-name)(?:\s|=|$)|\bwget\b(?![^\n]*(?:-O\s*-|-qO\s*-|-qO-|--output-document=-))[^\n]*https?://|\burlretrieve\s*\(`,
			spRole(roleDownload)),
		skillPat(SignalDownloadExec, "", "加上执行权限", needleList("chmod", "s_ix"),
			`\bchmod\s+(?:-R\s+)?(?:[ugoa]*\+[rw]*x\w*|[0-7]?[0-7][0-7][1357]|[0-7]?[0-7][1357][0-7]|[0-7]?[1357][0-7][0-7])\b|\bos\.chmod\s*\([^\n]*(?:0o?7[0-7]{2}|0o?5[0-7]{2}|S_IX)`,
			spRole(roleChmodX)),
		skillPat(SignalDownloadExec, "", "核对下载的校验和或签名", needleList("sha256", "shasum", "sha512", "gpg", "codesign", "checksum", "hashlib", "minisign", "cosign"),
			`\bshasum\b[^\n]*-c\b|\bsha(?:256|512)sum\b[^\n]*-c\b|--check\b|\bgpg\s+--verify\b|\bcodesign\s+(?:-v|--verify)\b|\bhashlib\.sha(?:256|512)\b|\bminisign\s+-V\b|\bcosign\s+verify|checksum`,
			spRole(roleChecksum)),
	}

	escalation := []skillPattern{
		// On its own a weak sign; a Linux package manager's line does not even run on a Mac.
		skillPat(SignalEscalation, Low, "要管理员权限（sudo）", needleList("sudo"), `(?:^|[\s;&|(\x{60}]|\$\()sudo\s+(?!-[kKlv]\b)(?:-[A-Za-z]+\s+)*[\w/.$"'-]`,
			spUnless(`\bsudo\s+(?:access|privileges?|rights|permissions?|password|mode|user|is|are|will|may|can|to|and|or|for|if|when|in|on|as|the|a|an)\b|\bsudo\s+(?:-\S+\s+)*(?:apt|apt-get|yum|dnf|pacman|zypper|apk|snap)\b`)),
		skillPat(SignalEscalation, High, "把密码直接交给 sudo", needleList("sudo", "askpass"), `\|\s*sudo\s+(?:-\w+\s+)*-S\b|\bsudo\s+-S\b|SUDO_ASKPASS|\bsudo\s+-A\b`),
		skillPat(SignalEscalation, High, "以管理员身份运行 AppleScript", needleList("administrator privileges"), `with\s+administrator\s+privileges`),
		skillPat(SignalEscalation, High, "改 macOS 的隐私权限数据库", needleList("tcc"), `TCC\.db\b[^\n]*\b(?:INSERT|UPDATE|DELETE|REPLACE)\b|\b(?:INSERT|UPDATE|DELETE|REPLACE)\b[^\n]*TCC\.db\b`),
		skillPat(SignalEscalation, Medium, "碰 macOS 的隐私权限（TCC）", needleList("tcc"), `\bTCC\.db\b|com\.apple\.TCC/|\btccutil\s+reset\b`,
			spUnless(`\b(?:INSERT|UPDATE|DELETE|REPLACE)\b`)),
		skillPat(SignalEscalation, High, "去掉下载来的文件的隔离标记（绕过 Gatekeeper 的检查）", needleList("xattr"),
			`\bxattr\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[dc][a-zA-Z]*\b`),
		skillPat(SignalEscalation, High, "关掉 Gatekeeper", needleList("spctl"), `\bspctl\s+(?:--master-disable|--global-disable|--disable|--add\b|--remove\b)`),
		skillPat(SignalEscalation, High, "关掉系统完整性保护（SIP）", needleList("csrutil"), `\bcsrutil\s+(?:disable|clear|authenticated-root\s+disable)`),
		skillPat(SignalEscalation, High, "关掉下载文件的隔离（LSQuarantine）", needleList("lsquarantine"), `\bLSQuarantine\b`),
		skillPat(SignalEscalation, High, "关掉防火墙", needleList("socketfilterfw", "pfctl"), `socketfilterfw\s+--setglobalstate\s+off|\bpfctl\s+-d\b`),
		skillPat(SignalEscalation, High, "改 sudo 的设置（不用密码就能当管理员）", needleList("sudoers", "nopasswd", "visudo"), `/etc/sudoers|\bNOPASSWD\b|\bvisudo\b`),
		skillPat(SignalEscalation, High, "把账户加进管理员组", needleList("dseditgroup", "dscl"), `\bdseditgroup\b[^\n]*\badmin\b|\bdscl\b[^\n]*-append\s+/Groups/admin\b`),
		skillPat(SignalEscalation, High, "改启动参数或允许未签名的系统扩展", needleList("nvram", "systemextensionsctl", "kextload"), `\bnvram\s+boot-args|\bsystemextensionsctl\s+developer\s+on|\bkextload\b`),
	}

	persistence := []skillPattern{
		skillPat(SignalPersistence, High, "把程序登记成开机自己运行（launchctl）", needleList("launchctl"), `\blaunchctl\s+(?:load|bootstrap|submit|enable)\b`),
		skillPat(SignalPersistence, Medium, "重启或改动后台服务（launchctl）", needleList("launchctl"), `\blaunchctl\s+(?:kickstart|setenv)\b`),
		skillPat(SignalPersistence, High, "改定时任务（crontab）", needleList("crontab"), `\bcrontab\s+(?:-[er]\b|-\s*$|-\s*[;&)|]|[~/$][^\s;&|)]*)|\|\s*crontab\s+-?\s*(?:$|[;&)|])`),
		skillPat(SignalPersistence, High, "加登录项（登录时自己打开）", needleList("login item"), `\bmake\s+(?:new\s+)?login\s+item\b`),
		skillPat(SignalPersistence, Medium, "注册登录项或后台程序", needleList("smappservice", "lssharedfilelist", "smloginitemsetenabled", "sfltool"),
			`\bSMAppService\b|\bLSSharedFileListInsertItem|\bSMLoginItemSetEnabled\b|\bsfltool\s+add`),
	}

	agent := []skillPattern{
		skillPat(SignalAgentTamper, Medium, "让 AI 工具跳过确认直接做", needleList("dangerously", "bypasspermissions", "--yolo", "approval", "approval-mode"),
			`--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|\bbypassPermissions\b|--yolo\b|approval[_-]policy\s*=\s*["']?never|--approval-mode[= ]yolo`),
	}

	destructive := []skillPattern{
		skillPat(SignalDestructive, High, "删掉整个家目录、整个磁盘或系统文件夹", needleList("rm "),
			`\brm\s+((?:-{1,2}[a-zA-Z-]+\s+)+)["']?(?:/|/\*|~|~/|~/\*|\$HOME/?\*?|\$\{HOME\}/?\*?|/Users(?:/\*)?|/System|/Library|/Applications|/private|(?:~|\$HOME|\$\{HOME\})/(?:Documents|Desktop|Downloads|Library|Pictures|Movies|Music)/?)["']?(?=\s|$|[;&|)])`,
			spTest(func(line []rune, m []int) bool {
				flags := rxGroupText(line, m, 1)
				recursive := strings.Contains(flags, "--recursive") || skc().rmRecursive.has(flags)
				force := strings.Contains(flags, "--force") || skc().rmForce.has(flags)
				return recursive && force
			})),
		skillPat(SignalDestructive, High, "删掉整个家目录、整个磁盘或系统文件夹", needleList("no-preserve-root"), `--no-preserve-root`),
		skillPat(SignalDestructive, High, "在整个家目录或整个磁盘上批量删文件", needleList("find"),
			`\bfind\s+["']?(?:/|~|~/|\$HOME/?|\$\{HOME\}/?|/Users/?)["']?\s[^\n]*(?:-delete\b|-exec\s+rm\b)`,
			spUnless(`-i?name\s+["']?(?:\.DS_Store|\._\*|\*\.pyc|__pycache__|\*\.tmp|\*~|\.localized)`)),
		skillPat(SignalDestructive, High, "抹掉磁盘", needleList("diskutil", "mkfs", "newfs", "dd "),
			`\bdiskutil\s+(?:erase\w*|zeroDisk|secureErase|reformat|partitionDisk|apfs\s+(?:deleteContainer|eraseVolume|deleteVolume))\b|\bdd\s+[^\n]*\bof=/dev/r?disk|\bmkfs\b|\bnewfs_\w+`),
		skillPat(SignalDestructive, High, "删掉整个家目录、整个磁盘或系统文件夹", needleList("rmtree", "rmsync", "rm("),
			`\bshutil\.rmtree\s*\(\s*(?:os\.path\.expanduser\(\s*['"]~/?['"]\s*\)|Path\.home\(\)|['"](?:/|~|~/)['"]|os\.environ\[\s*['"]HOME['"]\s*\]|os\.getenv\(\s*['"]HOME['"]\s*\))\s*[,)]|\bfs\.(?:rmSync|rm|rmdirSync)\s*\(\s*(?:os\.homedir\(\)|['"]/['"]|process\.env\.HOME)\s*[,)]`),
		skillPat(SignalPermission, "", "删文件", needleList("rm ", "remove", "unlink", "rmtree", "rmsync", "remove-item"),
			`\brm\s+-|\bos\.(?:remove|unlink)\s*\(|\bshutil\.rmtree\s*\(|\bfs\.(?:rm|unlink|rmdir)(?:Sync)?\s*\(|\bunlink\s*\(|\bRemove-Item\b`,
			spRole(roleDelete), spScope(scopeCode)),
	}

	supply := []skillPattern{
		skillPat(SignalSupplyChain, Low, "装包时没写版本号（每次装到的是当时最新的）", needleList("pip", "uv pip"),
			`\b(?:pip3?|python3?\s+-m\s+pip|uv\s+pip)\s+install\s+([^\n;&|#]+)`, spProse(""),
			spTest(func(line []rune, m []int) bool { return skillUnpinned(rxGroupText(line, m, 1), false) })),
		skillPat(SignalSupplyChain, Low, "装包时没写版本号（每次装到的是当时最新的）", needleList("npm", "yarn", "pnpm", "bun"),
			`\b(?:npm\s+(?:i|install|add)|yarn\s+(?:global\s+)?add|pnpm\s+(?:add|i|install)|bun\s+(?:add|install|i))\s+([^\n;&|#]+)`, spProse(""),
			spTest(func(line []rune, m []int) bool { return skillUnpinned(rxGroupText(line, m, 1), true) })),
		skillPat(SignalSupplyChain, Low, "运行时从网上取包，没写版本号", needleList("npx", "bunx", "dlx", "uvx", "pipx"),
			`\b(?:npx\s+(?:-y|--yes)|bunx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run)\s+((?:--?[\w-]+(?:[= ]\S+)?\s+)*)(@?[\w.-]+(?:/[\w.-]+)?(?:@\S+|==\S+)?)`,
			spProse(""),
			spTest(func(line []rune, m []int) bool {
				all := rxGroupText(line, m, 0)
				pkg := []rune(rxGroupText(line, m, 2))
				afterFirst := ""
				if len(pkg) > 0 {
					afterFirst = string(pkg[1:])
				}
				return !(strings.Contains(all, "==") || strings.Contains(afterFirst, "@") || skc().fromPinned.has(all))
			})),
		skillPat(SignalSupplyChain, Low, "装包时没写版本号（每次装到的是当时最新的）", needleList("go install", "cargo install", "gem install"),
			`\bgo\s+install\s+\S+@latest\b|\bcargo\s+install\s+(?![^\n]*--(?:version|vers|tag|rev|locked)\b)[\w-]+|\bgem\s+install\s+(?![^\n]*(?:\s-v\b|--version\b))[\w-]+`,
			spProse("")),
		skillPat(SignalSupplyChain, Medium, "直接从 git 仓库或网址装包", needleList("pip", "npm", "yarn", "pnpm", "bun"),
			`\b(?:pip3?|python3?\s+-m\s+pip|uv\s+pip|pipx)\s+install\b[^\n]*\s["']?(?:git\+|https?://)|\b(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+add|bun\s+add)\b[^\n]*\s["']?(?:git\+|github:|gitlab:|https?://|git@|[\w-]+/[\w.-]+(?:#\S*)?(?=\s|$|["']))`),
		skillPat(SignalSupplyChain, Medium, "从不加密或不核对的源装包", needleList("trusted-host", "index-url", "registry"),
			`--trusted-host\b|--(?:extra-)?index-url[= ]["']?http://|--registry[= ]["']?http://|\bnpm\s+config\s+set\s+registry\s+http://`),
		skillPat(SignalSupplyChain, Low, "从额外的源装包（可能被同名的包冒充）", needleList("extra-index-url"), `--extra-index-url\b`),
		skillPat(SignalSupplyChain, Low, "下载程序或安装包", needleList("curl", "wget", "releases/download"),
			`\b(?:curl|wget)\b[^\n]*https?://\S*(?:releases/download/|\.(?:zip|tar\.gz|tgz|tar\.xz|dmg|pkg|bin|exe|AppImage|deb|rpm)\b)`),
	}

	for _, group := range [][]skillPattern{injection, secrets, sending, downloadExec, escalation, persistence, agent, destructive, supply} {
		c.patterns = append(c.patterns, group...)
	}
	c.targets = buildSkillTargets()

	// A shell redirect into a variable's path (>> "$RC").
	c.varRedirect = icuCI(`(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?\$\{?[A-Za-z_]`)
	// A call that writes a file, in code.
	c.writeCall = icuCI(`\bopen\s*\([^\n]*,\s*(?:mode\s*=\s*)?['"][wax]|\.write_text\s*\(|\.write_bytes\s*\(|\bwriteFile(?:Sync)?\s*\(|\bappendFile(?:Sync)?\s*\(|\bcreateWriteStream\s*\(|\boutputFile(?:Sync)?\s*\(|\bjson\.dump\s*\(|\bplistlib\.dump\s*\(|\bshutil\.(?:copy\w*|move)\s*\(|\bos\.(?:symlink|rename|replace)\s*\(|\bfs\.(?:copyFile|rename|symlink|writeFile|appendFile)\w*\s*\(|\.open\s*\(\s*['"][wa]`)

	// Words that put what follows in the negative.
	c.negation = icuCI(`\b(?:never|do\s*n[o']?t|does\s*n[o']?t|must\s*n[o']?t|should\s*n[o']?t|avoid|refuse|instead\s+of|rather\s+than|not\s+(?:run|use|execute))\b|不要|别再|禁止|切勿|不得|避免|不能|不可以|而不是`)
	// Words of a line or section about risks.
	c.topic = icuCI(`\b(?:malicious|malware|attack(?:er|s)?|exploit\w*|phishing|inject(?:ion|ed)?|detect\w*|flag(?:s|ged|ging)?|block-?lists?|deny-?lists?|forbidden|prohibited|dangerous|unsafe|risky|suspicious|red\s+flags?|anti-?patterns?|black-?lists?|vulnerab\w*|threats?)\b|恶意|攻击|注入|检测|拦截|可疑|危险|不安全|漏洞|威胁`)
	c.notWorry = icuCI(`\bdo\s*n[o']?t\s+worry\b|\bno\s+need\s+to\s+worry\b|不用担心|别担心`)
	// A line of a script that defines patterns rather than runs commands.
	c.patternLine = icuCI(`\\[sbdwSWDB.|()\[\]]|\bre\.compile\b|\bRegExp\b|\bregex\b|\bpattern`)
	c.heading = icuCI(`^\s{0,3}#{1,6}\s`)
	c.listItem = icuCI(`^\s*(?:[-*+]|\d+[.)])\s`)
	c.fence = icuCI(`^\s{0,3}(?:\x{60}\x{60}\x{60}|~~~)`)
	// Text in an HTML comment addressed to an AI.
	c.aiAddressed = icuCI(`\b(?:assistant|claude|the\s+agent|the\s+model|ai\s+agent|llm|chatgpt|gemini|copilot|codex|AI)\b|助手|模型|智能体`)
	c.imperative = icuCI(`\b(?:must|should|always|never|need\s+to|have\s+to|required|make\s+sure|ignore|execute|run|send|upload|read|do\s+not|don't)\b|必须|一定|务必|执行|运行|发送|读取|不要`)
	c.action = icuCI(`\b(?:run|execute|install|send|upload|download|delete|remove|read|copy|modify|write|access|post|transfer)\w*\b|运行|执行|安装|发送|上传|下载|删除|读取|复制|修改`)
	// A description that says the skill changes nothing.
	c.readOnlyClaim = icuCI(`\bread[- ]?only\b|\b(?:does|will)\s*(?:not|n't)\s+(?:modify|change|write|delete|touch|alter)\b|\bnever\s+(?:modifies|changes|writes|deletes|alters)\b|\bno\s+side[- ]effects\b|\bwithout\s+(?:modifying|changing|writing)\b|只读|不会(?:修改|改动|删除|写入)|不改动|不修改`)
	c.base64Blob = icuCS(`[A-Za-z0-9+/_-]{120,}={0,2}`)
	c.hexBlob = icuCS(`\b[0-9a-fA-F]{160,}\b`)
	// Path pieces a program glues together (".claude" / "settings.json") as one path.
	c.joined = icuCS(`["']\s*(?:/|,|\+)\s*["']/?`)
	c.dataURI = icuCS(`data:[\w/+.-]+;base64,\s*$`)
	c.assign = icuCS(`^\s*(?:const\s+|let\s+|var\s+)?[A-Za-z_]\w*\s*[:=]`)
	c.assignStrip = icuCS(`^\s*(?:const\s+|let\s+|var\s+)?|\s*[:=]$`)
	c.forIn = icuCS(`^\s*for\s+[A-Za-z_]\w*\s+in\b`)
	c.forStrip = icuCS(`^\s*for\s+|\s+in$`)
	c.allowedShell = icuCI(`^(?:Bash|Shell)\(\s*\*?\s*(?::\s*\*)?\s*\)$`)
	c.rmRecursive = icuCS(`(?:^|\s)-[a-zA-Z]*[rR]`)
	c.rmForce = icuCS(`(?:^|\s)-[a-zA-Z]*f`)
	c.fromPinned = icuCS(`--from\s+\S+@`)
	return c
}

// skillUnpinned says whether a package install's arguments name a package without a pinned version (paths, requirement
// files and flags are not packages; pkg==1.2.3, pkg~=1.2, pkg@1.2.3 are pinned). node: npm's style, else Python's.
func skillUnpinned(args string, node bool) bool {
	var tokens []string
	for _, t := range strings.FieldsFunc(args, func(r rune) bool { return r == ' ' || r == '\t' }) {
		tokens = append(tokens, strings.Trim(t, `"'`))
	}
	takesValue := aiSet("-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
		"-t", "--target", "--prefix", "-f", "--find-links", "--root", "--python", "--registry", "--cwd", "--filter")
	var specs []string
	for len(tokens) > 0 {
		t := tokens[0]
		tokens = tokens[1:]
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "-") {
			if takesValue[t] && len(tokens) > 0 {
				tokens = tokens[1:]
			}
			continue
		}
		specs = append(specs, t)
	}
	for _, s := range specs {
		if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, "$") ||
			strings.HasPrefix(s, "{") || strings.HasPrefix(s, "<") || strings.Contains(s, "://") || strings.HasPrefix(s, "git+") ||
			strings.HasPrefix(s, "github:") || strings.HasSuffix(s, ".whl") || strings.HasSuffix(s, ".tgz") ||
			strings.HasSuffix(s, ".tar.gz") || strings.HasSuffix(s, ".txt") || strings.HasSuffix(s, ".toml") {
			continue
		}
		f := aiFirstRune(s)
		if !(unicode.IsLetter(f) || unicode.IsNumber(f) || f == '@') {
			continue
		}
		if !node {
			switch strings.ToLower(s) {
			case "pip", "setuptools", "wheel", "uv":
				continue // the installer itself
			}
			if !(strings.Contains(s, "==") || strings.Contains(s, "~=") || strings.Contains(s, " @ ")) {
				return true
			}
			continue
		}
		if strings.Contains(s, "/") && !strings.HasPrefix(s, "@") {
			continue // a GitHub shorthand: the URL-install pattern's
		}
		_, size := utf8.DecodeRuneInString(s)
		if !strings.Contains(s[size:], "@") {
			return true
		}
	}
	return false
}

// skillPublicIP says whether an IPv4 address is on the internet (not this Mac, a private network, or a range kept for
// documentation).
func skillPublicIP(s string) bool {
	var p []int
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		p = append(p, v)
	}
	if len(p) != 4 {
		return false
	}
	for _, v := range p {
		if v > 255 {
			return false
		}
	}
	a, b, c := p[0], p[1], p[2]
	switch {
	case a == 0, a == 10, a == 127, a == 169 && b == 254, a == 192 && b == 168, a == 192 && b == 0 && c == 2,
		a == 198 && b == 51 && c == 100, a == 203 && b == 0 && c == 113:
		return false
	case a == 172 && b >= 16 && b <= 31, a == 100 && b >= 64 && b <= 127, a == 198 && b >= 18 && b <= 19:
		return false
	}
	return a < 224
}

// ---------------------------------------------------------------- writing to places that matter

// skillTarget is a place where writing makes something start by itself or changes the agent.
type skillTarget struct {
	kind     SignalKind
	severity Severity
	label    string
	needles  []string
	path     *icuRegexp
	redirect *icuRegexp
	copy     *icuRegexp
	said     *icuRegexp
	// saidSeverity: said in words only, one step lower than a command doing it; "" words do not count.
	saidSeverity Severity
	// notOwn: writes naming the skill's own folder or name are the skill installing itself.
	notOwn    bool
	purpose   *icuRegexp
	mild      *icuRegexp
	mildLabel string
}

type tgOpt func(*skillTarget)

func tgSaid(s Severity) tgOpt  { return func(t *skillTarget) { t.saidSeverity = s } }
func tgNotOwn() tgOpt          { return func(t *skillTarget) { t.notOwn = true } }
func tgPurpose(p string) tgOpt { return func(t *skillTarget) { t.purpose = icuCI(p) } }
func tgMild(p, label string) tgOpt {
	return func(t *skillTarget) { t.mild, t.mildLabel = icuCI(p), label }
}

func skillTargetOf(kind SignalKind, sev Severity, label string, needles []string, p string, opts ...tgOpt) skillTarget {
	dest := `["']?[^\s"'|;&<>]*(?:` + p + `)`
	// Within a sentence: a full stop ends it, a dot inside a path does not.
	gap := func(n int) string { return `(?:[^.\n]|\.(?=\S)){0,` + strconv.Itoa(n) + `}` }
	t := skillTarget{kind: kind, severity: sev, label: label, needles: needles, path: icuCI(p),
		redirect:     icuCI(`(?:>>?|\btee\s+(?:-a\s+)?)\s*` + dest),
		copy:         icuCI(`\b(?:cp|mv|ln|install|ditto|rsync|sed\s+-i\S*|perl\s+-pi\S*|plutil\s+-(?:insert|replace|convert|remove)|defaults\s+write)\b[^\n|;&]*\s` + dest + `[^\s"'|;&<>]*["']?\s*(?:$|[;&|)#])`),
		said:         icuCI(`\b(?:append|add|write|insert|save|put|place|copy|install|register)\b` + gap(60) + `\b(?:to|into|in|under|inside)\b` + gap(40) + `(?:` + p + `)|\b(?:modify|edit|update|overwrite|replace|change|create|patch)\b` + gap(30) + `(?:` + p + `)|(?:写入|写进|写到|追加|加到|加进|添加到|放进|放到|复制到|拷到)[^。\n]{0,30}(?:` + p + `)|(?:修改|改写|覆盖|创建|新建)[^。\n]{0,15}(?:` + p + `)|(?:` + p + `)[^。\n]{0,10}(?:里|中)?(?:写入|追加|加上|添加)`),
		saidSeverity: Medium}
	for _, o := range opts {
		o(&t)
	}
	return t
}

func buildSkillTargets() []skillTarget {
	return []skillTarget{
		skillTargetOf(SignalPersistence, High, "在 LaunchAgents 里放东西（开机自己运行）", needleList("launchagents", "launchdaemons"), `Library/Launch(?:Agents|Daemons)\b`),
		skillTargetOf(SignalPersistence, High, "改 shell 的启动文件（每开一个终端都会运行）",
			needleList("zshrc", "zshenv", "zprofile", "zlogin", "bashrc", "bash_profile", "bash_login", ".profile", "tcshrc", "cshrc", "config.fish"),
			`(?:^|[\s"'/=(:~])\.(?:zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|profile|tcshrc|cshrc)(?![\w.-])|\.config/fish/config\.fish\b`,
			tgSaid(Low), tgMild(`\bexport\s+PATH=|\bPATH=|\balias\s|eval\s+["']?\$\(\s*[\w/.-]+\s+(?:init|env|completion|shellenv|hook)\b`,
				"往 shell 的启动文件里加 PATH 之类的设置")),
		skillTargetOf(SignalPersistence, High, "往 SSH 的 authorized_keys 里加钥匙（别人能远程登录这台 Mac）", needleList("authorized_keys"), `\.ssh/authorized_keys\b`),
		skillTargetOf(SignalPersistence, High, "改系统的定时任务或启动脚本", needleList("crontab", "cron", "/var/at", "periodic", "startupitems", "rc.local", "launchd.conf"),
			`/etc/crontab|/usr/lib/cron/tabs|/var/at/tabs|/etc/periodic/|/Library/StartupItems|/etc/rc\.local|/etc/launchd\.conf`),
		skillTargetOf(SignalAgentTamper, High, "改 AI 工具的设置（钩子、MCP 服务器、权限）",
			needleList("settings", ".claude.json", "claude_desktop_config", "mcp", "config.toml", "hooks.json", "cli-config", "windsurf"),
			`\.claude/settings(?:\.local)?\.json|\.claude\.json\b|claude_desktop_config\.json|\.cursor/(?:mcp|hooks|settings|cli-config)\.json|\.gemini/settings\.json|\.codex/config\.toml|\.copilot/(?:config|mcp-config)\.json|(?:^|[\s"'/\x{60}])\.mcp\.json\b|\.vscode/mcp\.json|windsurf/mcp_config\.json`,
			tgPurpose(`\b(?:settings|config(?:ure|uration)?|hooks?|mcp|permissions?|setup|set\s+up)\b|设置|配置|钩子`)),
		skillTargetOf(SignalAgentTamper, High, "改 AI 的记忆或长期指令（CLAUDE.md 之类）",
			needleList("claude", "agents.md", "gemini.md", "cursorrules", "cursor/rules", "windsurfrules", "copilot-instructions"),
			`(?:^|[\s"'/(\x{60}~])(?:CLAUDE(?:\.local)?|AGENTS|GEMINI)\.md\b|\.cursorrules\b|\.cursor/rules/|\.windsurfrules\b|copilot-instructions\.md\b|\.claude/(?:agents|commands|memory)/`,
			tgPurpose(`\b(?:memory|memories|remember|claude\.md|agents\.md|gemini\.md|instructions?|rules|init(?:iali[sz]e)?|onboard\w*|conventions)\b|记忆|项目说明|规则|指令`)),
		// A SKILL.md, or skills by wildcard; copying a skill into a skills folder is how one is installed.
		skillTargetOf(SignalAgentTamper, High, "改别的 skill", needleList("skills", "skill.md"),
			`\bSKILL\.md\b|(?:\.claude|\.cursor|\.gemini|\.copilot|\.codex|\.agents|\.github)/skills/\*`, tgSaid(""), tgNotOwn(),
			tgPurpose(`\bskills?\b[^\n]{0,80}\b(?:creat\w*|author\w*|writ\w*|build\w*|generat\w*|install\w*|manag\w*|scaffold\w*|edit\w*|maintain\w*|updat\w*|improv\w*|mak\w*|packag\w*|sync\w*)\b|\b(?:creat\w*|author\w*|writ\w*|build\w*|generat\w*|install\w*|manag\w*|scaffold\w*|edit\w*|maintain\w*|updat\w*|improv\w*|mak\w*|packag\w*|sync\w*)\b[^\n]{0,80}\bskills?\b|skill[^\n]{0,20}(?:创建|编写|生成|安装|管理)|(?:创建|编写|生成|安装|管理)[^\n]{0,20}skill`)),
		skillTargetOf(SignalEscalation, High, "改 sudo 的设置（不用密码就能当管理员）", needleList("sudoers"), `/etc/sudoers`),
	}
}

// ---------------------------------------------------------------- one file

type skillHit struct {
	label    string
	kind     SignalKind
	severity Severity
	role     skillRole
	line     int
	// hidden: in an HTML comment, in invisible characters, or in an encoded blob; masked: the line had invisible
	// characters in it (taken out before matching).
	hidden, masked bool
}

type invisibleChars struct {
	clean           []rune
	tags            []rune // Unicode tag characters, decoded to ASCII (emoji flags left out)
	bidi, zeroWidth int
}

func skillInvisible(s []rune, first bool) invisibleChars {
	var inv invisibleChars
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		v := s[i]
		if v >= 0xE0000 && v <= 0xE007F {
			// A subdivision flag: a waving black flag, a few tag letters, and the cancel tag.
			j := i
			for j < len(s) && s[j] >= 0xE0000 && s[j] <= 0xE007F {
				j++
			}
			run := s[i:j]
			flag := i > 0 && s[i-1] == 0x1F3F4 && len(run) <= 8 && run[len(run)-1] == 0xE007F
			if !flag {
				for _, t := range run {
					if t >= 0xE0020 && t <= 0xE007E {
						inv.tags = append(inv.tags, t-0xE0000)
					}
				}
			}
			i = j
			continue
		}
		if (v >= 0x202A && v <= 0x202E) || (v >= 0x2066 && v <= 0x2069) {
			inv.bidi++
			i++
			continue
		}
		if v == 0x200B || (v >= 0x2060 && v <= 0x2064) || v == 0x180E || (v >= 0xFFF9 && v <= 0xFFFB) || (v == 0xFEFF && !(first && i == 0)) {
			inv.zeroWidth++
			i++
			continue
		}
		// Joiners belong in emoji and in some scripts; between two ASCII characters they only hide something.
		if v == 0x200C || v == 0x200D {
			if i > 0 && i+1 < len(s) && s[i-1] < 0x80 && s[i+1] < 0x80 {
				inv.zeroWidth++
			} else {
				out = append(out, v)
			}
			i++
			continue
		}
		out = append(out, v)
		i++
	}
	inv.clean = out
	return inv
}

type skillFileScan struct {
	hits                                []skillHit
	tagLines, bidiLines, zeroWidthLines []int
	zeroWidth                           int
	commentLines, blobLines             []int
}

var skillProseExt = aiSet("md", "markdown", "mdx", "txt", "rst", "text", "")

func skillColonEnd(s string) bool { return strings.HasSuffix(s, ":") || strings.HasSuffix(s, "：") }

func aiContainsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// aiLower is String.lowercased(): full Unicode lowercasing.
func aiLower(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 0x130: // İ
			b.WriteString("i\u0307")
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

var skillDynRx sync.Map

func skillDynamicRx(p string) *icuRegexp {
	if r, ok := skillDynRx.Load(p); ok {
		return r.(*icuRegexp)
	}
	r := icuCS(p)
	skillDynRx.Store(p, r)
	return r
}

type assignedVar struct {
	name   string
	target int
	line   int
}

// skillScanOpts change how skillScanFileWith reads a script (the install checks'); the zero value is the skills' way.
type skillScanOpts struct {
	// code, in place of scriptCode: a line's code and whether it is only a comment, called once for each line in order.
	code func(line string) (code string, only bool)
	// talks, in place of the whole line's words: whether a match (in the line as checked) is in a statement that talks
	// about such things rather than does them.
	talks func(s []rune, m []int) bool
	// cancelled: stop reading when it says so.
	cancelled func() bool
}

// skillScanFile runs every pattern over one text or script file.
func skillScanFile(text, path string, script bool, own []string) skillFileScan {
	return skillScanFileWith(text, path, script, own, skillScanOpts{})
}

// skillScanFileWith is skillScanFile read the way opts say.
func skillScanFileWith(text, path string, script bool, own []string, opts skillScanOpts) skillFileScan {
	c := skc()
	var out skillFileScan
	name := aiNSLast(path)
	commands := !skillLockfiles[name]
	markdown := !script && skillProseExt[strings.ToLower(aiNSExt(name))]
	lines := strings.Split(text, "\n")
	inComment, inFence, fenceTalk, sectionTopic, sectionNeg, listTalk := false, false, false, false, false, false
	var recent []string
	var assigned []assignedVar

	for index, raw := range lines {
		if opts.cancelled != nil && index%64 == 0 && opts.cancelled() {
			return out
		}
		n := index + 1
		inv := skillInvisible([]rune(strings.TrimSuffix(raw, "\r")), index == 0)
		if aiUTF16Len(inv.clean) > 4000 {
			inv.clean = graphemePrefix(inv.clean, 4000)
		}
		if len(inv.tags) > 0 {
			out.tagLines = append(out.tagLines, n)
		}
		if inv.bidi > 0 {
			out.bidiLines = append(out.bidiLines, n)
		}
		if inv.zeroWidth > 0 {
			out.zeroWidthLines = append(out.zeroWidthLines, n)
			out.zeroWidth += inv.zeroWidth
		}
		masked := inv.zeroWidth > 0 || inv.bidi > 0 || len(inv.tags) > 0

		// What the reader of the rendered Markdown sees, and what sits in an HTML comment.
		var visible, hidden string
		cleanStr := string(inv.clean)
		if markdown {
			rest := cleanStr
			var vb, hb strings.Builder
			for rest != "" {
				if inComment {
					if i := strings.Index(rest, "-->"); i >= 0 {
						hb.WriteString(rest[:i])
						rest = rest[i+3:]
						inComment = false
					} else {
						hb.WriteString(rest)
						rest = ""
					}
				} else if i := strings.Index(rest, "<!--"); i >= 0 {
					vb.WriteString(rest[:i])
					rest = rest[i+4:]
					inComment = true
				} else {
					vb.WriteString(rest)
					rest = ""
				}
			}
			visible, hidden = vb.String(), hb.String()
		} else {
			visible = cleanStr
		}

		// A script's line that is only a comment carries no commands; code after a block comment closed on the line
		// (/**/ x, a /*! license */ banner, the end * … */ of a block comment) is code.
		scriptComment := false
		if script {
			var code string
			var only bool
			if opts.code != nil {
				code, only = opts.code(visible)
			} else {
				code, only = scriptCode(visible)
			}
			scriptComment = only
			if !only && code != aiTrimWS(visible) {
				visible = code
			}
		}

		// Whether this line talks about something rather than says to do it.
		trimmed := aiTrimWS(visible)
		visibleR := []rune(visible)
		talkNeg, talkTopic, commentLine := false, false, false
		if script {
			commentLine = scriptComment
			talkTopic = c.topic.hasRunes(visibleR) || c.patternLine.hasRunes(visibleR)
		} else {
			lastTalks := func(l string) bool { return c.topic.has(l) || c.negation.has(l) }
			if c.fence.hasRunes(visibleR) {
				if inFence {
					inFence, fenceTalk = false, false
				} else {
					inFence = true
					fenceTalk = len(recent) > 0 && lastTalks(recent[len(recent)-1])
				}
			}
			if !inFence && c.heading.hasRunes(visibleR) {
				sectionTopic, sectionNeg = c.topic.hasRunes(visibleR), c.negation.hasRunes(visibleR)
			}
			if trimmed != "" && !inFence {
				if c.listItem.hasRunes(visibleR) {
					if len(recent) > 0 {
						last := recent[len(recent)-1]
						if skillColonEnd(last) && lastTalks(last) {
							listTalk = true
						}
					}
				} else if !(len(recent) > 0 && skillColonEnd(recent[len(recent)-1])) || c.heading.hasRunes(visibleR) {
					listTalk = false
				}
			}
			lead := false
			from := len(recent) - 2
			if from < 0 {
				from = 0
			}
			for _, l := range recent[from:] {
				if skillColonEnd(l) && lastTalks(l) {
					lead = true
				}
			}
			talkTopic = c.topic.hasRunes(visibleR) || sectionTopic || fenceTalk || listTalk || lead
			talkNeg = sectionNeg
		}
		if trimmed != "" {
			recent = append(recent, trimmed)
			if len(recent) > 3 {
				recent = recent[1:]
			}
		}

		run := func(text string, hidden, decoded bool) {
			if text == "" {
				return
			}
			s := c.joined.replaceAll([]rune(text), "/")
			sStr := string(s)
			lower := aiLower(sStr)
			quiet := s
			if c.notWorry.hasRunes(s) {
				quiet = c.notWorry.replaceAll(s, "")
			}
			for _, p := range c.patterns {
				switch p.scope {
				case scopeCode:
					if !script {
						continue
					}
				case scopeProse:
					if script {
						continue
					}
				}
				// A script's comments carry no commands, only words to the agent.
				words := p.role == roleInjection || p.role == roleConceal
				if script && commentLine && !words {
					continue
				}
				if !commands && !words {
					continue
				}
				if !aiContainsAny(lower, p.needles) {
					continue
				}
				m := p.re.find(s, 0)
				if m == nil {
					continue
				}
				if p.unless != nil && p.unless.hasRunes(s) {
					continue
				}
				if p.test != nil && !p.test(s, m) {
					continue
				}
				if p.outsideCode && !script && !decoded {
					ticks := 0
					for _, r := range s[:m[0]] {
						if r == '`' {
							ticks++
						}
					}
					if inFence || ticks%2 == 1 {
						continue
					}
				}
				if !decoded {
					if words {
						if hidden {
							if c.topic.hasRunes(s) {
								continue
							}
						} else if talkTopic {
							continue
						}
					} else if !hidden {
						if opts.talks != nil {
							if opts.talks(s, m) {
								continue
							}
						} else if before := aiPrefixUTF16(quiet, aiUTF16Len(s[:m[0]])); talkTopic || talkNeg || c.negation.hasRunes(before) {
							continue
						}
					} else if c.topic.hasRunes(s) || c.negation.hasRunes(s) {
						continue
					}
				}
				sev := p.sev(!script)
				if p.role == roleConceal && c.action.hasRunes(s) {
					sev = Medium
				}
				out.hits = append(out.hits, skillHit{label: p.label, kind: p.kind, severity: sev, role: p.role, line: n,
					hidden: hidden || decoded, masked: masked})
			}
			if !commands {
				return
			}
			ownHit := aiContainsAny(lower, own)
			// Writing to a place that matters.
			for ti, t := range c.targets {
				if !aiContainsAny(lower, t.needles) || !t.path.hasRunes(s) {
					continue
				}
				var talk bool
				if opts.talks != nil {
					talk = !hidden && !decoded && opts.talks(s, t.path.find(s, 0))
				} else {
					talk = !hidden && !decoded && (talkTopic || talkNeg || c.negation.hasRunes(quiet))
				}
				if script && commentLine {
					continue
				}
				if t.notOwn && ownHit {
					continue
				}
				// A variable set to it here (RC=~/.zshrc, for f in ~/.claude/skills/*/SKILL.md), written through now or later.
				variable, hasVariable := "", false
				if script {
					if v := c.assign.find(s, 0); v != nil {
						variable, hasVariable = string(c.assignStrip.replaceAll(s[v[0]:v[1]], "")), true
					} else if v := c.forIn.find(s, 0); v != nil {
						variable, hasVariable = string(c.forStrip.replaceAll(s[v[0]:v[1]], "")), true
					}
				}
				if hasVariable {
					// Only the last 15 lines' are ever looked at: the older are dropped (a long file can set thousands).
					keep := assigned[:0]
					for _, a := range assigned {
						if n-a.line <= 15 {
							keep = append(keep, a)
						}
					}
					assigned = append(keep, assignedVar{variable, ti, n})
				}
				intoVariable := hasVariable && skillDynamicRx(`(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?\$\{?`+rxEscape(variable)+`\b`).hasRunes(s)
				command := skillRedirects(t.redirect, s, script) || skillCopies(t.copy, s, script) || (script && c.writeCall.hasRunes(s)) || intoVariable
				words := !command && !script && t.saidSeverity != "" && t.said.hasRunes(s)
				if !(command || words) || talk {
					continue
				}
				isMild := t.mild != nil && t.mild.hasRunes(s)
				label, sev := t.label, t.severity
				if isMild {
					label, sev = t.mildLabel, Low
				} else if words {
					sev = t.saidSeverity
				}
				out.hits = append(out.hits, skillHit{label: label, kind: t.kind, severity: sev, role: rolePlain, line: n,
					hidden: hidden || decoded, masked: masked})
			}
			// A variable set to such a place, written to within a few lines.
			if script && !commentLine && (c.writeCall.hasRunes(s) || c.varRedirect.hasRunes(s)) {
				call := c.writeCall.hasRunes(s)
				for _, a := range assigned {
					if n-a.line > 15 || n == a.line || (c.targets[a.target].notOwn && ownHit) {
						continue
					}
					name := rxEscape(a.name)
					if !((call && skillDynamicRx(`\b`+name+`\b`).hasRunes(s)) ||
						skillDynamicRx(`(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?\$\{?`+name+`\b`).hasRunes(s)) {
						continue
					}
					t := c.targets[a.target]
					out.hits = append(out.hits, skillHit{label: t.label, kind: t.kind, severity: t.severity, role: rolePlain, line: a.line,
						masked: masked})
				}
			}
		}
		run(visible, false, false)
		if aiTrimWS(hidden) != "" {
			out.commentLines = append(out.commentLines, n)
			run(hidden, true, false)
			hr := []rune(hidden)
			if c.aiAddressed.hasRunes(hr) && c.imperative.hasRunes(hr) && !c.topic.hasRunes(hr) {
				// Hidden by what it is: not made more serious for that again.
				out.hits = append(out.hits, skillHit{label: "HTML 注释里藏着给 AI 的话（你看不到，AI 看得到）", kind: SignalInjection,
					severity: Medium, role: roleInjection, line: n})
			}
		}
		// What the tag characters spell out, and what an encoded blob in the instructions decodes to.
		if len(inv.tags) > 0 {
			for _, l := range strings.Split(string(inv.tags), "\n") {
				run(l, true, true)
			}
		}
		if markdown && !inFence && !talkTopic {
			for _, blob := range skillBlobs(inv.clean) {
				out.blobLines = append(out.blobLines, n)
				if blob != nil {
					for _, l := range strings.Split(*blob, "\n") {
						run(l, true, true)
					}
				}
			}
		}
	}
	return out
}

// scriptCode is the code of a script's line: what is left after the block comments that open and close before it;
// only true when the line is nothing but a comment (#, //, -- and REM to its end, or a block comment not closed on it).
func scriptCode(line string) (code string, only bool) {
	s := aiTrimWS(line)
	for {
		switch {
		case strings.HasPrefix(s, "/*"):
			i := strings.Index(s[2:], "*/")
			if i < 0 {
				return "", true
			}
			s = aiTrimWS(s[2+i+2:])
		case strings.HasPrefix(s, "*"):
			i := strings.Index(s, "*/")
			if i < 0 {
				return "", true
			}
			s = aiTrimWS(s[i+2:])
		case (strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "#!")) || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "-- ") ||
			strings.HasPrefix(s, "REM "):
			return "", true
		default:
			return s, false
		}
		if s == "" {
			return "", true
		}
	}
}

// aiPrefixUTF16 is the characters of s within the first n UTF-16 code units (NSString's substring(to:), a character cut
// in half left out).
func aiPrefixUTF16(s []rune, n int) []rune {
	used := 0
	for i, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if used+w > n {
			return s[:i]
		}
		used += w
	}
	return s
}

func aiIsHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// skillBlobs are the long base64 or hex runs in a line (not a data: URI), each with its decoded text when it is text.
func skillBlobs(line []rune) []*string {
	c := skc()
	var out []*string
	for _, m := range c.base64Blob.findAll(line) {
		before := line[:m[0]]
		if c.dataURI.hasRunes(before) {
			continue
		}
		b := string(line[m[0]:m[1]])
		allHex, upper, lower, digit, slashes := true, false, false, false, 0
		for _, r := range b {
			if !aiIsHex(r) {
				allHex = false
			}
			switch {
			case r >= 'A' && r <= 'Z':
				upper = true
			case r >= 'a' && r <= 'z':
				lower = true
			case r >= '0' && r <= '9':
				digit = true
			case r == '/':
				slashes++
			}
		}
		if allHex {
			continue // the hex check's
		}
		// Encoded bytes mix cases and digits; a long path or name of words does not, and has many slashes.
		bs := string(before)
		if !upper || !lower || !digit || slashes*20 >= len(b) || strings.Contains(b, "//") || strings.HasSuffix(bs, "://") || strings.HasSuffix(bs, "/") {
			continue
		}
		s := strings.ReplaceAll(strings.ReplaceAll(b, "-", "+"), "_", "/")
		for len(s)%4 != 0 {
			s += "="
		}
		if d, err := base64.StdEncoding.DecodeString(s); err == nil {
			out = append(out, aiPrintable(d))
		} else {
			out = append(out, nil)
		}
	}
	for _, m := range c.hexBlob.findAll(line) {
		h := string(line[m[0]:m[1]])
		var bytes []byte
		for i := 0; i+1 < len(h); i += 2 {
			if v, err := strconv.ParseUint(h[i:i+2], 16, 8); err == nil {
				bytes = append(bytes, byte(v))
			}
		}
		out = append(out, aiPrintable(bytes))
	}
	return out
}

func aiPrintable(d []byte) *string {
	s, ok := aiDecodeUTF8(d)
	if !ok || s == "" {
		return nil
	}
	total, good := 0, 0
	for _, r := range s {
		total++
		if r >= 0x20 || r == '\n' || r == '\t' || r == '\r' {
			good++
		}
	}
	if float64(good)/float64(total) > 0.9 {
		return &s
	}
	return nil
}

// ---------------------------------------------------------------- one skill

var mentionStop = aiSet("curl", "wget", "chmod", "sudo", "os", "urllib", "request", "urlretrieve", "requests", "get", "x", "u", "a",
	"then", "fi", "if", "do", "done", "and", "true", "false", "http", "https", "bin", "tmp", "usr", "local", "home")

// skillMentioned are the file names and variables a command line mentions (a URL by its last part), without the commands
// and flags: what links a download to the chmod of the same file.
func skillMentioned(line string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(" \t,()'\"=;&|`", r) }) {
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "+") {
			continue
		}
		allNum := true
		for _, r := range w {
			if !(unicode.IsNumber(r) || r == 'o') {
				allNum = false
				break
			}
		}
		if allNum {
			continue
		}
		if strings.Contains(w, "://") {
			parts := strings.FieldsFunc(w, func(r rune) bool { return r == '/' })
			w = ""
			if len(parts) > 0 {
				w = parts[len(parts)-1]
			}
		}
		w = aiNSLast(w)
		w = strings.Trim(w, "{}$")
		if graphemeCount(w) >= 2 && !mentionStop[aiLower(w)] {
			out[w] = true
		}
	}
	return out
}

func skillBump(s Severity) Severity {
	switch s {
	case Low:
		return Medium
	case Medium, High:
		return High
	}
	return ""
}

// aiSplitLines splits text at "\n" the way Swift's split(separator: "\n") does: by Character, so a "\r\n" (one
// Character) is not a place to split.
func aiSplitLines(text string, omitEmpty bool) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' && !(i > 0 && text[i-1] == '\r') {
			if !omitEmpty || i > start {
				out = append(out, text[start:i])
			}
			start = i + 1
		}
	}
	if !omitEmpty || len(text) > start {
		out = append(out, text[start:])
	}
	return out
}

// skillMinified says whether code is minified: lines too long to read, where the text checks would only find noise.
func skillMinified(text, name string) bool {
	if strings.Contains(name, ".min.") {
		return true
	}
	lines := aiSplitLines(text, true)
	if len(lines) == 0 {
		return false
	}
	longest := 0
	for _, l := range lines {
		if len(l) > longest {
			longest = len(l)
		}
	}
	return longest > 5000 && len(text)/len(lines) > 400
}

func aiAbs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

// A redirect or a copy as the targets' patterns find one, less what only looks like it (luoke-scan#205):
//
//   - the `>` that closes a placeholder: `~/.claude/skills/<slug>/SKILL.md` is a path with a name left open, not
//     something written to `/SKILL.md`;
//   - in prose, `>` as "comes before": `existing > CLAUDE.md > ask` orders three things, no command is in the line;
//   - in prose, "install" as a word: `every install path matching ~/.claude/skills/*/SKILL.md` runs no install(1).
//     As a command it stands where a command does (a line's start, after `$`, sudo, `&&`, `;`, `|`, or a back quote).
//
// In a script every line is a command, so only the placeholder is taken out there.
var (
	skillPlaceholderOpen = icuCS(`<[A-Za-z_][\w .-]{0,40}$`)
	skillShellWord       = icuCI(`\b(?:echo|printf|cat|tee|sed|awk|jq|cp|mv|curl|wget)\b|<<`)
	skillLoneArrow       = icuCS(`\s>\s`)
	skillInstallVerb     = icuCI(`^install\b`)
	skillCommandStart    = icuCI(`(?:^|[$;|&\x{60}]|\bsudo|\bthen|\bdo)\s*$`)
)

func skillRedirects(re *icuRegexp, s []rune, script bool) bool {
	ordering := !script && len(skillLoneArrow.findAll(s)) >= 2 && !skillShellWord.hasRunes(s)
	for _, m := range re.findAll(s) {
		lone := s[m[0]] == '>' && !(m[0]+1 < len(s) && s[m[0]+1] == '>')
		if lone && skillPlaceholderOpen.hasRunes(s[:m[0]]) {
			continue
		}
		if lone && ordering {
			continue
		}
		return true
	}
	return false
}

func skillCopies(re *icuRegexp, s []rune, script bool) bool {
	for _, m := range re.findAll(s) {
		if !script && skillInstallVerb.hasRunes(s[m[0]:m[1]]) && !skillCommandStart.hasRunes(s[:m[0]]) {
			continue
		}
		return true
	}
	return false
}

// A list of strings in a script is what the script looks for, not what it does: a guard's signatures
// (`COMMAND_INJECTION=( 'rm -rf /' 'curl .* | bash' … )`), a linter's deny list. Lines that are nothing but a quoted
// string, three or more in a row (blank lines and comments between them aside), are such a list, and what the
// checks find on them is left out; unless the script runs strings somewhere (eval, sh -c, a line that is a
// variable): then a list may be what it runs, and everything counts as before. Hidden and masked hits always count.
var (
	skillOnlyString  = icuCS("^\\s*(?:'[^']*'|\"(?:[^\"\\\\]|\\\\.)*\")\\s*,?\\s*(?:#.*)?$")
	skillBlankOrNote = icuCS(`^\s*(?:#.*|//.*)?$`)
	skillRunsString  = icuCS(`\beval\b|\b(?:ba|z|k|da)?sh\s+-c\b|^\s*"?\$\{?[A-Za-z_]\w*(?:\[[^\]]*\])?\}?"?\s*(?:$|[;&|])|\bexec\s+["']?\$|\bos\.system\s*\(|\bsubprocess\.|\bchild_process\b|\bexecSync\s*\(`)
)

func skillListedLines(text string) map[int]bool {
	lines := strings.Split(text, "\n")
	listed := map[int]bool{}
	var run []int
	flush := func() {
		if len(run) >= 3 {
			for _, n := range run {
				listed[n] = true
			}
		}
		run = nil
	}
	for i, l := range lines {
		r := []rune(strings.TrimSuffix(l, "\r"))
		switch {
		case skillOnlyString.hasRunes(r):
			run = append(run, i+1)
		case skillBlankOrNote.hasRunes(r):
		default:
			flush()
		}
	}
	flush()
	if len(listed) == 0 {
		return nil
	}
	for i, l := range lines {
		if !listed[i+1] && skillRunsString.hasRunes([]rune(l)) {
			return nil
		}
	}
	return listed
}

func skillWithoutListed(hits []skillHit, text string) []skillHit {
	listed := skillListedLines(text)
	if listed == nil {
		return hits
	}
	var out []skillHit
	for _, h := range hits {
		if listed[h.line] && !h.hidden && !h.masked {
			continue
		}
		out = append(out, h)
	}
	return out
}

// SkillSignals are everything the static checks find in a skill, merged per kind, label and file.
func SkillSignals(skill Skill) []SkillSignal {
	c := skc()
	var out []SkillSignal
	add := func(kind SignalKind, sev Severity, label, file string, lines []int) {
		out = append(out, SkillSignal{Kind: kind, Severity: sev, Label: label, File: file, Lines: lines})
	}
	scriptSendOrDelete := false
	about := []rune(skill.Name + "\n" + skill.Description)
	// How a skill's own install line names it.
	var own []string
	for _, o := range aiSortedUnique([]string{aiLower(skill.Name), aiLower(aiNSLast(skill.Folder))}) {
		if graphemeCount(o) >= 3 {
			own = append(own, o)
		}
	}

	for _, f := range skill.Files {
		if !f.HasText || (f.Kind != FileKindText && f.Kind != FileKindScript) {
			continue
		}
		text := f.Text
		script := f.Kind == FileKindScript
		if skillMinified(text, f.Path) {
			add(SignalUnreadable, Low, "带着压缩过的代码，读不出它做什么", f.Path, []int{})
			continue
		}
		s := skillScanFile(text, f.Path, script, own)
		hits := s.hits
		if script {
			hits = skillWithoutListed(hits, text)
		}
		// Hidden: words to the agent the user does not see are serious; commands one step more.
		for i := range hits {
			if !hits[i].hidden && !hits[i].masked {
				continue
			}
			if hits[i].role == roleInjection || hits[i].role == roleConceal {
				hits[i].severity = High
			} else if hits[i].severity != "" {
				hits[i].severity = skillBump(hits[i].severity)
			}
			if hits[i].hidden {
				hits[i].label += "（藏起来了）"
			} else if hits[i].masked {
				hits[i].label += "（中间夹着看不见的字符）"
			}
		}
		if len(s.tagLines) > 0 {
			add(SignalInjection, High, "藏着看不见的字符（Unicode 标签字符，AI 读得到）", f.Path, s.tagLines)
		}
		if len(s.bidiLines) > 0 {
			sev := Medium
			if script {
				sev = High
			}
			add(SignalInjection, sev, "有改变文字显示顺序的控制字符（看到的和实际的不一样）", f.Path, s.bidiLines)
		}
		if s.zeroWidth >= 3 {
			add(SignalInjection, Medium, "夹着零宽字符（看不见的字符）", f.Path, s.zeroWidthLines)
		}
		if len(s.blobLines) > 0 && !script {
			add(SignalInjection, Medium, "说明里有一大段编码过的内容", f.Path, s.blobLines)
		}

		// A key read and data sent from the same script, or near each other in prose.
		near := func(a, b skillHit) bool { return script || aiAbs(a.line-b.line) <= 3 }
		var sending []skillHit
		for _, h := range hits {
			if h.role == roleSend || h.role == roleDrop {
				sending = append(sending, h)
			}
		}
		paired := map[int]bool{} // a key read that is part of a pair is said once, as the pair
		for _, sec := range hits {
			if sec.role != roleSecretStrong && sec.role != roleSecretWeak {
				continue
			}
			for _, p := range sending {
				if !(near(sec, p) && (sec.role == roleSecretStrong || p.role == roleDrop)) {
					continue
				}
				what := strings.ReplaceAll(strings.ReplaceAll(sec.label, "（藏起来了）", ""), "（中间夹着看不见的字符）", "")
				label := "读"
				if r := aiFirstRune(what); what != "" && r < 0x80 {
					label += " "
				}
				label += what
				if r, _ := utf8.DecodeLastRuneInString(what); what != "" && r < 0x80 {
					label += " "
				}
				add(SignalExfil, High, label+"再发到网上", f.Path, []int{sec.line, p.line})
				paired[sec.line] = true
				break
			}
		}
		// A download made executable: a program fetched to run.
		var downloads, chmods []skillHit
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
		lines := strings.Split(text, "\n")
		linked := func(d, ch skillHit) bool {
			if aiAbs(ch.line-d.line) > 15 || ch.line > len(lines) || d.line > len(lines) {
				return false
			}
			a, b := skillMentioned(lines[ch.line-1]), skillMentioned(lines[d.line-1])
			for k := range a {
				if b[k] {
					return true
				}
			}
			return false
		}
	pairs:
		for _, d := range downloads {
			for _, ch := range chmods {
				if linked(d, ch) {
					if verified {
						add(SignalSupplyChain, Medium, "下载程序来运行（核对了校验和）", f.Path, []int{d.line, ch.line})
					} else {
						add(SignalDownloadExec, High, "下载程序、加上执行权限再运行", f.Path, []int{d.line, ch.line})
					}
					break pairs
				}
			}
		}
		for _, h := range hits {
			if script && (h.role == roleSend || h.role == roleDelete || h.role == roleDrop) {
				scriptSendOrDelete = true
			}
		}
		for _, h := range hits {
			switch h.role {
			case roleSend, roleDownload, roleChmodX, roleChecksum, roleDelete, roleSecretWeak:
				continue
			case roleSecretStrong:
				if paired[h.line] {
					continue
				}
			}
			if h.severity != "" || h.role == rolePlain {
				add(h.kind, h.severity, h.label, f.Path, []int{h.line})
			}
		}
	}

	// What the text checks cannot see.
	var compiled, packed, opaque, large, links, deps []SkillFile
	for _, f := range skill.Files {
		unread := f.Kind == FileKindCompiled || f.Kind == FileKindArchive || f.Kind == FileKindBinary ||
			(f.Unread != "" && f.Unread != UnreadICloud && (f.Kind == FileKindText || f.Kind == FileKindScript || f.Unread == UnreadLinkOutside ||
				f.Unread == UnreadDependencies || f.Unread == UnreadTooDeep))
		if !unread {
			continue
		}
		switch f.Kind {
		case FileKindCompiled:
			compiled = append(compiled, f)
		case FileKindArchive:
			packed = append(packed, f)
		case FileKindBinary:
			opaque = append(opaque, f)
		}
		switch f.Unread {
		case UnreadTooLarge, UnreadBudget, UnreadUnreadable:
			large = append(large, f)
		case UnreadLinkOutside:
			links = append(links, f)
		case UnreadDependencies, UnreadTooDeep:
			deps = append(deps, f)
		}
	}
	names := func(fs []SkillFile) string {
		var ps []string
		for i, f := range fs {
			if i >= 5 {
				break
			}
			ps = append(ps, f.Path)
		}
		s := strings.Join(ps, "、")
		if len(fs) > 5 {
			s += " 等 " + strconv.Itoa(len(fs)) + " 个"
		}
		return s
	}
	if len(compiled) > 0 {
		add(SignalUnreadable, Medium, "带着编译过的程序，看不到里面写了什么", names(compiled), []int{})
	}
	if len(packed) > 0 {
		add(SignalUnreadable, Low, "带着压缩包，里面没看", names(packed), []int{})
	}
	if len(opaque) > 0 {
		add(SignalUnreadable, Low, "带着认不出格式的文件", names(opaque), []int{})
	}
	if len(large) > 0 {
		add(SignalUnreadable, Low, "有文件太大或读不了，没看", names(large), []int{})
	}
	if len(links) > 0 {
		add(SignalUnreadable, Low, "有链接指向 skill 文件夹外面，没跟过去", names(links), []int{})
	}
	if len(deps) > 0 {
		add(SignalUnreadable, Low, "带着依赖文件夹，里面没逐个看", names(deps), []int{})
	}
	if skill.Unlisted > 0 {
		add(SignalUnreadable, Low, "文件太多，有 "+strconv.Itoa(skill.Unlisted)+" 个没看", "", []int{})
	}

	// The front matter: a shell without limits.
	unlimited := false
	for _, t := range skill.AllowedTools {
		x := aiTrimWS(t)
		switch aiLower(x) {
		case "bash", "shell", "run_shell_command", "terminal", "*":
			unlimited = true
		}
		if unlimited || c.allowedShell.has(x) {
			unlimited = true
			break
		}
	}
	if skill.HasAllowedTools && unlimited {
		add(SignalPermission, Low, "允许 AI 不受限制地跑命令（allowed-tools 里的 Bash 没限定命令）", "SKILL.md", []int{})
	}
	// Says it changes nothing, while a script deletes or sends.
	if c.readOnlyClaim.has(skill.Description) && scriptSendOrDelete {
		add(SignalPermission, Medium, "说自己只读，脚本却会删文件或往外发数据", "SKILL.md", []int{})
	}

	// What the skill says it is for: writing what that is about stays low.
	for i := range out {
		sev := out[i].Severity
		if sev == "" {
			sev = Low
		}
		if out[i].Kind != SignalAgentTamper || sev.Rank() < Medium.Rank() {
			continue
		}
		for _, t := range c.targets {
			if t.label == out[i].Label {
				if t.purpose != nil && t.purpose.hasRunes(about) {
					out[i].Severity = Low
					out[i].Label += "（它说自己就是做这个的）"
				}
				break
			}
		}
	}
	// Keeping things from the user, together with anything that matters.
	concealed, serious := false, false
	for _, s := range out {
		if strings.HasPrefix(s.Label, "让 AI 瞒着你") {
			concealed = true
		} else if s.Severity != "" && s.Severity.Rank() >= Medium.Rank() && s.Kind != SignalUnreadable {
			serious = true
		}
	}
	if concealed && serious {
		for i := range out {
			if strings.HasPrefix(out[i].Label, "让 AI 瞒着你") {
				out[i].Severity = High
			}
		}
	}
	return mergeSignals(out)
}

func aiUniqueInts(a []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, v := range a {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

func skillSevOrLow(s Severity) Severity {
	if s == "" {
		return Low
	}
	return s
}

// mergeSignals: one signal per kind, label and file, with its lines (the most serious severity among them).
func mergeSignals(signals []SkillSignal) []SkillSignal {
	var order []string
	by := map[string]SkillSignal{}
	for _, s := range signals {
		k := string(s.Kind) + "|" + s.Label + "|" + s.File
		if e, ok := by[k]; ok {
			e.Lines = aiUniqueInts(append(append([]int{}, e.Lines...), s.Lines...))
			if skillSevOrLow(s.Severity).Rank() > skillSevOrLow(e.Severity).Rank() || e.Severity == "" {
				if s.Severity != "" {
					e.Severity = s.Severity
				}
			}
			by[k] = e
		} else {
			order = append(order, k)
			s.Lines = aiUniqueInts(s.Lines)
			by[k] = s
		}
	}
	out := make([]SkillSignal, 0, len(order))
	for _, k := range order {
		out = append(out, by[k])
	}
	return out
}
