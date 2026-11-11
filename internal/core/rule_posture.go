package core

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// PostureRule checks basic security settings: FileVault, firewall (and its stealth mode), SIP, Gatekeeper, screen
// lock, automatic updates, pending updates on a Mac that has not restarted for long; what is shared and who can log
// in (remote login, screen and file sharing, internet sharing, AirDrop for everyone, automatic login, the guest
// account); root certificates someone added to the trusted ones; XProtect's definitions not updated for long. Only
// bad states are reported. Each probe that cannot run is skipped on its own and listed, never read as "fine".
// Nothing here needs a password or shows a dialog.
type PostureRule struct {
	// Command runs a system command and returns its exit status (-1: it did not finish) and output; nil: runs it.
	Command func(tool string, args []string) (int, string)
	// BootTime is when this Mac started; nil: kern.boottime.
	BootTime func() (time.Time, bool)
	// PendingUpdates are the system updates waiting; nil: the software update preferences.
	PendingUpdates func() (int, bool)
	// XProtectUpdated is when XProtect's definitions last changed; nil: its bundles' Info.plist, the newer.
	XProtectUpdated func() (time.Time, bool)
	LongUptime      time.Duration
	XProtectStale   time.Duration
}

func init() { Register("posture", NewPostureRule) }

// NewPostureRule is the rule for this Mac (l nil) or a fake home: there every command is answered by f, and the boot
// time, pending updates and XProtect's date are f's.
func NewPostureRule(l *Layout, f *Fakes) Rule {
	r := &PostureRule{LongUptime: 30 * 24 * time.Hour, XProtectStale: 60 * 24 * time.Hour}
	if l != nil {
		r.Command = f.Answer
		r.BootTime = func() (time.Time, bool) {
			if f.BootTime == nil {
				return time.Time{}, false
			}
			return *f.BootTime, true
		}
		r.PendingUpdates = func() (int, bool) {
			if f.PendingUpdates == nil {
				return 0, false
			}
			return *f.PendingUpdates, true
		}
		r.XProtectUpdated = func() (time.Time, bool) {
			if f.XProtectUpdated == nil {
				return time.Time{}, false
			}
			return *f.XProtectUpdated, true
		}
	}
	return r
}

func (r *PostureRule) ID() string      { return "posture" }
func (r *PostureRule) Emits() []string { return []string{"posture"} }

func postureRun(tool string, args []string) (int, string) {
	res := Run(tool, args, RunOpts{Timeout: 15 * time.Second})
	if res.TimedOut {
		return -1, res.Stdout
	}
	return res.Status, res.Stdout
}

// RecommendedUpdates are the updates the software update preferences say are waiting; ok false when not known.
func RecommendedUpdates() (int, bool) {
	d := ReadPlistDict("/Library/Preferences/com.apple.SoftwareUpdate.plist")
	if a, ok := d["RecommendedUpdates"].([]any); ok {
		return len(a), true
	}
	return 0, false
}

// XProtectDate is when XProtect's definitions last changed (its bundle's Info.plist, the newer copy).
func XProtectDate() (time.Time, bool) {
	var newest time.Time
	found := false
	for _, b := range []string{"/private/var/protected/xprotect/XProtect.bundle", "/Library/Apple/System/Library/CoreServices/XProtect.bundle"} {
		if t, ok := Modified(b + "/Contents/Info.plist"); ok && (!found || t.After(newest)) {
			newest, found = t, true
		}
	}
	return newest, found
}

// postureSpace is what the Swift version's regular expressions (ICU) take for \s: White_Space.
const postureSpace = `[\t\n\x0B\f\r \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]`

var (
	postureService     = regexp.MustCompile(`"([^"]+)"` + postureSpace + `*=>` + postureSpace + `*(enabled|false)`)
	postureCert        = regexp.MustCompile(`^Cert \p{Nd}+: `)
	postureScreenDelay = regexp.MustCompile(`screenlock delay is (\p{Nd}+) seconds`)
)

// postureLines are Swift's split(separator: "\n"): pieces between line feeds, empty ones left out, and a CR LF not a
// line feed (it is one Character there).
func postureLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// postureTrim is Swift's trimmingCharacters(in: .whitespacesAndNewlines).
func postureTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', 0x85, 0x2028, 0x2029:
			return true
		}
		return unicode.Is(unicode.Zs, r)
	})
}

// postureEnabledServices are the services the system's launchd overrides say are on (`launchctl print-disabled
// system`: `"label" => enabled`, or `=> false` from older systems). One with no override keeps its default (off for
// these).
func postureEnabledServices(text string) map[string]bool {
	out := map[string]bool{}
	for _, line := range postureLines(text) {
		if m := postureService.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// postureTrustedCerts are the certificates `security dump-trust-settings` lists that are trusted as a root for
// anything: no trust settings at all ("always trust"), or a setting that trusts it as a root without being limited
// to one host or use (a "Policy String"). "Never trust" and a host's own exception (a NAS, a router) are not.
func postureTrustedCerts(text string) []string {
	var out []string
	var name *string
	count, rootSetting, limited, deny := 0, false, false, false
	closeCert := func() {
		if name != nil && (count == 0 || (rootSetting && !limited && !deny)) {
			out = append(out, *name)
		}
		name, count, rootSetting, limited, deny = nil, 0, false, false, false
	}
	for _, raw := range postureLines(text) {
		line := sysTrimSpaces(raw)
		if loc := postureCert.FindStringIndex(line); loc != nil {
			closeCert()
			n := sysTrimSpaces(line[loc[1]:])
			name = &n
		} else if strings.HasPrefix(line, "Number of trust settings") {
			parts := postureSplit(line, ":")
			if len(parts) > 0 {
				if n, err := strconv.Atoi(sysTrimSpaces(parts[len(parts)-1])); err == nil {
					count = n
				}
			}
		} else if strings.HasPrefix(line, "Policy String") {
			limited = true
		} else if strings.HasPrefix(line, "Result Type") {
			if strings.Contains(line, "Deny") {
				deny = true
			} else if strings.Contains(line, "TrustRoot") || strings.Contains(line, "TrustAsRoot") {
				rootSetting = true
			}
		}
	}
	closeCert()
	return out
}

// postureSplit is Swift's split(separator:): the pieces between separators, empty ones left out.
func postureSplit(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (r *PostureRule) Run(ctx *Context) ([]Finding, error) {
	command := r.Command
	if command == nil {
		command = postureRun
	}
	bootTime, pendingUpdates, xprotectUpdated := r.BootTime, r.PendingUpdates, r.XProtectUpdated
	if bootTime == nil {
		bootTime = KernelBootTime
	}
	if pendingUpdates == nil {
		pendingUpdates = RecommendedUpdates
	}
	if xprotectUpdated == nil {
		xprotectUpdated = XProtectDate
	}
	var out []Finding
	var failed []string
	bad := func(rule string, sev Severity, title, how string, ev map[string]string) {
		e := map[string]string{}
		for k, v := range ev {
			e[k] = v
		}
		e["how"] = how
		key := e["_key"]
		delete(e, "_key")
		out = append(out, Finding{Rule: "posture." + rule, Category: CatPosture, Severity: sev, Verdict: Info, Title: title, Evidence: e, Key: key})
	}
	probe := func(name, tool string, args []string) (string, bool) {
		status, text := command(tool, args)
		if status == -1 || (status != 0 && text == "") {
			failed = append(failed, name)
			return "", false
		}
		return strings.ToLower(text), true
	}

	if t, ok := probe("FileVault", "/usr/bin/fdesetup", []string{"status"}); ok && strings.Contains(t, "off") {
		bad("filevault", High, "FileVault 没开：电脑丢了，硬盘上的东西能直接被读出来", "系统设置 → 隐私与安全性 → FileVault", nil)
	}
	if t, ok := probe("防火墙", "/usr/libexec/ApplicationFirewall/socketfilterfw", []string{"--getglobalstate"}); ok {
		if strings.Contains(t, "disabled") {
			bad("firewall", Medium, "防火墙没开", "系统设置 → 网络 → 防火墙", nil)
		} else if s, ok := probe("防火墙隐身模式", "/usr/libexec/ApplicationFirewall/socketfilterfw", []string{"--getstealthmode"}); ok &&
			strings.Contains(s, "stealth") && (strings.Contains(s, "off") || strings.Contains(s, "disabled")) {
			bad("stealth", Low, "防火墙的隐身模式没开：别人探测这台 Mac 时它会回应", "系统设置 → 网络 → 防火墙 → 选项，打开「启用隐身模式」", nil)
		}
	}
	if t, ok := probe("SIP", "/usr/bin/csrutil", []string{"status"}); ok && strings.Contains(t, "disabled") {
		bad("sip", High, "系统完整性保护（SIP）被关掉了", "需要在恢复模式里重新打开（螺壳会给出一步步的说明）", nil)
	}
	if t, ok := probe("Gatekeeper", "/usr/sbin/spctl", []string{"--status"}); ok && strings.Contains(t, "disabled") {
		bad("gatekeeper", High, "Gatekeeper 被关掉了：没签名的应用打开时不会再拦", "系统设置 → 隐私与安全性 → 安全性，「允许以下来源的应用程序」改回 App Store 和已知开发者", nil)
	}
	// Asking for the password when the screen locks; sysadminctl writes its answer to stderr.
	if t, ok := probe("锁屏", "/bin/sh", []string{"-c", "/usr/sbin/sysadminctl -screenLock status 2>&1"}); ok {
		how := "系统设置 → 锁定屏幕 →「屏幕保护程序启动或显示器关闭后需要密码」选「立即」"
		m := postureScreenDelay.FindStringSubmatch(t)
		secs, err := 0, error(nil)
		if m != nil {
			secs, err = strconv.Atoi(m[1])
		}
		if strings.Contains(t, "screenlock is off") {
			bad("screen-lock", Medium, "锁屏不要密码：你走开时别人能直接用这台 Mac", how, nil)
		} else if m != nil && err == nil && secs > 300 {
			bad("screen-lock-delay", Low, "屏保或关屏后 "+strconv.Itoa(secs/60)+" 分钟内不要密码", how, map[string]string{"delay_seconds": strconv.Itoa(secs)})
		} else if !strings.Contains(t, "screenlock delay is") {
			failed = append(failed, "锁屏")
		}
	}
	// No key means the default (on); `defaults` exits 1 then, which is not a failure.
	if _, autoCheck := command("/usr/bin/defaults", []string{"read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"}); postureTrim(autoCheck) == "0" {
		bad("autoupdate", Medium, "系统不会自动检查更新", "系统设置 → 通用 → 软件更新 → 自动更新", nil)
	}
	if boot, ok := bootTime(); ok {
		up := ctx.Now.Sub(boot)
		pending, _ := pendingUpdates()
		if up >= r.LongUptime && pending > 0 {
			days := strconv.Itoa(int(up.Seconds() / 86_400))
			bad("pending-updates", Low, "有 "+strconv.Itoa(pending)+" 个系统更新等着装，这台 Mac 已经 "+days+" 天没重启",
				"系统设置 → 通用 → 软件更新；重启也会释放交换文件", map[string]string{"uptime_days": days, "pending": strconv.Itoa(pending)})
		}
	}
	r.sharing(bad, probe, command)
	if d, ok := xprotectUpdated(); ok && ctx.Now.Sub(d) > r.XProtectStale {
		bad("xprotect-stale", Medium, "macOS 自带的恶意软件特征库（XProtect）"+strconv.Itoa(int(ctx.Now.Sub(d).Seconds()/86_400))+" 天没更新了",
			"系统设置 → 通用 → 软件更新 → 自动更新，打开「安装安全响应和系统文件」", map[string]string{"updated": ISODay(d)})
	}
	if len(failed) > 0 {
		joined := strings.Join(failed, "、")
		out = append(out, Finding{Rule: "posture.partial", Category: CatPosture, Severity: Low, Verdict: Info,
			Title: "有几样没查成：" + joined, Evidence: map[string]string{"skipped": joined}})
	}
	return out, nil
}

// sharing: what this Mac shares, who can log in to it, and which root certificates someone added. All read without a
// password: launchd's overrides, the login window's and AirDrop's settings, the trust settings.
func (r *PostureRule) sharing(bad func(string, Severity, string, string, map[string]string), probe func(string, string, []string) (string, bool),
	command func(string, []string) (int, string)) {
	if t, ok := probe("共享服务", "/bin/launchctl", []string{"print-disabled", "system"}); ok {
		on := postureEnabledServices(t)
		if on["com.openssh.sshd"] {
			bad("remote-login", Medium, "「远程登录」（SSH）开着：知道密码或有钥匙的人能从网络上登录这台 Mac",
				"不用的话：系统设置 → 通用 → 共享，关掉「远程登录」", nil)
		}
		if on["com.apple.screensharing"] {
			bad("screen-sharing", Medium, "「屏幕共享」或「远程管理」开着：别人能从网络上看到、操作这台 Mac",
				"不用的话：系统设置 → 通用 → 共享，关掉「屏幕共享」和「远程管理」", nil)
		}
		if on["com.apple.smbd"] {
			bad("file-sharing", Low, "「文件共享」开着：同一个网络里的人能看到共享出来的文件夹",
				"不用的话：系统设置 → 通用 → 共享，关掉「文件共享」", nil)
		}
		if on["com.apple.networksharing"] { // the probe gives its output lowercased
			bad("internet-sharing", Low, "「互联网共享」开着：这台 Mac 在把网络分给别的设备", "不用的话：系统设置 → 通用 → 共享，关掉「互联网共享」", nil)
		}
	}
	if _, airdrop := command("/usr/bin/defaults", []string{"read", "com.apple.sharingd", "DiscoverableMode"}); strings.ToLower(postureTrim(airdrop)) == "everyone" {
		bad("airdrop-everyone", Low, "隔空投送对所有人开着：附近任何人都能给你发东西", "控制中心 → 隔空投送，选「仅限联系人」", nil)
	}
	// No such key: nobody logs in by themselves (`defaults` exits 1, not a failure).
	if status, auto := command("/usr/bin/defaults", []string{"read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"}); status == 0 && postureTrim(auto) != "" {
		bad("auto-login", High, "开机自动登录：谁打开这台 Mac 都直接进到你的账户", "系统设置 → 用户与群组，「自动以此身份登录」选「关闭」", nil)
	}
	if _, guest := command("/usr/bin/defaults", []string{"read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"}); postureTrim(guest) == "1" {
		bad("guest", Low, "客人用户开着：不用密码就能登录这台 Mac", "不用的话：系统设置 → 用户与群组 → 客人用户，关掉", nil)
	}
	// Root certificates added by the user (or an administrator, -d): whoever holds the key can read HTTPS traffic.
	var certs []string
	for _, args := range [][]string{{"dump-trust-settings"}, {"dump-trust-settings", "-d"}} {
		_, text := command("/usr/bin/security", args)
		// The same certificate trusted for this user and for all users is one certificate.
		var add []string
		for _, c := range postureTrustedCerts(text) {
			if !postureContains(certs, c) {
				add = append(add, c)
			}
		}
		certs = append(certs, add...)
	}
	if len(certs) > 0 {
		shown := certs
		if len(shown) > 10 {
			shown = shown[:10]
		}
		sorted := append([]string{}, certs...)
		sort.Strings(sorted)
		bad("trusted-roots", Medium, "有 "+strconv.Itoa(len(certs))+" 个加进来的根证书被设成信任：用它的人能看到你的 HTTPS 内容",
			"认得的（公司的代理、自己开发用的 mkcert、抓包工具）就留着；不认得的在「钥匙串访问」里删掉，或把「信任」改回「使用系统默认」",
			// Keyed on which ones: one added later is a new finding, not hidden by a "以后别提" for these.
			map[string]string{"certs": strings.Join(shown, "；"), "_key": strings.Join(sorted, "|")})
	}
}

func postureContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
