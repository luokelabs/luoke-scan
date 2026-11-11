package service

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// What the user sees of a finding on a card or a page, for someone who does not know computers (负责人 11-06：
// 扫描的用户不是技术人员，看到茫茫多信息和技术细节会害怕). A short title with an app's or a file's name, never a
// path, a bundle id, a background task's label, a signature or a command; and one sentence: what it is, whether to
// bother. The rule's own title, its evidence and its 「怎么办」 stay in the report.

// placeName: the folder a path is in, as the Finder names it; empty when it is none of the usual ones.
func (s *Service) placeName(path string) string {
	shown := s.display(path) // ~/Downloads/… on this Mac and in a fake home alike
	for _, p := range []struct{ dir, name string }{{"Downloads", "下载"}, {"Desktop", "桌面"}, {"Documents", "文稿"},
		{"Pictures", "图片"}, {"Movies", "影片"}, {"Music", "音乐"}} {
		if strings.HasPrefix(shown, "~/"+p.dir+"/") {
			return p.name
		}
	}
	return ""
}

// appName: a readable name from a bundle id (com.example.SomeApp → SomeApp); the name itself when it is not one.
func appName(id string) string {
	id = strings.TrimSuffix(id, ".app")
	if i := strings.LastIndex(id, "."); i >= 0 && i < len(id)-1 && strings.Count(id, ".") >= 2 {
		id = id[i+1:]
	}
	return id
}

// startupAdvice: what a startup item does, and what to do about one the user doesn't know.
const startupAdvice = "开机后在后台自动运行。不认识可以移除。"

// An AI plugin's or instruction file's advice, in two lines that each fit one line of an item row where the core cuts
// texts (§4 maxLines), so what to do is never cut off: when it runs (never by itself, only while the AI tool uses it:
// the question users ask first) and what it can do then; what to do. Not 「if you didn't install it」 (a plugin mostly
// came along with the AI tool, and nobody remembers that).
const (
	skillRuns      = "不会自己运行；AI 用到它时能改动、删除或外传文件"
	pluginRuns     = "不会自己运行；用 Claude Code 时能改动、删除或外传文件" // its hooks run on Claude Code's own events
	agentFileRuns  = "不会自己运行；AI 在这个项目里写代码时才照着它做"
	skillStarts    = "本身不会自己运行，但 AI 用过它可能装上开机自启的程序" // found to set up what starts by itself
	agentFileStart = "本身不会自己运行，但 AI 照着做可能装上开机自启的程序"
	skillDo        = "不认识的建议移到废纸篓。"
	pluginDo       = "不认识的，在 Claude Code 里输入 /plugin 卸载。" // its plugin manager would put a deleted folder back
	agentFileDo    = "不是你自己写的就删掉。"
)

// startsThings: found to set up something that starts by itself (launchctl, LaunchAgents): it does not run by itself,
// but once used, what it set up does; 「不会自己运行」 alone would say the opposite of why it is reported.
func startsThings(f core.Finding) bool {
	if strings.HasSuffix(f.Rule, "."+string(core.SignalPersistence)) {
		return true
	}
	for _, k := range strings.Split(f.Evidence["kinds"], ",") {
		if k == string(core.SignalPersistence) {
			return true
		}
	}
	return false
}

// skillLines: an AI plugin's or instruction file's two lines: when it runs, what to do.
func skillLines(f core.Finding) (runs, do string) {
	file := f.Evidence["skill"] == "" && strings.HasPrefix(f.Rule, "agentfile")
	switch {
	case file && startsThings(f):
		runs, do = agentFileStart, agentFileDo
	case file:
		runs, do = agentFileRuns, agentFileDo
	case startsThings(f):
		runs, do = skillStarts, skillDo
	case pluginSkill(f):
		runs, do = pluginRuns, pluginDo
	default:
		runs, do = skillRuns, skillDo
	}
	if pluginSkill(f) {
		do = pluginDo
	}
	return runs, do
}

// skillGroupAdvice: one row of several plugins and instruction files. All of one kind: that kind's lines, of them all;
// of several kinds, lines that name no tool (a Codex skill is not uninstalled in Claude Code).
func skillGroupAdvice(fs []core.Finding) string {
	runs, dos := map[string]bool{}, map[string]bool{}
	starts, plugin := false, false
	for _, f := range fs {
		r, d := skillLines(f)
		runs[r], dos[d] = true, true
		starts = starts || startsThings(f)
		plugin = plugin || pluginSkill(f)
	}
	var r, d string
	for x := range runs {
		r = x
	}
	for x := range dos {
		d = x
	}
	if len(runs) > 1 {
		r = "不会自己运行；AI 工具用到它时能改动、删除或外传文件"
		if starts {
			r = skillStarts
		}
	}
	if len(dos) > 1 {
		d = "不认识的、不是你写的，就移到废纸篓。"
		if plugin {
			d = "不认识的移到废纸篓；Claude Code 的用 /plugin 卸载。"
		}
	}
	return strings.ReplaceAll(r, "它", "它们") + "\n" + d
}

// grantClient: who holds a grant, by name: an app's own name for a bundle id (io.gone.meet → meet), a program's file
// name for a path.
func grantClient(client string) string {
	if strings.HasPrefix(client, "/") {
		return itemName(fileName(client))
	}
	return appName(client)
}

// quoted: 「录屏」「辅助功能」 for 「录屏、辅助功能」.
func quoted(list string) string {
	var out string
	for _, g := range strings.Split(list, "、") {
		if g != "" {
			out += "「" + g + "」"
		}
	}
	return out
}

// grantAdvice: where a stale grant is taken away.
const grantAdvice = "在系统设置中选中它，点「−」移除。"

// fileName: a file's name as the user reads it (core.DisplayName: percent-encoded names decoded).
func fileName(path string) string { return core.DisplayName(path) }

// programName: a startup item by where its program is: the app it is in (the outermost 「….app」, the one the user
// installed: 「Jump Desktop Connect」 for /Applications/Jump Desktop Connect.app/Contents/MacOS/JumpConnect), else the
// program file's own name. Not by the job's label or a bundle id its plist claims: whoever installed the job wrote
// those (a job labelled 「com.google.keystone.agent」 would read as Google's), and a label's last part (「agent」
// 「service」「socket」) names no one. "" for macOS's own programs (an interpreter a job runs) and for none.
func programName(program string) string {
	if program == "" || core.IsSystemProgram(program) {
		return ""
	}
	if i := strings.Index(program, ".app/"); i >= 0 {
		return fileName(program[:i])
	}
	return fileName(strings.TrimSuffix(program, ".app"))
}

// keyboardName: the program a keyboard finding is about, by its file's name (the rule's title says what kind of
// program it is first); empty when the file is gone.
func keyboardName(f core.Finding) string {
	if f.Path == "" {
		return ""
	}
	return appName(strings.TrimSuffix(filepath.Base(f.Path), ".app"))
}

// plainSize: a size after a plain title, nothing for none.
func plainSize(b *int64) string {
	if b == nil || *b <= 0 {
		return ""
	}
	return sizeNote(b)
}

// plain: a finding's title and one sentence for the user.
func (s *Service) plain(f core.Finding) (string, string) {
	size := plainSize(f.Bytes)
	name := fileName(f.Path)
	where := s.placeName(f.Path)
	if where != "" {
		where += "里的"
	}
	switch {
	case f.Rule == "posture.filevault":
		return "硬盘没加密：电脑丢了，别人能直接读出里面的东西", "打开时会给你一个恢复密钥，抄下来放好。"
	case f.Rule == "posture.firewall":
		return "防火墙没开", "在系统设置 › 网络 › 防火墙里打开就好。"
	case f.Rule == "posture.screen-lock":
		return "锁屏不要密码：你走开时别人能直接用这台 Mac", "在系统设置 › 锁定屏幕里改成要密码。"
	case f.Rule == "posture.gatekeeper":
		return "Mac 自带的一道安全保护被关掉了", "在系统设置 › 隐私与安全性里，把「允许以下来源的应用程序」改回「App Store 与已知开发者」。"
	case f.Rule == "posture.sip":
		return "Mac 自带的一道安全保护被关掉了", "不是你自己关的话，要在恢复模式里打开：在 Apple 支持网站搜「系统完整性保护」，照着做。"
	case f.Rule == "cache.app" || f.Rule == "cache.electron":
		return f.Title + size, "删了不影响使用，它会重新生成；先退出它再清。"
	case f.Rule == "cache.logs":
		return f.Title + size, "只在查问题时用得上，不用了可以移到废纸篓。"
	case f.Rule == core.InstallScriptsRuleID:
		// What happens and what can go wrong, not 「会跑它的构建脚本」 (luoke-scan#152: read as a plain statement)
		title := f.Title
		if tool := f.Evidence["tool"]; tool != "" {
			title = tool + " 装软件时会自动运行里面的程序"
		}
		return title, "遇到恶意软件，装的时候就会中招。建议关闭，个别软件可能会装不上。"
	case f.Category == core.CatCache:
		return f.Title, "删了不影响使用，用到时会自己重新下载。"
	case f.Rule == "supplychain.malicious":
		advice := "装过就当密码和登录已经泄露：先把重要的密码都换掉；点「在访达里显示」看是哪个项目用了它，这个项目先别再打开。"
		if f.Evidence["packages"] != "" { // the ones past what is listed one by one, as one finding (no place to show)
			return "另外还有 " + f.Evidence["count"] + " 个已知的恶意软件包", "装过就当密码和登录已经泄露：先把重要的密码都换掉，用到它们的项目先别再打开。"
		}
		name := ""
		if p := f.Evidence["package"]; p != "" {
			name = "「" + p + "」"
		}
		if n := f.Evidence["count"]; n != "" && n != "1" {
			return "有 " + n + " 处装了已知的恶意软件包" + name, advice
		}
		return "装了一个已知的恶意软件包" + name, advice
	case isMalware(f): // apps.* and malware.odd-name are CatMalware too, but only signatures say 「病毒」
		return where + "「" + name + "」可能是病毒", "病毒库认出了它。建议移到废纸篓，先不要打开。"
	case f.Rule == "malware.odd-name":
		return where + "有个文件名字很怪，病毒扫描查不了它", "不认识就移到废纸篓；要留着就改个名，下一轮会查。"
	case strings.HasPrefix(f.Rule, "keyboard."):
		who := keyboardName(f)
		if who == "" {
			return "有个来路不明的程序能读到你按的每一个键", "认得就不用管；不认得的话，在「输入监控」里把它的开关关掉。"
		}
		return "「" + who + "」能读到你按的每一个键", "输入法、快捷键工具常这样；不认得就在「输入监控」里关掉它。"
	case strings.HasPrefix(f.Rule, "model.chat-template"): // CatSkill too
		return plainChatTemplate(f)
	case f.Category == core.CatSkill || strings.HasPrefix(f.Rule, "agentfile"):
		if sk := f.Evidence["skill"]; sk != "" {
			tool := f.Evidence["agent"]
			if tool == "" {
				tool = "AI 工具"
			} else {
				tool = "「" + tool + "」"
			}
			runs, do := skillLines(f)
			if pluginSkill(f) {
				return "Claude Code 的插件「" + sk + "」能操作你的电脑", runs + "\n" + do
			}
			return tool + "的插件「" + sk + "」能操作你的电脑", runs + "\n" + do
		}
		runs, do := skillLines(f)
		if strings.HasPrefix(f.Rule, "agentfile") && name != "." && name != "" {
			return "「" + name + "」会让 AI 写代码的工具运行命令", runs + "\n" + do
		}
		return "AI 工具里有个插件能操作你的电脑", runs + "\n" + do
	case f.Rule == "mcp.secrets" || strings.HasPrefix(f.Rule, "secrets.") || strings.HasPrefix(f.Rule, "exposure."):
		return "有密码或密钥直接放在文件里，别人可能看得到", "换个地方存，或者把这个密码改掉。"
	case f.Rule == "leftover.installer":
		return "已经装好的应用留下的安装包" + size, "用不到了，移到废纸篓就好。"
	case f.Rule == "leftover.partial-download":
		return "没下载完的文件" + size, "用不到了，移到废纸篓就好。"
	case f.Category == core.CatLeftover:
		app := appName(f.Evidence["bundle_id"])
		if app == "" {
			app = appName(name)
		}
		return "已经删掉的应用「" + app + "」留下的数据" + size, "不用了可以移到废纸篓，随时能放回。"
	case f.Category == core.CatLeak:
		return "程序用完没删的临时文件" + size, "移到废纸篓不影响使用，随时能放回。"
	case f.Rule == "stale.project":
		return "很久没动过的项目「" + name + "」" + size, "代码已经存在网上的，删了也找得回；拿不准就先别动。"
	case strings.HasPrefix(f.Rule, "browser."): // before persistence: forced extensions and native hosts are CatPersistence
		return "浏览器里有个来路不明的扩展", "不认识的话，在浏览器的扩展设置里删掉。"
	case f.Rule == "persistence.daemon-missing" || f.Rule == "persistence.path-missing" || f.Rule == "persistence.cron-missing":
		return "已经删掉的程序留下的开机启动项", "移到废纸篓不影响使用。"
	case f.Evidence["submitted"] == "1": // handed to launchd by a running program: gone after a restart
		if nm := s.shortName(f); nm != "" && nm != "." {
			return "「" + nm + "」在后台起的程序", "重启以后不会再自己起来。不认识的话，在访达里看看它是哪个程序。"
		}
		return "有个程序在后台运行", "重启以后不会再自己起来。不认识的话，在访达里看看它是哪个程序。"
	case f.Category == core.CatPersistence || strings.HasPrefix(f.Rule, "startup."):
		if nm := s.shortName(f); nm != "" && nm != "." {
			return "会跟着电脑一起启动的「" + nm + "」", startupAdvice
		}
		return "有个会跟着电脑一起启动的程序", startupAdvice
	case f.Rule == "space.ai-model" || f.Rule == "space.ai-models":
		return "很久没用的 AI 模型" + size, "用不到了可以删，再用时会重新下载。"
	case f.Category == core.CatPermission:
		return "已删除的「" + grantClient(f.Path) + "」仍有" + quoted(f.Evidence["grants"]) + "权限", grantAdvice
	case f.Category == core.CatProcess:
		if nm := appName(filepath.Base(f.Path)); f.Rule == "process.deleted-binary" && nm != "" && nm != "." {
			return "「" + nm + "」已经删掉了却还在运行", "重启一下电脑就好。"
		}
		return "有个程序已经删掉了却还在运行", "重启一下电脑就好。"
	case strings.HasPrefix(f.Rule, "apps."):
		return "最近装的「" + appName(strings.TrimSuffix(name, ".app")) + "」来路不明", "确认是你自己装的就好；不认识就移到废纸篓。"
	case f.Category == core.CatVitals:
		return f.Title, vitalsAdvice(f)
	}
	return f.Title, ""
}

// lookGroup: findings that say the same thing to the user (several apps signed by nobody, several apps' leftover
// data): one line on the page with their names, not one row each (负责人 11-06).
type lookGroup struct {
	key      string
	findings []core.Finding
}

func groupKey(f core.Finding) string {
	switch {
	case f.Category == core.CatLeftover && f.Rule != "leftover.installer" && f.Rule != "leftover.partial-download":
		return "leftover"
	case strings.HasPrefix(f.Rule, "model.chat-template"):
		return "model.chat-template"
	case f.Category == core.CatSkill || strings.HasPrefix(f.Rule, "agentfile"):
		return "skill"
	case f.Rule == "mcp.secrets" || strings.HasPrefix(f.Rule, "secrets.") || strings.HasPrefix(f.Rule, "exposure."):
		return "secrets"
	case strings.HasPrefix(f.Rule, "apps."):
		return "apps"
	case strings.HasPrefix(f.Rule, "cache.rebuildable.") && f.Evidence["tool"] != "":
		return "cache/" + f.Evidence["tool"] // one tool's caches in one line (Cargo's downloads and their sources)
	}
	return f.Rule
}

func groupLook(fs []core.Finding) []lookGroup {
	var out []lookGroup
	at := map[string]int{}
	for _, f := range fs {
		k := groupKey(f)
		if i, ok := at[k]; ok {
			out[i].findings = append(out[i].findings, f)
			continue
		}
		at[k] = len(out)
		out = append(out, lookGroup{key: k, findings: []core.Finding{f}})
	}
	return out
}

// shortName: what to call one finding in a group's list of names.
func (s *Service) shortName(f core.Finding) string {
	switch {
	case f.Category == core.CatLeftover && f.Evidence["bundle_id"] != "":
		return appName(f.Evidence["bundle_id"])
	case strings.HasPrefix(f.Rule, "model.chat-template") && f.Evidence["model"] != "":
		return modelShortName(f.Evidence["model"])
	case f.Evidence["skill"] != "":
		return f.Evidence["skill"]
	case f.Category == core.CatPersistence && f.Evidence["app"] != "": // the app Login Items lists it under
		return f.Evidence["app"]
	case programName(f.Evidence["program"]) != "":
		return programName(f.Evidence["program"])
	case f.Evidence["label"] != "":
		return appName(f.Evidence["label"]) // a job that runs one of macOS's own programs: only its label is left
	case f.Category == core.CatLeak && f.Evidence["prefix"] != "":
		if tool, ok := core.AutoKnownTemp[f.Evidence["prefix"]]; ok {
			return tool
		}
		return f.Evidence["prefix"]
	case f.Rule == "leftover.installer" && (f.Evidence["installed"] != "" || f.Evidence["exact"] != ""):
		if app := f.Evidence["installed"]; app != "" { // the app it installs, not 「oMLX-0.7.3.dmg」
			return app
		}
		return f.Evidence["exact"]
	}
	return itemName(fileName(f.Path))
}

// itemName: what to call a file or an app by its name: an app without 「.app」, a bundle id's last part
// (com.example.SomeApp → SomeApp), any other name as it is: a file name with several dots stays whole (never just
// 「dmg」 of 「oMLX-0.7.3.dmg」).
func itemName(name string) string {
	name = strings.TrimSuffix(name, ".app")
	if looksLikeBundleID(name) {
		return appName(name)
	}
	return name
}

// looksLikeBundleID: reverse-DNS like com.example.SomeApp: three or more parts, each starting with a letter, no
// spaces, and not ending in a file's extension.
func looksLikeBundleID(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 3 || strings.ContainsAny(name, " /") || fileExtensions[strings.ToLower(parts[len(parts)-1])] {
		return false
	}
	for _, p := range parts {
		if p == "" || !unicode.IsLetter([]rune(p)[0]) {
			return false
		}
	}
	return true
}

// fileExtensions: the last part of a name that makes it a file's, not a bundle id's.
var fileExtensions = map[string]bool{}

func init() {
	for _, e := range strings.Fields(`dmg pkg mpkg xip zip gz tgz bz2 xz 7z rar tar iso img app plist json yaml yml toml txt md
		pdf doc docx xls xlsx ppt pptx key pages numbers csv log db sqlite mov mp4 m4v avi mkv mp3 m4a wav flac jpg jpeg png
		gif heic webp tiff psd svg html js ts py sh command scpt exe msi bin`) {
		fileExtensions[e] = true
	}
}

// nameList: names in quotes joined by 、, the first max of them and 「等」 after the last when there are more:
// 「「A」、「B」、「C」、「D」等」.
func nameList(names []string, max int) string {
	if len(names) > max {
		return strings.Join(names[:max], "、") + "等"
	}
	return strings.Join(names, "、")
}

// plainGroup: a group's line and its one sentence; one finding is drawn as plain says.
func (s *Service) plainGroup(g lookGroup) (string, string, string) {
	if len(g.findings) == 1 {
		t, a := s.plain(g.findings[0])
		return t, a, ""
	}
	n := len(g.findings)
	var names []string
	seen := map[string]bool{}
	var total int64
	programs := 0 // the kinds counted in programs (「有 N 个程序…」): one program with several items is one, as its chip
	for _, f := range g.findings {
		nm := s.shortName(f)
		if nm == "" || !seen[nm] {
			programs++
		}
		if nm != "" && !seen[nm] {
			seen[nm] = true
			names = append(names, "「"+nm+"」")
		}
		if f.Bytes != nil {
			total += *f.Bytes
		}
	}
	nameLine := nameList(names, 4)
	size := plainSize(&total)
	f := g.findings[0]
	_, advice := s.plain(f)
	advice = strings.Replace(strings.Replace(advice, "把它", "把它们", 1), "选中它，", "选中它们，", 1) // 说的是好几个
	switch g.key {
	case "leftover":
		return fmt.Sprintf("%d 个已经删掉的应用留下了数据%s", n, size), advice, nameLine
	case "apps":
		return fmt.Sprintf("%d 个最近装的应用来路不明", n), advice, nameLine
	case "skill":
		return fmt.Sprintf("%d 个 AI 插件能操作你的电脑", n), skillGroupAdvice(g.findings), nameLine
	case "model.chat-template":
		return fmt.Sprintf("本机模型的对话模板里多了给模型的话，一共 %d 项", n),
			"每次和它们对话都会悄悄带上这些话，可能让它们瞒着你或把回答带偏。删掉这些模型，从可信的地方重新下载。" + templateKinds(g.findings), nameLine
	case "secrets":
		return fmt.Sprintf("有 %d 处密码或密钥直接放在文件里，别人可能看得到", n), advice, ""
	case "persistence.daemon-missing", "persistence.path-missing", "persistence.cron-missing":
		return fmt.Sprintf("%d 个已经删掉的程序留下的开机启动项", n), advice, ""
	case "permission.stale-grant":
		return fmt.Sprintf("%d 个已删除的应用仍有权限", n), strings.Replace(grantAdvice, "选中它", "选中它们", 1), nameLine
	case "vitals.cpu":
		return fmt.Sprintf("有 %d 个程序一直占满处理器，可能卡住了", programs), strings.Replace(advice, "它", "它们", -1), nameLine
	// what a plan can clean, when a kind of it is one row (planGroups): the kind, not the first one's own title
	case "stale.large-file":
		return fmt.Sprintf("%d 个很久没打开过的大文件%s", n, size), advice, nameLine
	case "stale.project":
		return fmt.Sprintf("%d 个很久没动过的项目%s", n, size), advice, nameLine
	case "stale.artifacts":
		return fmt.Sprintf("%d 个项目里能重新生成的文件%s", n, size), advice, nameLine
	case "space.duplicates":
		return fmt.Sprintf("%d 组重复的文件%s", n, size), advice, nameLine
	}
	// The kinds whose one-item title names it (「『Claude』的缓存」): with several names the line says what kind they are,
	// their names in the line under it, not one of them as if all were it. With one name, its title as before.
	if len(names) > 1 {
		switch {
		case f.Rule == "cache.app" || f.Rule == "cache.electron":
			return fmt.Sprintf("几个应用的缓存，一共 %d 项%s", n, size), "删了不影响使用，它们会重新生成；先退出这些应用再清。", nameLine
		case f.Rule == "cache.logs":
			return fmt.Sprintf("几个应用的日志，一共 %d 项%s", n, size), advice, nameLine
		case f.Rule == core.InstallScriptsRuleID:
			return fmt.Sprintf("%d 个工具装软件时会自动运行里面的程序", n), advice, nameLine
		case strings.HasPrefix(f.Rule, "keyboard."):
			return fmt.Sprintf("有 %d 个程序能读到你按的每一个键", programs), "输入法、快捷键工具常这样；不认得的就在「输入监控」里关掉。", nameLine
		case isMalware(f):
			return fmt.Sprintf("%d 个文件可能是病毒", n), "病毒库认出了它们。建议移到废纸篓，先不要打开。", nameLine
		case f.Rule == "supplychain.malicious":
			return fmt.Sprintf("有 %d 处装了已知的恶意软件包", n), advice, nameLine
		case f.Category == core.CatProcess:
			return fmt.Sprintf("有 %d 个程序已经删掉了却还在运行", programs), advice, nameLine
		}
	}
	if tool, ok := strings.CutPrefix(g.key, "cache/"); ok {
		return fmt.Sprintf("%s 的缓存 %d 项%s，删了会自动重建", tool, n, size), advice, ""
	}
	if strings.HasPrefix(f.Rule, "browser.") {
		return fmt.Sprintf("浏览器里有 %d 个来路不明的扩展", n), advice, nameLine
	}
	if f.Category == core.CatPersistence || strings.HasPrefix(f.Rule, "startup.") {
		return fmt.Sprintf("有 %d 个会跟着电脑一起启动的程序", programs), advice, nameLine
	}
	// The first one's title without its own size, then how many and their size together (luoke-scan#129: not 「安装包
	// （246.1 MB），一共 41 项」 with the first one's size)
	bare := f
	bare.Bytes = nil
	t, _ := s.plain(bare)
	return fmt.Sprintf("%s，一共 %d 项%s", t, n, size), advice, nameLine
}

// lookSkillAdvice: the short line under 「要你看看」 for AI plugins and instruction files, of all of the row's (not the
// first one's: a Codex skill is not uninstalled in Claude Code). It first says they do not run by themselves (the
// question users ask first), unless one was found to set up what starts by itself (that would say the opposite of why
// it is reported; the line then says only what to do); then what to do: a Claude Code plugin is uninstalled there,
// the rest deleted.
func lookSkillAdvice(fs []core.Finding) string {
	starts := false
	plugins, files, others := 0, 0, 0
	for _, f := range fs {
		starts = starts || startsThings(f)
		switch {
		case pluginSkill(f):
			plugins++
		case f.Evidence["skill"] == "" && strings.HasPrefix(f.Rule, "agentfile"):
			files++
		default:
			others++
		}
	}
	runs := "不会自己运行；"
	if starts {
		runs = ""
	}
	switch {
	case plugins > 0 && files+others == 0:
		return runs + "不是你装的，就在 Claude Code 里用 /plugin 卸掉"
	case plugins > 0:
		return runs + "不是你装的就删掉，Claude Code 的用 /plugin 卸掉"
	case others == 0:
		return runs + "不是你写的就删掉"
	}
	return runs + "不是你装的就删掉"
}

// lookAdvice: what to do about a kind under 「要你看看」, in one short line as in the design (luoke-brand
// ui/issues/2026-11-09-scan; 负责人 11-11): 「不认识的可以关掉开机启动」「不是你装的就删掉」「应用已经删了，权限可以
// 一起移除」, and the same for the kinds the design does not show. advice: plain's longer one, for a kind with no short
// line. Not for steps to take at once (a known malicious package, a deleted program that starts again): those are
// read whole as they are.
func lookAdvice(g lookGroup, advice string) string {
	f := g.findings[0]
	switch {
	case f.Rule == "posture.filevault":
		return "打开时会给你恢复密钥，抄下来放好"
	case f.Rule == "posture.firewall":
		return "在系统设置的「网络」里打开防火墙"
	case f.Rule == "posture.screen-lock":
		return "在「锁定屏幕」里改成要密码"
	case f.Rule == "posture.gatekeeper":
		return "改回只允许 App Store 与已知开发者的应用"
	case f.Rule == "posture.sip":
		return "不是你关的，就在恢复模式里打开"
	case f.Rule == core.InstallScriptsRuleID:
		return "建议关掉，个别软件可能会装不上"
	case f.Rule == "malware.odd-name":
		return "不认识就删掉，要留着就改个名"
	case strings.HasPrefix(f.Rule, "keyboard."):
		return "不认识的就在「输入监控」里关掉"
	case strings.HasPrefix(f.Rule, "model.chat-template"):
		return "不是你改的就删掉，从可信的地方重新下载"
	case f.Category == core.CatSkill || strings.HasPrefix(f.Rule, "agentfile"):
		return lookSkillAdvice(g.findings)
	case g.key == "secrets":
		return "换个地方存，或者改掉这个密码"
	case f.Rule == "browser.native-host":
		return "不认识的扩展可以移除"
	case strings.HasPrefix(f.Rule, "browser."):
		return "不是你装的就在浏览器里移除"
	case f.Rule == "persistence.daemon-missing" || f.Rule == "persistence.path-missing" || f.Rule == "persistence.cron-missing":
		return "程序已经删了，启动项可以移除"
	case f.Category == core.CatPersistence && f.Evidence["scope"] == "cron":
		return "不认识的定时任务可以删掉"
	case f.Category == core.CatPersistence || strings.HasPrefix(f.Rule, "startup."):
		return "不认识的可以关掉开机启动"
	case f.Category == core.CatPermission:
		return "应用已经删了，权限可以一起移除"
	case f.Category == core.CatProcess:
		return "重启一下电脑就好"
	case strings.HasPrefix(f.Rule, "apps."):
		return "不是你装的就删掉"
	case f.Rule == "vitals.cpu":
		return "不是在做你交给它的事，多半是卡住了，可以退出它"
	case f.Rule == "vitals.memory":
		return "关掉暂时不用的程序和网页标签"
	case f.Rule == "vitals.battery":
		return "用起来明显不够时，可以去 Apple 换电池"
	case f.Rule == "vitals.thermal":
		return "让它歇一会儿，别挡住出风口"
	case f.Category == core.CatLeak:
		return "多是测试留下的，可以清掉"
	}
	return advice
}

// planLines: an item of the clean-up plan on the scan page: what it is (an app's or a file's name, its size) and one
// line that tells it apart from the next (the file's name, how many, how long it has not been opened). A file's name is
// fine; a path, a rule name or a bundle id is not (负责人 11-09 on luoke-scan#129). "" detail when there is nothing to add.
func (s *Service) planLines(f core.Finding) (string, string) {
	size := plainSize(f.Bytes)
	name := fileName(f.Path)
	ev := f.Evidence
	switch {
	case f.Rule == "leftover.installer":
		app := ev["installed"]
		if app == "" {
			app = ev["exact"]
		}
		var detail []string
		if d := ev["days"]; d != "" {
			detail = append(detail, d+" 天前下载")
		}
		if app == "" {
			return "安装包「" + name + "」" + size, strings.Join(detail, "，")
		}
		detail = append(detail, app+" 已经装好了")
		return app + " 的安装包" + size, name + " · " + strings.Join(detail, "，")
	case f.Category == core.CatLeak && ev["prefix"] != "":
		who := ev["prefix"]
		if tool, ok := core.AutoKnownTemp[who]; ok {
			who = tool
		}
		return who + " 留下的临时文件夹" + size, ev["count"] + " 个 " + ev["prefix"] + "-*，在系统临时目录里"
	case f.Rule == "space.duplicates":
		n := len(strings.Split(ev["copies"], "；")) + 1 // the one kept and its copies
		if ev["copies"] == "" || f.Bytes == nil {
			break
		}
		return name + size, fmt.Sprintf("%d 份一样的，每份 %s", n, core.FormatBytes(*f.Bytes/int64(n-1)))
	case f.Rule == "stale.large-file":
		if d := ev["last_opened"]; d != "" {
			return name + size, s.ago(d) + "没打开过"
		}
		if ev["never_opened"] != "" {
			return name + size, "没打开过，" + s.ago(ev["last_changed"]) + "前放进来的"
		}
		return name + size, ""
	case f.Rule == "space.ai-model" && ev["model"] != "":
		title := ev["model"] + size
		if ev["tool"] != "" {
			title = ev["tool"] + " 的模型 " + title
		}
		if d := ev["downloaded"]; d != "" {
			return title, s.ago(d) + "前下载"
		}
		return title, ""
	case f.Rule == "leftover.partial-download":
		return "没下载完的「" + name + "」" + size, ""
	case f.Rule == core.InstallScriptsRuleID || f.Category == core.CatPersistence || strings.HasPrefix(f.Rule, "startup.") || f.Category == core.CatSkill:
		// What it is and what it does, under the title: the title alone (「会跟着电脑一起启动的「daily」」「pip 装源码包时会跑
		// 它的构建脚本」) read as a bare statement (luoke-scan#152)
		return s.plain(f)
	}
	t, _ := s.plain(f)
	return t, ""
}

// ago: how long ago a day (2006-01-02) was, as the page says it: 「37 天」「5 个月」「7 年多」 (at least 「1 天」, so
// 「1 天前下载」 still reads); the day itself when it is not a day.
func (s *Service) ago(day string) string {
	t, err := time.ParseInLocation("2006-01-02", day, time.Local)
	if err != nil {
		return day
	}
	days := int(s.now().Sub(t).Hours() / 24)
	switch {
	case days < 1:
		return "1 天"
	case days < 60:
		return fmt.Sprintf("%d 天", days)
	case days < 2*365:
		return fmt.Sprintf("%d 个月", days/30)
	}
	return fmt.Sprintf("%d 年多", days/365)
}

// plainChatTemplate: a local model whose chat template has words to the model its family's does not (luoke-scan#79).
// The model's name, nothing of the template; one thing to do, and 「在访达里显示」 (listButtons) to find it.
func plainChatTemplate(f core.Finding) (string, string) {
	name := modelShortName(f.Evidence["model"])
	if name == "" { // the round's note that some were not looked at
		return f.Title, ""
	}
	what := "多了一段给模型的话"
	if f.Evidence["kinds"] == string(core.TplHidden) {
		what = "藏着看不见的字符"
	}
	return "本机模型「" + name + "」的对话模板里" + what,
		"每次和它对话都会悄悄带上这段，可能让它瞒着你或把回答带偏。删掉这个模型，从可信的地方重新下载。" + templateKinds([]core.Finding{f})
}

// templateKindShort: a kind in two to six words, for the line under the title.
var templateKindShort = map[core.TemplateKind]string{core.TplExfil: "外发对话内容", core.TplConceal: "对你隐瞒",
	core.TplIgnore: "绕过原有指令", core.TplImpersonate: "冒充系统", core.TplSteer: "夹带推荐"}

// templateKinds: what the extra words do, in the rule's words, all the models' together: 「\n多出来的话会：让模型瞒着你或骗你、…。」;
// "" when nothing but invisible characters.
func templateKinds(fs []core.Finding) string {
	seen := map[string]bool{}
	var out []string
	for _, k := range []core.TemplateKind{core.TplExfil, core.TplConceal, core.TplIgnore, core.TplImpersonate, core.TplSteer} {
		for _, f := range fs {
			if !seen[string(k)] && strings.Contains(","+f.Evidence["kinds"]+",", ","+string(k)+",") {
				seen[string(k)] = true
				out = append(out, templateKindShort[k])
			}
		}
	}
	if len(out) == 0 {
		return ""
	}
	return "\n包含：" + strings.Join(out, "、") + "。"
}

// modelShortName: a model's own name without its publisher (Qwen/Qwen2.5-7B-Instruct → Qwen2.5-7B-Instruct).
func modelShortName(model string) string {
	if i := strings.LastIndex(model, "/"); i >= 0 {
		return model[i+1:]
	}
	return model
}
