package service

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// 「状态」 (luoke-scan#124): how this Mac stands, at a glance, as Stats does — the disk, the folders that take the
// most, the big things, what the scanner may read, the security settings. Only to look at: no clearing here (that is
// the overview's). What the last round found, plus the disk's free space read now.
const (
	macMaxFolders = 8
	macMaxBig     = 5
)

// macFolderNames: the folders the space rule measures, as people call them (relative to home).
var macFolderNames = map[string]string{
	"Desktop": "桌面", "Documents": "文稿", "Downloads": "下载", "Movies": "影片", "Music": "音乐", "Pictures": "图片",
	"Public": "公共", "Applications": "自己装的应用", "Library/Caches": "应用的缓存", "Library/Application Support": "应用的数据",
	"Library/Containers": "应用的数据（沙盒里的）", "Library/Developer": "开发工具的数据", "Library/Mail": "邮件",
	"Library/Messages": "信息", "Library/Photos": "照片的数据", "Library/Mobile Documents": "iCloud 云盘", ".cache": "命令行工具的缓存",
	".local/share": "命令行工具的数据", ".Trash": "废纸篓", ".ollama": "Ollama 的模型", ".docker": "Docker 的数据",
	"Library/Group Containers": "几个应用共用的数据", "Library/Logs": "日志", "Library/Saved Application State": "应用记下的窗口",
	"Library/Fonts": "字体", "Library/Safari": "Safari 的数据", "Library/Calendars": "日历", "Library/Metadata": "系统的索引",
}

// macDevCaches: tools whose caches are folded into one line 「开发工具的缓存」 (a non-technical reader need not tell
// pip from uv): the folder's last part under ~/.cache, ~/Library/Caches, or home.
var macDevCaches = map[string]bool{"pip": true, "pypoetry": true, "uv": true, "go-build": true, ".npm": true, "npm": true,
	".bun": true, "bun": true, "yarn": true, "Yarn": true, "pnpm": true, ".pnpm-store": true, ".cargo": true, ".rustup": true,
	".gradle": true, ".m2": true, "Homebrew": true, "node-gyp": true, "ms-playwright": true, "puppeteer": true, "ccache": true,
	"Xcode": true, "CocoaPods": true, ".cocoapods": true, "deno": true, ".deno": true, "huggingface": true}

// macSecurity: the settings the posture rule checks, in the order the page lists them: the line (as macOS's Settings
// calls it), the rule's id, the probe's name in 「有几样没查成」 ("" when it has no probe of its own).
var macSecurity = []struct{ label, rule, probe string }{
	{"硬盘加密（文件保险箱）", "filevault", "FileVault"},
	{"防火墙", "firewall", "防火墙"},
	{"系统完整性保护", "sip", "SIP"},
	{"只打开来路清楚的应用", "gatekeeper", "Gatekeeper"},
	{"锁屏要密码", "screen-lock", "锁屏"},
	{"自动检查系统更新", "autoupdate", ""},
}

// macBigRules: the findings that are one big thing on the disk (a file, a virtual disk, a model, snapshots).
var macBigRules = map[string]bool{"stale.large-file": true, "space.vm-disk": true, "space.ai-model": true, "space.ipsw": true,
	"space.xcode-archives": true, "space.simulators": true}

func (s *Service) macPage(c *Card, st State) {
	r := s.Store.LastReport()
	free, total, diskKnown := int64(0), int64(0), false
	if s.Config.Volume != nil {
		free, total, diskKnown = s.Config.Volume(s.Config.Context.Home)
		diskKnown = diskKnown && total > 0
	}
	var f []core.Finding
	if r != nil {
		f = s.visible(*r, st)
	}
	fda := s.permissionStates(st)["fda"]
	// 两件事分开（11-09 本机开发版：重新打包以后权限没了，页面说「没允许」，列表里却是上一轮量到的文稿、下载）：
	// full 是上一轮实际查到了没有，管这一轮的数说了什么；fda 是现在给没给，管第一屏的提示和权限那一行
	full := r != nil && roundHadFullAccess(*r)
	security := s.macSecurityLines(r)
	off := 0
	for _, l := range security {
		if l.state == macOff {
			off++
		}
	}
	big := macBig(f)

	// 顶上三个数：一样宽（窗口的 spaceEvenly）
	stats := []Stat{}
	if diskKnown {
		stats = append(stats, Stat{"硬盘还剩", macSize(free)})
	}
	if r != nil {
		switch {
		case !full:
			stats = append(stats, Stat{macBigKey, "没查全"}) // 下载、文稿、桌面没查：不写「没有」（设计评审 r1）
		case len(big) == 0:
			stats = append(stats, Stat{macBigKey, "没有"})
		default:
			stats = append(stats, Stat{macBigKey, fmt.Sprintf("%d 个", len(big))})
		}
		key := "安全设置"
		if failed := countState(security, macFailed); failed > 0 {
			key = fmt.Sprintf("安全设置（%d 项没查成）", failed) // 没查到的也写在顶上（设计评审 r2、r3）
		}
		if off > 0 {
			stats = append(stats, Stat{key, fmt.Sprintf("%d 项没开启", off)})
		} else {
			stats = append(stats, Stat{key, "查到的都已开启"})
		}
	}
	c.Stats(stats)
	if r == nil {
		c.Text("还没查过这台 Mac。查过一轮，这里会写哪些文件夹占地方、有哪些大文件、安全设置开没开。", true)
		c.Buttons([]Button{{Label: "现在查一下", Event: "scan_now", Primary: true}})
	} else {
		// 照常见工具的写法（负责人 11-09）：只写上次扫描的时间；硬盘还剩多少是现在的数，和系统的「储存空间」一样不写时间
		when := "上次扫描：" + localTime(r.StartedAt.Time) + strings.TrimSpace(s.agoNote(r.StartedAt.Time))
		if s.IsScanning() {
			c.Text(when, true)
		} else {
			c.ButtonsAfter(when, []Button{{Label: "现在查一下", Event: "scan_now"}}) // 和「概览」同一个按钮：查，不清理
		}
	}
	if s.IsScanning() { // 正在查的这一轮：一行带进度条，查完了上面的数换成新的（负责人 11-09，luoke-scan#101）
		what, frac := s.scanProgress(r)
		c.Line("正在查这台 Mac", what, frac)
	}
	if r != nil && fda != "granted" {
		c.ButtonsAfter("没允许完全磁盘访问："+macUnseen+"查不了。给「螺壳」打开开关以后，回来点「现在查一下」。", []Button{fdaButton})
	}

	// 硬盘（段标题只管一行就不要了：设计评审 r2）
	c.Divider()
	if diskKnown {
		used := total - free
		c.Line("硬盘", fmt.Sprintf("用了 %s，一共 %s", macSize(used), macSize(total)), float64(used)/float64(total))
	} else {
		c.Line("硬盘", "读不到这块硬盘的大小", -1)
	}
	if folders, sum := s.macFolders(); len(folders) > 0 {
		c.Divider()
		head := "占地方最多的文件夹"
		if !full {
			head += "（不含" + macUnseen + "）"
		}
		c.Text(head, true)
		for _, l := range folders { // 条是占列出来的合计的多少：第一行不会是满条，不像「满了」（设计评审 r3）
			c.Line(l.name, l.size, float64(l.bytes)/float64(sum))
		}
		switch {
		case !full: // 没查的地方不下结论（设计评审 r2 的阻碍项）
			c.Text("这些加起来约 "+macApprox(sum)+"。"+macUnseen+"没查，那里有多大还不知道。", true)
		case diskKnown && total-free > sum:
			c.Text("这些加起来约 "+macApprox(sum)+"。其余是没列出来的小文件夹，以及系统和应用本身。", true)
		}
	}
	c.Divider()
	c.Text("一年多没打开过的大文件", true)
	if min := s.macBigMin(); min > 0 {
		c.Text(macApprox(min)+" 以上算大文件，按大小排", true) // 多大算「大」写出来（设计评审 r4），整数
	}
	switch {
	case r == nil:
		c.Text("查过一轮才知道。", true)
	case len(big) == 0 && !full:
		c.Text(macUnseen+"没查；别的地方没找到一年多没打开过的大文件。", true)
	case len(big) == 0:
		c.Text("没找到一年多没打开过的大文件。", true)
	}
	if len(big) > 0 {
		for i, x := range big {
			if i >= macMaxBig {
				c.Text(fmt.Sprintf("共 %d 个，这里列最大的 %d 个；全部在「概览」里", len(big), macMaxBig), true)
				break
			}
			var buttons []Button
			if x.Path != "" {
				buttons = []Button{{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(x)}}}
			}
			c.LineButtons(s.macBigName(x), macSize(*x.Bytes), buttons)
		}
	}

	// 权限
	c.Divider()
	c.Text("权限", true)
	switch fda {
	case "granted":
		c.Line("完全磁盘访问", "已允许", -1) // 一行放得下名字：查不了哪些在第一屏说（设计评审 r6）
	case "denied":
		c.LineButtons("完全磁盘访问", "没允许", []Button{fdaButton})
	default:
		c.Line("完全磁盘访问", "还不知道，查过一轮才知道", -1)
	}
	stale := 0
	for _, x := range f {
		if x.Rule == "permission.stale-grant" {
			stale++
		}
	}
	switch {
	case !full:
		c.Line("已经删掉的应用还拿着权限", "没查成，要先允许完全磁盘访问", -1) // 权限的记录要完全磁盘访问才读得到
	case stale == 0:
		c.Line("已经删掉的应用还拿着权限", "没有", -1)
	default:
		c.Line("已经删掉的应用还拿着权限", fmt.Sprintf("%d 个", stale), -1)
		c.Text("要收回，去「概览」看。", true)
	}

	// 安全设置：没开的、没查成的排在前面；一个图标一种状态（形状不同，不只靠颜色）
	c.Divider()
	c.Text("安全设置", true)
	sort.SliceStable(security, func(i, j int) bool { return macRank[security[i].state] < macRank[security[j].state] })
	for _, l := range security {
		c.StateLine(l.label, macIcon[l.state], l.state, l.state != macOn)
	}
	if off > 0 {
		c.Text("没开启的怎么打开，在「概览」的「要你看看的」里有写。", true)
	}
	if failed := len(security) - off - countState(security, macOn); failed > 0 {
		c.Text("没查成的，下次扫描或点上面的「现在查一下」时会再查。", true)
	}
}

// The three states, all three characters long so the icons before them stand in one column (design review r2).
const (
	macOn     = "已开启"
	macOff    = "没开启"
	macFailed = "没查成"
)

// macBigKey: the big files' number at the top, worded as the section is (「3 个」 is not every big file on the Mac).
const macBigKey = "一年多没打开过的大文件"

var fdaButton = Button{Label: "打开「完全磁盘访问」设置", Event: "scan_open_settings", Context: O{"grant": fdaGrant}}

// macApprox: a total said roughly (「约 621 MB」): whole numbers, so it does not disagree with the rows by a rounding.
func macApprox(b int64) string {
	s := macSize(b)
	if i := strings.Index(s, "."); i > 0 && b >= 1000 {
		return s[:i] + s[i+2:]
	}
	return s
}

// macSize: a size with one decimal always (「21.0 MB」), so a column of them lines up.
func macSize(b int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(b)
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", b)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

var macRank = map[string]int{macOff: 0, macFailed: 1, macOn: 2}
var macIcon = map[string]string{macOn: "check", macOff: "warning", macFailed: "question"}

func countState(lines []macSecurityLine, state string) int {
	n := 0
	for _, l := range lines {
		if l.state == state {
			n++
		}
	}
	return n
}

// agoNote: 「（3 天前）」 after a time more than a day back, nothing for today.
func (s *Service) agoNote(t time.Time) string {
	days := int(s.now().Sub(t).Hours() / 24)
	if days < 1 {
		return " " // 「上次扫描：10月20日 20:00」
	}
	return fmt.Sprintf("（%d 天前）", days)
}

// roundHadFullAccess: the round looked everywhere: nothing was skipped for want of Full Disk Access.
func roundHadFullAccess(r core.Report) bool {
	for _, x := range r.Skipped {
		if strings.Contains(x.Reason, "完全磁盘访问") {
			return false
		}
	}
	return true
}

// macUnseen: what is not looked at without Full Disk Access, in people's words (core.Guarded and core.PrivacyPlaces:
// Desktop, Documents, Downloads, Music, the Photos library, iCloud Drive, other apps' containers, Mail, Messages…).
// Not just the three folders: an app's container (WeChat's) is often the biggest thing (design review r5).
const macUnseen = "下载、文稿、桌面、照片和一些应用的数据等"

// fdaGrant: the 「打开设置」 grant for Full Disk Access (skippedLines' wording).
const fdaGrant = "完全磁盘访问"

type macLine struct {
	name, size string
	bytes      int64
}

// macFolders: the folders the space rule measured last, biggest first (developer tools' caches folded into one line),
// at most macMaxFolders, each with how much it grew in the last seven days when that is a gigabyte or more; and the
// total of what is listed.
func (s *Service) macFolders() ([]macLine, int64) {
	sizes := core.SpaceSizes(s.Store)
	home := core.Canonical(s.Config.Context.Home)
	type row struct{ now, before int64 }
	rows := map[string]*row{}
	gone := map[string]bool{} // 已经删掉的应用：合成一行，写几个应用
	for path, days := range sizes {
		if len(days) == 0 {
			continue
		}
		var keys []string
		for d := range days {
			keys = append(keys, d)
		}
		sort.Strings(keys)
		last := keys[len(keys)-1]
		name := s.macFolderName(path, home)
		if name == "" || days[last] < 1<<20 { // 不到 1 MB 的不列
			continue
		}
		if strings.HasPrefix(name, macGoneApp) {
			gone[core.StripTeamID(strings.TrimPrefix(filepath.Base(path), "."))] = true
			name = macGoneApp
		}
		x := rows[name]
		if x == nil {
			x = &row{}
			rows[name] = x
		}
		x.now += days[last]
		before := days[last]
		if t, err := time.Parse("2006-01-02", last); err == nil {
			week := t.AddDate(0, 0, -7).Format("2006-01-02")
			for i := len(keys) - 2; i >= 0; i-- {
				if keys[i] <= week {
					before = days[keys[i]]
					break
				}
			}
		}
		x.before += before
	}
	names := make([]string, 0, len(rows))
	for n := range rows {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if rows[names[i]].now != rows[names[j]].now {
			return rows[names[i]].now > rows[names[j]].now
		}
		return names[i] < names[j]
	})
	var out []macLine
	var sum int64
	for i, n := range names {
		if i >= macMaxFolders {
			break
		}
		x := rows[n]
		size := macSize(x.now)
		if x.now-x.before >= 1<<30 {
			size += "，这周多了 " + macSize(x.now-x.before)
		}
		label := n
		if n == macGoneApp {
			label = fmt.Sprintf("已经删掉的应用留下的数据（%d 个应用）", len(gone))
		}
		out = append(out, macLine{label, size, x.now})
		sum += x.now
	}
	return out, sum
}

// macFolderName: a measured folder as people call it; "" for what is neither under home nor the temp folder.
func (s *Service) macFolderName(path, home string) string {
	rel, err := filepath.Rel(home, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		if strings.Contains(path, "/T/") || strings.HasSuffix(path, "/T") || strings.HasPrefix(path, "/private/var/folders") {
			return "临时文件"
		}
		return ""
	}
	if n, ok := macFolderNames[rel]; ok {
		return n
	}
	if macDevCaches[filepath.Base(rel)] {
		return "开发工具的缓存"
	}
	for _, p := range []struct{ prefix, word string }{{"Library/Application Support/", "的数据"}, {"Library/Containers/", "的数据"},
		{"Library/Caches/", "的缓存"}, {"Library/Developer/", "的数据"}, {".local/share/", "的数据"}, {".cache/", "的缓存"}} {
		if strings.HasPrefix(rel, p.prefix) {
			return withWord(s.macAppName(strings.TrimPrefix(rel, p.prefix)), p.word)
		}
	}
	if strings.HasPrefix(rel, ".") { // 家目录下的隐藏文件夹：多半是某个工具的
		return withWord(s.macAppName(rel), "的文件夹")
	}
	if strings.HasPrefix(rel, "Library/") {
		return "资源库里的「" + strings.TrimPrefix(rel, "Library/") + "」"
	}
	return rel // 用户自己建的文件夹，照它的名字
}

// macAppName: a folder named after an app or a tool, as the app is called: an installed app's own name for a bundle
// id, 「一个已经不在的应用」 for one that is not on this Mac (no id fragments: 「removed」 reads as 「deleted」, design review
// r1); a plain name as it is, without a hidden folder's dot.
func (s *Service) macAppName(name string) string {
	name = strings.TrimPrefix(name, ".")
	if core.LooksLikeBundleID(core.StripTeamID(name)) {
		if s.Config.AppName != nil {
			if n := s.Config.AppName(core.StripTeamID(name)); n != "" {
				return n
			}
		}
		return macGoneApp
	}
	return name
}

// macGoneApp: a bundle id whose app is not on this Mac; its folders are folded into one line with how many apps.
const macGoneApp = "已经删掉的应用"

// withWord: a name and a Chinese word after it, a space between when the name ends in a Latin letter or a digit
// (「Slack 的数据」, 「微信的数据」).
func withWord(name, word string) string {
	if word == "" || name == "" {
		return name + word
	}
	last := name[len(name)-1]
	if last >= '0' && last <= '9' || last >= 'a' && last <= 'z' || last >= 'A' && last <= 'Z' {
		return name + " " + word
	}
	return name + word
}

// macBigName: a big thing's line: the file's own name (long ones shortened in the middle, keeping the extension) and
// what it is, without the rule's wording.
func (s *Service) macBigName(x core.Finding) string {
	switch x.Rule {
	case "stale.large-file":
		return macShort(filepath.Base(x.Path), 40)
	case "space.ai-model":
		name := filepath.Base(x.Path)
		if parts := strings.Split(name, "--"); strings.HasPrefix(name, "models--") && len(parts) > 1 {
			name = parts[len(parts)-1] // Hugging Face 的缓存目录「models--组织--模型名」：只留模型名
		}
		return "AI 模型：" + macShort(name, 32)
	}
	title, _ := s.plain(x)
	if title == "" {
		title = x.Title
	}
	return title
}

// macShort: a file name cut in the middle to at most n display units (a Chinese character counts two, a Latin letter or
// a digit one: a name of Chinese characters is twice as wide), keeping its extension (「二零二三年大学…完整版.mp4」).
func macShort(name string, n int) string {
	width := func(rs []rune) int {
		w := 0
		for _, r := range rs {
			if r < 0x2E80 {
				w++
			} else {
				w += 2
			}
		}
		return w
	}
	r := []rune(name)
	if width(r) <= n {
		return name
	}
	ext := []rune(filepath.Ext(name))
	if len(ext) > 8 {
		ext = nil
	}
	body := r[:len(r)-len(ext)]
	keep := n - width(ext) - 1
	headW := keep * 2 / 3
	i, w := 0, 0
	for i < len(body) && w+width(body[i:i+1]) <= headW {
		w += width(body[i : i+1])
		i++
	}
	j, tw := len(body), 0
	for j > i && tw+width(body[j-1:j]) <= keep-w {
		tw += width(body[j-1 : j])
		j--
	}
	head, tail := strings.TrimRight(string(body[:i]), " "), strings.TrimLeft(string(body[j:]), " ")
	// 括号不留半个：截掉的那段里有开括号，尾巴上配不上的闭括号连同它前面的一起去掉（「…发言）完整版」→「…完整版」）
	for _, pair := range [][2]string{{"（", "）"}, {"(", ")"}, {"「", "」"}} {
		if k := strings.Index(tail, pair[1]); k >= 0 && !strings.Contains(tail[:k], pair[0]) {
			tail = strings.TrimLeft(tail[k+len(pair[1]):], " ")
		}
	}
	return head + "…" + tail + string(ext)
}

// macBigMin: how big a file must be to be listed (the stale-file rule's MinBytes: 500 MB on a Mac, less for a fake
// home); 0 when the rule is not there.
func (s *Service) macBigMin() int64 {
	for _, r := range s.Config.Rules {
		if x, ok := r.(*core.StaleFileRule); ok {
			return x.MinBytes
		}
	}
	return 0
}

// macBig: the big things the last round found, biggest first.
func macBig(f []core.Finding) []core.Finding {
	var out []core.Finding
	for _, x := range f {
		if macBigRules[x.Rule] && x.Bytes != nil && *x.Bytes > 0 {
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return *out[i].Bytes > *out[j].Bytes })
	return out
}

type macSecurityLine struct{ label, state string }

// macSecurityLines: each setting the posture rule checks: 「没开」 when it reported it, 「没查成」 when its probe failed (or
// the rule did not run), else 「开着」. A lock screen that waits before asking counts as on (it asks).
func (s *Service) macSecurityLines(r *core.Report) []macSecurityLine {
	reported := map[string]bool{}
	failed := map[string]bool{}
	ran := false
	if r != nil {
		if _, ok := r.RuleSeconds["posture"]; ok {
			ran = true
		}
		for _, x := range r.Findings {
			if strings.HasPrefix(x.Rule, "posture.") {
				ran = true
				reported[strings.TrimPrefix(x.Rule, "posture.")] = true
			}
			if x.Rule == "posture.partial" {
				for _, n := range strings.Split(x.Evidence["skipped"], "、") {
					failed[n] = true
				}
			}
		}
		for _, k := range r.Skipped {
			if k.Rule == "posture" {
				ran = false
			}
		}
	}
	out := make([]macSecurityLine, 0, len(macSecurity))
	for _, x := range macSecurity {
		state := macOn
		switch {
		case !ran || (x.probe != "" && failed[x.probe]):
			state = macFailed
		case reported[x.rule]:
			state = macOff
		}
		out = append(out, macSecurityLine{x.label, state})
	}
	return out
}
