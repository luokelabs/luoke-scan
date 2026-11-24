package core

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// PermissionRule: what apps no longer on this Mac still hold: privacy grants (TCC), and their entries in Login Items &
// Extensions (the background items macOS keeps, and launchd jobs that name them: backgrounditems.go). One finding
// per app. Reading TCC needs Full Disk Access; without it the rule says so instead of reporting nothing. Swift:
// Rules/PermissionRule.swift.
type PermissionRule struct {
	// LaunchServices: also ask macOS where apps are (off for a fake home).
	LaunchServices bool
	// UserUUID is this user's generated UID, whose background items are theirs to remove (nil: every user's, as in a
	// fake home's archive).
	UserUUID func() string
}

func init() { Register("permission.stale-grant", NewPermissionRule) }

func NewPermissionRule(l *Layout, f *Fakes) Rule {
	r := &PermissionRule{LaunchServices: l == nil}
	if l == nil {
		r.UserUUID = CurrentUserUUID
	}
	return r
}

func (r *PermissionRule) ID() string { return "permission.stale-grant" }
func (r *PermissionRule) Emits() []string {
	return []string{"permission.stale-grant", "permission.partial"}
}

// grantNames are the grants worth naming to the user.
var grantNames = map[string]string{
	"kTCCServiceSystemPolicyAllFiles":         "完全磁盘访问",
	"kTCCServiceAccessibility":                "辅助功能",
	"kTCCServiceScreenCapture":                "录屏",
	"kTCCServiceListenEvent":                  "输入监控",
	"kTCCServicePostEvent":                    "控制电脑",
	"kTCCServiceSystemPolicyDocumentsFolder":  "文稿",
	"kTCCServiceSystemPolicyDownloadsFolder":  "下载",
	"kTCCServiceSystemPolicyDesktopFolder":    "桌面",
	"kTCCServiceCamera":                       "摄像头",
	"kTCCServiceMicrophone":                   "麦克风",
	"kTCCServiceAppleEvents":                  "自动化",
	"kTCCServiceAddressBook":                  "通讯录",
	"kTCCServiceCalendar":                     "日历",
	"kTCCServiceReminders":                    "提醒事项",
	"kTCCServicePhotos":                       "照片",
	"kTCCServicePhotosAdd":                    "照片",
	"kTCCServiceSpeechRecognition":            "语音识别",
	"kTCCServiceSystemPolicyRemovableVolumes": "可移除的宗卷",
	"kTCCServiceSystemPolicyNetworkVolumes":   "网络宗卷",
	"kTCCServiceBluetoothAlways":              "蓝牙",
	"kTCCServiceSystemPolicyAppBundles":       "App 管理",
	"kTCCServiceDeveloperTool":                "开发者工具",
	"kTCCServiceMediaLibrary":                 "媒体与 Apple Music",
	"kTCCServiceFocusStatus":                  "专注",
	"kTCCServiceWillow":                       "家庭",
}

// powerfulGrants are the grants that let an app see or do anything on this Mac: a stale one is medium.
var powerfulGrants = []string{"完全磁盘访问", "辅助功能", "输入监控", "录屏", "App 管理"}

// GrantPages are the System Settings page for each grant (Privacy & Security, by its anchor). Those without an anchor
// known to open their own list open Privacy & Security (Privacy): the list is one click from there.
var GrantPages = map[string]string{
	"完全磁盘访问": "Privacy_AllFiles", "辅助功能": "Privacy_Accessibility", "录屏": "Privacy_ScreenCapture",
	"输入监控": "Privacy_ListenEvent", "控制电脑": "Privacy_Accessibility", "文稿": "Privacy_FilesAndFolders",
	"下载": "Privacy_FilesAndFolders", "桌面": "Privacy_FilesAndFolders", "摄像头": "Privacy_Camera",
	"麦克风": "Privacy_Microphone", "自动化": "Privacy_Automation", "通讯录": "Privacy_Contacts",
	"日历": "Privacy_Calendars", "提醒事项": "Privacy_Reminders", "照片": "Privacy_Photos",
	"语音识别": "Privacy_SpeechRecognition", "可移除的宗卷": "Privacy_FilesAndFolders", "网络宗卷": "Privacy_FilesAndFolders",
	"蓝牙": "Privacy", "App 管理": "Privacy", "开发者工具": "Privacy", "媒体与 Apple Music": "Privacy", "专注": "Privacy",
	"家庭": "Privacy",
}

// GrantSettingsURL is the System Settings page of a grant (x-apple.systempreferences: deep link); "" none.
func GrantSettingsURL(grant string) string {
	if grant == LoginItemsGrant {
		return LoginItemsURL
	}
	if p, ok := GrantPages[grant]; ok {
		return "x-apple.systempreferences:com.apple.preference.security?" + p
	}
	return ""
}

// What a stale-grant finding says of the Login Items entries left behind, as facts (not for the model: explain.go):
// the items one a line (a name, or a launchd job's plist), whether one of them goes on starting, and whether as root.
const (
	LeftItemsKey  = "left_items"
	LeftStartsKey = "left_starts"
	LeftDaemonKey = "left_daemon"
)

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

type tccGrant struct {
	service, client string
	isPath          bool
}

// readTCC reads the allowed grants of a TCC database (auth_value 2; client_type 0 a bundle id, 1 a path) with the
// system's sqlite3, read-only.
func readTCC(db string) ([]tccGrant, error) {
	res := Run("/usr/bin/sqlite3", []string{"-readonly", "-json", db,
		"SELECT service, client, client_type FROM access WHERE auth_value = 2"}, RunOpts{Timeout: 20 * time.Second})
	unreadable := tccUnreadable(db)
	if res.Status != 0 {
		return nil, unreadable
	}
	var rows []map[string]any
	if strings.TrimSpace(res.Stdout) != "" {
		if err := json.Unmarshal([]byte(res.Stdout), &rows); err != nil {
			return nil, unreadable
		}
	}
	var out []tccGrant
	for _, row := range rows {
		s, ok1 := row["service"].(string)
		c, ok2 := row["client"].(string)
		if !ok1 || !ok2 {
			continue
		}
		t, _ := row["client_type"].(float64)
		out = append(out, tccGrant{service: s, client: c, isPath: t == 1})
	}
	return out, nil
}

func tccUnreadable(db string) error {
	return Skip("读不了 " + db + "（需要完全磁盘访问）")
}

func (r *PermissionRule) Run(ctx *Context) ([]Finding, error) {
	apps := NewInstalledApps(ctx.AppDirs, r.LaunchServices)
	var grants []tccGrant
	var unreadable []string
	for _, db := range ctx.TCCDatabases {
		if !Exists(db) && !strings.HasPrefix(db, "/Library") {
			continue
		}
		if ctx.AccessOff { // macOS may still let it through: the user has not said yes
			unreadable = append(unreadable, tccUnreadable(db).Error())
			continue
		}
		g, err := readTCC(db)
		if err != nil {
			unreadable = append(unreadable, err.Error())
			continue
		}
		grants = append(grants, g...)
	}
	tccUnread := len(grants) == 0 && len(unreadable) > 0

	// What is left in Login Items & Extensions: the background items macOS keeps, and launchd jobs naming their app.
	// Some macOS versions let every user read the archive, others only with Full Disk Access; with access switched
	// off it is left alone as TCC is.
	left := launchdLeftovers(ctx, apps)
	var items []BackgroundItem
	if !ctx.AccessOff {
		var why string
		if items, why = ReadBackgroundItems(ctx.BackgroundItems); why != "" {
			unreadable = append(unreadable, why)
		}
	}
	user := ""
	if r.UserUUID != nil {
		if user = r.UserUUID(); user == "" {
			items = nil // not known whose they are: none is said to be the user's
		}
	}
	for k, l := range backgroundLeftovers(ctx, items, user, apps) {
		if had, ok := left[k]; ok {
			had.items = uniqueStrings(append(had.items, l.items...))
			had.starts = had.starts || l.starts
			had.daemon = had.daemon || l.daemon
			if had.name == "" {
				had.name = l.name
			}
		} else {
			left[k] = l
		}
	}
	if tccUnread && len(left) == 0 {
		return nil, Skip(strings.Join(unreadable, "；"))
	}

	type held struct {
		isPath   bool
		services map[string]bool
		left     *leftBehind
	}
	byClient := map[string]*held{}
	for _, g := range grants {
		name, ok := grantNames[g.service]
		if !ok {
			continue
		}
		h := byClient[g.client]
		if h == nil {
			h = &held{isPath: g.isPath, services: map[string]bool{}}
			byClient[g.client] = h
		}
		h.services[name] = true
	}
	// An app's Login Items entries join its grants (bundle ids compared ignoring case).
	lower := map[string]string{}
	for c, h := range byClient {
		if !h.isPath {
			lower[strings.ToLower(c)] = c
		}
	}
	for k, l := range left {
		c, ok := lower[k]
		if !ok {
			c = l.client
			byClient[c] = &held{services: map[string]bool{}}
		}
		byClient[c].left = l
	}
	clients := make([]string, 0, len(byClient))
	for c := range byClient {
		clients = append(clients, c)
	}
	sort.Strings(clients)
	var out []Finding
	for _, client := range clients {
		h := byClient[client]
		if h.left == nil { // a Login Items entry was found for an app known to be gone
			var gone bool
			if h.isPath {
				gone = ctx.MayLook(client) && !Exists(client)
			} else {
				gone = !apps.Covers(client)
			}
			if !gone {
				continue
			}
		}
		services := appsSortedKeys(h.services)
		powerful := false
		for _, g := range powerfulGrants {
			powerful = powerful || h.services[g]
		}
		sev := Low
		if powerful || (h.left != nil && h.left.daemon) {
			sev = Medium
		}
		held := append([]string(nil), services...)
		if h.left != nil {
			held = append(held, LoginItemsGrant)
		}
		var pages []string
		for _, s := range held {
			u := GrantSettingsURL(s)
			dup := false
			for _, p := range pages {
				dup = dup || p == u
			}
			if u != "" && !dup {
				pages = append(pages, u)
			}
		}
		list := strings.Join(services, "、")
		var title string
		var how []string
		ev := map[string]string{"grants": strings.Join(held, "、"), "settings": strings.Join(pages, " "),
			"hint": "以后装上同名的东西，会直接拿到这些权限"}
		switch {
		case list != "" && h.left != nil:
			title = client + " 已经不在这台 Mac 上，还拿着「" + list + "」，还在「登录项」里"
		case list != "":
			title = client + " 已经不在这台 Mac 上，还拿着「" + list + "」"
		default:
			title = client + " 已经不在这台 Mac 上，还在「登录项」里"
			ev["hint"] = "系统设置里还留着它的开关" // its program went with the app
		}
		if list != "" {
			how = append(how, "系统设置 → 隐私与安全性 → "+list+"，选中它点「−」（会要你的密码）。应用卸载以后用命令行（tccutil）删不掉，只能在这一页删")
		}
		if l := h.left; l != nil {
			how = append(how, "系统设置 → 通用 → 登录项与扩展：「登录时打开」里有它就选中它点「−」，「允许在后台」里有它就关掉它的开关")
			if l.name != "" {
				ev["app"] = l.name
			}
			var shown []string
			for _, it := range l.items {
				if strings.HasPrefix(it, "/") {
					shown = append(shown, ctx.Shown(it))
				} else {
					shown = append(shown, it)
				}
			}
			ev["login_items"] = strings.Join(shown, "、")
			// The same as facts, for data/overview: each item as it is, and what the hint below says in words.
			ev[LeftItemsKey] = strings.Join(l.items, "\n")
			ev[LeftStartsKey], ev[LeftDaemonKey] = flag(l.starts), flag(l.daemon)
			// Only a launchd job whose program is still there goes on starting (launchdLeftovers).
			switch {
			case l.daemon:
				ev["hint"] = "它留下的后台程序还会以管理员（root）身份启动"
			case l.starts:
				ev["hint"] = "它留下的后台程序还会照常启动"
			}
		}
		ev["how"] = strings.Join(how, "；")
		out = append(out, Finding{Rule: r.ID(), Category: CatPermission, Severity: sev, Verdict: Confirm, Path: client,
			Title: title, Evidence: ev})
	}
	if len(unreadable) > 0 {
		out = append(out, Finding{Rule: "permission.partial", Category: CatPermission, Severity: Low, Verdict: Info,
			Title: "有的权限记录读不了，结果不完整", Evidence: map[string]string{"why": strings.Join(unreadable, "；")}})
	}
	return out, nil
}
