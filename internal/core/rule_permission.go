package core

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// PermissionRule: privacy grants (TCC) held by apps that are no longer on this Mac. Reading TCC needs Full Disk
// Access; without it the rule says so instead of reporting nothing. Swift: Rules/PermissionRule.swift.
type PermissionRule struct {
	// LaunchServices: also ask macOS where apps are (off for a fake home).
	LaunchServices bool
}

func init() { Register("permission.stale-grant", NewPermissionRule) }

func NewPermissionRule(l *Layout, f *Fakes) Rule { return &PermissionRule{LaunchServices: l == nil} }

func (r *PermissionRule) ID() string { return "permission.stale-grant" }
func (r *PermissionRule) Emits() []string {
	return []string{"permission.stale-grant", "permission.partial"}
}

// grantNames are the grants worth naming to the user.
var grantNames = map[string]string{
	"kTCCServiceSystemPolicyAllFiles":        "完全磁盘访问",
	"kTCCServiceAccessibility":               "辅助功能",
	"kTCCServiceScreenCapture":               "录屏",
	"kTCCServiceListenEvent":                 "输入监控",
	"kTCCServicePostEvent":                   "控制电脑",
	"kTCCServiceSystemPolicyDocumentsFolder": "文稿",
	"kTCCServiceSystemPolicyDownloadsFolder": "下载",
	"kTCCServiceSystemPolicyDesktopFolder":   "桌面",
	"kTCCServiceCamera":                      "摄像头",
	"kTCCServiceMicrophone":                  "麦克风",
	"kTCCServiceAppleEvents":                 "自动化",
}

// grantPages are the System Settings page for each grant.
var grantPages = map[string]string{
	"完全磁盘访问": "Privacy_AllFiles", "辅助功能": "Privacy_Accessibility", "录屏": "Privacy_ScreenCapture",
	"输入监控": "Privacy_ListenEvent", "控制电脑": "Privacy_Accessibility", "文稿": "Privacy_FilesAndFolders",
	"下载": "Privacy_FilesAndFolders", "桌面": "Privacy_FilesAndFolders", "摄像头": "Privacy_Camera",
	"麦克风": "Privacy_Microphone", "自动化": "Privacy_Automation",
}

// GrantSettingsURL is the System Settings page of a grant (x-apple.systempreferences: deep link); "" none.
func GrantSettingsURL(grant string) string {
	if p, ok := grantPages[grant]; ok {
		return "x-apple.systempreferences:com.apple.preference.security?" + p
	}
	return ""
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
		if ctx.AccessOff { // macOS may still let it through: the user said no
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
	if len(grants) == 0 && len(unreadable) > 0 {
		return nil, Skip(strings.Join(unreadable, "；"))
	}
	type held struct {
		isPath   bool
		services map[string]bool
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
	clients := make([]string, 0, len(byClient))
	for c := range byClient {
		clients = append(clients, c)
	}
	sort.Strings(clients)
	var out []Finding
	for _, client := range clients {
		h := byClient[client]
		var gone bool
		if h.isPath {
			gone = ctx.MayLook(client) && !Exists(client)
		} else {
			gone = !apps.Covers(client)
		}
		if !gone {
			continue
		}
		services := appsSortedKeys(h.services)
		powerful := h.services["完全磁盘访问"] || h.services["辅助功能"] || h.services["输入监控"] || h.services["录屏"]
		sev := Low
		if powerful {
			sev = Medium
		}
		var pages []string
		for _, s := range services {
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
		out = append(out, Finding{Rule: r.ID(), Category: CatPermission, Severity: sev, Verdict: Confirm, Path: client,
			Title: client + " 已经不在这台 Mac 上，还拿着「" + list + "」",
			Evidence: map[string]string{"grants": list, "settings": strings.Join(pages, " "),
				"how":  "系统设置 → 隐私与安全性 → " + list + "，选中它点「−」（会要你的密码）。应用卸载以后用命令行（tccutil）删不掉，只能在这一页删",
				"hint": "以后装上同名的东西，会直接拿到这些权限"}})
	}
	if len(unreadable) > 0 {
		out = append(out, Finding{Rule: "permission.partial", Category: CatPermission, Severity: Low, Verdict: Info,
			Title: "有的权限记录读不了，结果不完整", Evidence: map[string]string{"why": strings.Join(unreadable, "；")}})
	}
	return out, nil
}
