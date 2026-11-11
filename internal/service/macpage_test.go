package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// 「状态」 (luoke-scan#124): folder names in people's words, never an id fragment.
func TestMacFolderNames(t *testing.T) {
	s := &Service{Config: Config{AppName: func(id string) string {
		if id == "com.tencent.xinWeChat" {
			return "微信"
		}
		return ""
	}}}
	for rel, want := range map[string]string{
		"Downloads":               "下载",
		"Library/Caches/pip":      "开发工具的缓存",
		".npm":                    "开发工具的缓存",
		"Library/Developer/Xcode": "开发工具的缓存",
		"Library/Containers/com.tencent.xinWeChat": "微信的数据",
		"Library/Caches/com.example.gone":          "已经删掉的应用的缓存",
		"Library/Application Support/Slack":        "Slack 的数据",
		"Library/Group Containers":                 "几个应用共用的数据",
		"Library/Keychains":                        "资源库里的「Keychains」",
		".vscode":                                  "vscode 的文件夹",
		"Projects":                                 "Projects",
	} {
		if got := s.macFolderName("/h/"+rel, "/h"); got != want {
			t.Errorf("%s: got %q, want %q", rel, got, want)
		}
	}
	if got := s.macFolderName("/private/var/folders/ab/xyz/T", "/h"); got != "临时文件" {
		t.Errorf("temp folder: %q", got)
	}
	if got := s.macFolderName("/opt/elsewhere", "/h"); got != "" {
		t.Errorf("outside home: %q", got)
	}
}

func TestMacShortAndSize(t *testing.T) {
	if got := macShort("macOS Sonoma 安装程序 备份 2023 年 3 月最终版 (1).dmg", 28); len([]rune(got)) > 28 || !strings.HasSuffix(got, ".dmg") || !strings.Contains(got, "…") {
		t.Errorf("long name: %q", got)
	}
	if got := macShort("IMG_8519.MOV", 28); got != "IMG_8519.MOV" {
		t.Errorf("short name changed: %q", got)
	}
	for b, want := range map[int64]string{21_000_000: "21.0 MB", 182_000_000_000: "182.0 GB", 999: "999 B"} {
		if got := macSize(b); got != want {
			t.Errorf("macSize(%d) = %q, want %q", b, got, want)
		}
	}
}

// Without Full Disk Access nothing that was not looked at is called 「没有」 (design review r1, r2).
func TestMacPageWithoutFullDiskAccess(t *testing.T) {
	store := &core.Store{Dir: t.TempDir()}
	no := false
	s := New(store, Config{Context: core.Context{Home: t.TempDir()}, Clock: time.Now, FullDiskAccess: func() *bool { return &no },
		Volume: func(string) (int64, int64, bool) { return 182_000_000_000, 494_000_000_000, true }})
	now := core.Time{Time: time.Now()}
	report := core.Report{StartedAt: now, FinishedAt: now, RuleSeconds: map[string]float64{"posture": 0.1},
		Skipped: []core.Skipped{{Rule: "space", Reason: "要打开「完全磁盘访问」才能查"}}, Findings: []core.Finding{
			{Rule: "posture.filevault", Category: core.CatPosture, Title: "FileVault 没开"},
			{Rule: "posture.partial", Category: core.CatPosture, Evidence: map[string]string{"skipped": "Gatekeeper"}},
		}}
	if err := store.SaveReport(report); err != nil {
		t.Fatal(err)
	}
	c := NewCard("mac")
	s.macPage(c, State{Acks: map[string]Ack{}, Ignored: map[string]core.Time{}})
	b, _ := json.Marshal(c.Messages())
	page := string(b)
	for _, want := range []string{"没查全", "1 项没开启", "没开启", "没查成", "已开启", "打开「完全磁盘访问」设置", "没查成，要先允许完全磁盘访问",
		"下载、文稿、桌面、照片和一些应用的数据等没查；别的地方没找到一年多没打开过的大文件", "182.0 GB", "spaceEvenly"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, not := range []string{"其余是没列出来", "已允许"} {
		if strings.Contains(page, not) {
			t.Errorf("should not say %q without Full Disk Access", not)
		}
	}
}

// Access taken away after a round that had it (a rebuilt development app, or the user switching it off): what the
// round found is told as found; only the notice and the permission line say access is off now (11-09).
func TestMacPageAccessGoneAfterAFullRound(t *testing.T) {
	store := &core.Store{Dir: t.TempDir()}
	no := false
	s := New(store, Config{Context: core.Context{Home: t.TempDir()}, Clock: time.Now, FullDiskAccess: func() *bool { return &no }})
	now := core.Time{Time: time.Now()}
	if err := store.SaveReport(core.Report{StartedAt: now, FinishedAt: now}); err != nil {
		t.Fatal(err)
	}
	c := NewCard("mac")
	s.macPage(c, State{Acks: map[string]Ack{}, Ignored: map[string]core.Time{}})
	b, _ := json.Marshal(c.Messages())
	page := string(b)
	for _, want := range []string{"没允许完全磁盘访问", "打开「完全磁盘访问」设置", "没找到一年多没打开过的大文件"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(page, "没查全") || strings.Contains(page, "没查成，要先允许") {
		t.Error("the round looked everywhere: do not call it not looked at")
	}
}

// A round running now: one line with how far it is, weighed by how long each check took last time; no
// 「现在查一下」 while it runs (负责人 11-09).
func TestMacPageWhileScanning(t *testing.T) {
	store := &core.Store{Dir: t.TempDir()}
	s := New(store, Config{Context: core.Context{Home: t.TempDir()}, Clock: time.Now})
	now := core.Time{Time: time.Now()}
	if err := store.SaveReport(core.Report{StartedAt: now, FinishedAt: now,
		RuleSeconds: map[string]float64{"space": 270, "posture": 20, "stale": 10}}); err != nil {
		t.Fatal(err)
	}
	lock := core.TakeLock(store.Dir, "round.lock", 0)
	defer lock.Release()
	store.SaveProgress(core.RoundProgress{Started: time.Now(), Done: []string{"posture", "stale"}, Total: 3, Current: "space"})
	page := func() string {
		c := NewCard("mac")
		s.macPage(c, State{Acks: map[string]Ack{}, Ignored: map[string]core.Time{}})
		b, _ := json.Marshal(c.Messages())
		return string(b)
	}
	got := page()
	for _, want := range []string{"正在查这台 Mac", "查了 10%，大约还要 5 分钟"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(got, "现在查一下") {
		t.Error("no scan button while a round runs")
	}
	store.SaveProgress(core.RoundProgress{Done: []string{"posture", "stale", "space"}, Total: 3, Current: "model"})
	if !strings.Contains(page(), "都查完了，在写说明") {
		t.Error("model phase not told")
	}
	store.ClearProgress()
	if store.Progress() != nil {
		t.Error("progress left after clear")
	}
}
