package service

import (
	"strings"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// How this Mac runs (luoke-scan#126), for the user: the rule's title is already in plain words; one thing to do, and a
// button that opens Activity Monitor or the battery's settings. Nothing is ended from here (「要定的」 2: a 「退出」
// button could stop a program in the middle of real work, an export or a build).

const (
	activityMonitorGrant = "活动监视器"
	activityMonitorApp   = "/System/Applications/Utilities/Activity Monitor.app"
	batteryGrant         = "电池"
	batteryURL           = "x-apple.systempreferences:com.apple.Battery-Settings.extension"
)

// vitalsAdvice: what to do about a finding of the vitals rule.
func vitalsAdvice(f core.Finding) string {
	switch f.Rule {
	case "vitals.cpu":
		return "如果它不是在做你交给它的事（比如导出视频、编译），多半是卡住了：在活动监视器里选中它，看看要不要退出它。"
	case "vitals.memory":
		return "关掉暂时不用的程序和网页标签会快一些；在活动监视器的「内存」里能看到谁占得最多。"
	case "vitals.battery":
		return "在系统设置的「电池」里点「电池健康」旁边的 ⓘ 看看；用起来明显不够时，可以去 Apple 换一块电池。"
	case "vitals.thermal":
		return "让它歇一会儿，或者关掉不用的程序；放在硬的桌面上，别挡住出风口。"
	}
	return ""
}

// vitalsButton: the one button of a finding of the vitals rule.
func vitalsButton(f core.Finding) Button {
	if f.Rule == "vitals.battery" {
		return Button{Label: "打开「电池」设置", Event: "scan_open_settings", Context: O{"grant": batteryGrant}}
	}
	return Button{Label: "在活动监视器里看", Event: "scan_open_settings", Context: O{"grant": activityMonitorGrant}}
}

// isVitals: a finding of the vitals rule (its .partial note too).
func isVitals(f core.Finding) bool { return strings.HasPrefix(f.Rule, "vitals.") }
