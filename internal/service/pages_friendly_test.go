package service

import "testing"

func TestFriendlyName(t *testing.T) {
	for in, want := range map[string]string{
		"临时文件夹 puppeteer_dev_chrome_profile-P00020": "Puppeteer 留下的临时文件夹",
		"puppeteer_dev_chrome_profile-XyZ987":       "Puppeteer 留下的临时文件夹",
		"安装包 Fixtureapp-2.0.dmg":                    "安装包 Fixtureapp-2.0.dmg",
		"临时文件夹 wings-AbC123":                        "临时文件夹 wings-AbC123",
	} {
		if got := friendlyName(in); got != want {
			t.Errorf("friendlyName(%q) = %q, want %q", in, got, want)
		}
	}
}
