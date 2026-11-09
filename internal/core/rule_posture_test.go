package core

import (
	"reflect"
	"testing"
)

func TestPostureEnabledServices(t *testing.T) {
	text := "disabled services = {\n\t\"com.openssh.sshd\" => enabled\n\t\"com.apple.screensharing\" => true\n" +
		"\t\"com.apple.smbd\" => disabled\n\t\"io.example.old\" =>  false\n}\n"
	got := postureEnabledServices(text)
	if !reflect.DeepEqual(got, map[string]bool{"com.openssh.sshd": true, "io.example.old": true}) {
		t.Fatalf("%v", got)
	}
}

func TestPostureTrustedCerts(t *testing.T) {
	text := "Number of trusted certs = 4\nCert 0: Example Debug Proxy CA\n   Number of trust settings : 0\n" +
		"Cert 1: Example Bad CA\n   Number of trust settings : 1\n   Trust Setting 0:\n      Result Type           : kSecTrustSettingsResultDeny\n" +
		"Cert 2: nas.example\n   Number of trust settings : 1\n   Trust Setting 0:\n      Policy OID            : SSL\n" +
		"      Policy String         : nas.example\n      Result Type           : kSecTrustSettingsResultTrustRoot\n" +
		"Cert 3: Example Corp Root\n   Number of trust settings : 1\n   Trust Setting 0:\n      Policy OID            : SSL\n" +
		"      Result Type           : kSecTrustSettingsResultTrustRoot\n"
	got := postureTrustedCerts(text)
	if !reflect.DeepEqual(got, []string{"Example Debug Proxy CA", "Example Corp Root"}) {
		t.Fatalf("%q", got)
	}
	if got := postureTrustedCerts("SecTrustSettings: No Trust Settings were found.\n"); len(got) != 0 {
		t.Fatalf("%q", got)
	}
}

// A CR LF is one Character in Swift: split(separator: "\n") does not split there.
func TestPostureLines(t *testing.T) {
	if got := postureLines("a\n\nb\r\nc\n"); !reflect.DeepEqual(got, []string{"a", "b\r\nc"}) {
		t.Fatalf("%q", got)
	}
}

func TestPostureFixtureAnswers(t *testing.T) {
	no := false
	f := &Fakes{Commands: []FakeCommand{{Tool: "/usr/bin/fdesetup", Status: 0, Output: "FileVault is Off.\n"},
		{Tool: "/bin/sh", Status: 0, Output: "screenLock delay is 900 seconds\n"}}, OtherCommands: FakeOutput{Status: -1}}
	r := NewPostureRule(&Layout{Root: t.TempDir()}, f)
	ctx := Context{Now: FixtureNow, FullDiskAccess: &no}
	found, err := r.Run(&ctx)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]string{}
	for _, x := range found {
		rules[x.Rule] = x.Title
	}
	want := map[string]string{"posture.filevault": "FileVault 没开：电脑丢了，硬盘上的东西能直接被读出来",
		"posture.screen-lock-delay": "屏保或关屏后 15 分钟内不要密码",
		"posture.partial":           "有几项没查成：防火墙、SIP、Gatekeeper、共享服务"}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("%q", rules)
	}
}
