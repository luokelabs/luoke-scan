package core

import (
	"reflect"
	"strings"
	"testing"
)

// The Swift version's tests (ExposureTests: 命令行里的密码和令牌只记种类).
func TestSecretKinds(t *testing.T) {
	token := "ghp_" + strings.Repeat("a1B2", 9)
	cases := []struct {
		args    []string
		program string
		want    []string
	}{
		{[]string{"--token", token, "--password=hunter2", "--api-key", "--verbose", "--password-file", "/etc/x", "https://me:pw@example.com/repo.git"}, "",
			[]string{"GitHub 令牌", "参数 --password", "参数 --token", "网址里的密码"}},
		{[]string{"--password=", "https://example.com/a:b", "git@github.com:me/x.git", "-p", "8080"}, "", []string{}},
		{[]string{"AKIA" + strings.Repeat("Z", 16)}, "", []string{"AWS 访问密钥"}},
		// Review of #19: not secrets.
		{[]string{"--private-key", "/Users/me/.ssh/deploy", "--token=$GH_TOKEN", "--password", "@/run/pw", "/opt/sk-learn-models/v1/weights.bin",
			"--pass", "through"}, "", []string{}},
		// Secrets some programs take their own way.
		{[]string{"-uroot", "-pS3cret", "db"}, "mysql", []string{"参数 -p（数据库密码）"}},
		{[]string{"-p", "3306"}, "mysql", []string{}},
		{[]string{"-u", "me:pw", "https://x"}, "curl", []string{"参数 -u（用户名:密码）"}},
		{[]string{"-ume:pw"}, "curl", []string{"参数 -u（用户名:密码）"}},
		{[]string{"-u", "me", "https://x"}, "curl", []string{}},
		{[]string{"-u", "origin"}, "git", []string{}},
		{[]string{"redis://:pw@cache:6379"}, "", []string{"网址里的密码"}},
		{[]string{"sk-" + strings.Repeat("aB3", 10)}, "", []string{"API 密钥（sk-…）"}},
		// The shapes' edges: word boundaries as ICU has them, a key with no digit, a path segment.
		{[]string{"xAKIA" + strings.Repeat("Z", 16)}, "", []string{}},
		{[]string{"AKIA" + strings.Repeat("Z", 17)}, "", []string{}},
		{[]string{"中AKIA" + strings.Repeat("Z", 16)}, "", []string{}},
		{[]string{"=AKIA" + strings.Repeat("Z", 16) + "/"}, "", []string{"AWS 访问密钥"}},
		{[]string{"sk-" + strings.Repeat("ab", 15)}, "", []string{}},
		{[]string{"x/sk-" + strings.Repeat("a1", 15)}, "", []string{}},
		{[]string{"key=sk-" + strings.Repeat("a1", 15)}, "", []string{"API 密钥（sk-…）"}},
		{[]string{"glpat-" + strings.Repeat("x", 20)}, "", []string{"GitLab 令牌"}},
		{[]string{"glpat-" + strings.Repeat("x", 19)}, "", []string{}},
		{[]string{"xoxb-1234567890"}, "", []string{"Slack 令牌"}},
		{[]string{"xoxq-1234567890"}, "", []string{}},
		{[]string{"github_pat_" + strings.Repeat("A_1", 14)}, "", []string{"GitHub 令牌"}},
		{[]string{"ghp_" + strings.Repeat("a", 36) + "_"}, "", []string{}},
	}
	for _, c := range cases {
		got := SecretKinds(c.args, c.program)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q %q: %q; want %q", c.args, c.program, got, c.want)
		}
	}
}

func TestListeningSocketKinds(t *testing.T) {
	l := func(a string) ListeningSocket { return ListeningSocket{Port: 1, Address: a} }
	if !l("0.0.0.0").Everywhere() || !l("::").Everywhere() || l("192.168.1.5").Everywhere() {
		t.Fatal("everywhere")
	}
	if !l("127.0.0.1").Loopback() || !l("::1").Loopback() || !l("::ffff:127.0.0.1").Loopback() {
		t.Fatal("loopback")
	}
	if l("192.168.1.5").Loopback() || l("fe80::1").Loopback() || l("0.0.0.0").Loopback() {
		t.Fatal("not loopback")
	}
}

func TestOpenSSHKeyFacts(t *testing.T) {
	s := func(b []byte) []byte {
		n := len(b)
		return append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, b...)
	}
	key := func(cipher string, pub []byte) []byte {
		out := []byte("openssh-key-v1\x00")
		out = append(out, s([]byte(cipher))...)
		out = append(out, s([]byte("none"))...)
		out = append(out, s(nil)...)
		out = append(out, 0, 0, 0, 1)
		return append(out, s(pub)...)
	}
	rsa := func(bits int) []byte {
		p := append(s([]byte("ssh-rsa")), s([]byte{1, 0, 1})...)
		return append(p, s(append([]byte{0}, make([]byte, bits/8)...))...)
	}
	// A modulus of zeros has no bits; one of 0xc3 bytes has all of them.
	full := func(bits int) []byte {
		m := []byte{0}
		for i := 0; i < bits/8; i++ {
			m = append(m, 0xc3)
		}
		return append(append(s([]byte("ssh-rsa")), s([]byte{1, 0, 1})...), s(m)...)
	}
	if k, ok := exposureOpenSSHKey(key("none", full(1024))); !ok || k.encrypted || k.weak != " 1024 位的 RSA" || k.kind != "ssh-rsa" {
		t.Fatalf("%+v %v", k, ok)
	}
	if k, ok := exposureOpenSSHKey(key("aes256-ctr", full(3072))); !ok || !k.encrypted || k.weak != "" {
		t.Fatalf("%+v %v", k, ok)
	}
	if k, ok := exposureOpenSSHKey(key("none", rsa(4096))); !ok || k.weak != " 0 位的 RSA" {
		t.Fatalf("%+v %v", k, ok)
	}
	if k, ok := exposureOpenSSHKey(key("aes256-ctr", s([]byte("ssh-dss")))); !ok || k.weak != " DSA 的" {
		t.Fatalf("%+v %v", k, ok)
	}
	if _, ok := exposureOpenSSHKey([]byte("openssh-key-v1\x00\x00\x00")); ok {
		t.Fatal("truncated")
	}
}
