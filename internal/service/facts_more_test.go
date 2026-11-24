package service

import (
	"encoding/json"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

func factsJSON(t *testing.T, f core.Finding) string {
	t.Helper()
	b, err := json.Marshal((&Service{}).attentionFacts(f))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The security settings, processes and keyboard watchers say what the rule found as codes, paths and numbers, not
// sentences (luoke-scan#212): the window writes its own words from them.
func TestAttentionFactsOfPostureProcessesAndKeyboard(t *testing.T) {
	sig := func(k core.SigKind, team string) string { return core.Signature{Kind: k, Team: team}.Label() }
	for _, c := range []struct {
		f    core.Finding
		want string
	}{
		{core.Finding{Rule: "posture.filevault", Evidence: map[string]string{"how": "words"}},
			`{"grant":"FileVault","setting":"filevault"}`},
		{core.Finding{Rule: "posture.firewall", Evidence: map[string]string{"how": "words"}},
			`{"grant":null,"setting":"firewall"}`},
		{core.Finding{Rule: "posture.screen-lock-delay", Evidence: map[string]string{"delay_seconds": "600"}},
			`{"delaySeconds":600,"grant":null,"setting":"screen-lock-delay"}`},
		{core.Finding{Rule: "posture.pending-updates", Evidence: map[string]string{"uptime_days": "40", "pending": "2"}},
			`{"grant":null,"pending":2,"setting":"pending-updates","uptimeDays":40}`},
		{core.Finding{Rule: "posture.xprotect-stale", Evidence: map[string]string{"updated": "2026-09-01"}},
			`{"grant":null,"setting":"xprotect-stale","updated":"2026-09-01"}`},
		{core.Finding{Rule: "posture.trusted-roots", Key: "a|b|c", Evidence: map[string]string{"certs": "mkcert dev；Proxy CA"}},
			`{"certs":["mkcert dev","Proxy CA"],"certsMore":1,"grant":null,"setting":"trusted-roots"}`},
		{core.Finding{Rule: "posture.partial", Evidence: map[string]string{"skipped": "FileVault、锁屏、别的"}},
			`{"grant":null,"setting":"partial","skipped":["filevault","screen-lock","别的"]}`},
		{core.Finding{Rule: "process.deleted-binary", Path: "/opt/x/tool", Evidence: map[string]string{"pids": "10,11", "count": "2", "started": "2026-11-01"}},
			`{"count":2,"pids":[10,11],"program":"/opt/x/tool","started":"2026-11-01"}`},
		{core.Finding{Rule: "process.dyld-insert", Path: "/tmp/h.dylib", Evidence: map[string]string{"library": "/tmp/h.dylib",
			"signature": sig(core.SigDeveloper, "ABCDE12345"), "pids": "7", "count": "1", "programs": "a、b", "started": "2026-11-02"}},
			`{"count":1,"library":"/tmp/h.dylib","pids":[7],"programs":["a","b"],"signature":{"kind":"developer","team":"ABCDE12345"},"started":"2026-11-02"}`},
		{core.Finding{Rule: "process.library-temp", Evidence: map[string]string{"program": "/opt/t", "place": "下载文件夹",
			"libraries": "/tmp/a.dylib（" + sig(core.SigAdhoc, "") + "）；/tmp/b.dylib（文件已经删掉）；/tmp/c.dylib（没查签名）",
			"pids":      "5", "count": "1", "started": "2026-11-03", "library_count": "3"}},
			`{"count":1,"libraries":[{"path":"/tmp/a.dylib","signature":{"kind":"adhoc","team":null}},{"path":"/tmp/b.dylib","signature":{"kind":"deleted","team":null}},{"path":"/tmp/c.dylib","signature":null}],"libraryCount":3,"pids":[5],"place":"downloads","program":"/opt/t","started":"2026-11-03"}`},
		{core.Finding{Rule: "process.pile-up", Path: "/usr/sbin/lsof", Evidence: map[string]string{"count": "30", "parent_pid": "99", "parent": "?"}},
			`{"count":30,"parent":null,"parentPid":99,"pids":[],"program":"/usr/sbin/lsof","started":null}`},
		{core.Finding{Rule: "process.orphan", Evidence: map[string]string{"count": "2", "pids": "1,2", "oldest": "node（1，30 小时）；sleep（2，5 小时）"}},
			`{"count":2,"oldest":[{"hours":30,"name":"node","pid":1},{"hours":5,"name":"sleep","pid":2}],"pids":[1,2],"started":null}`},
		{core.Finding{Rule: "process.partial", Evidence: map[string]string{}}, `{"skipped":"launchctl"}`},
		{core.Finding{Rule: "keyboard.unvouched", Key: "keyboard//opt/homebrew/bin/skhd", Evidence: map[string]string{"signature": sig(core.SigUnsigned, "")}},
			`{"interpreter":false,"program":"/opt/homebrew/bin/skhd","signature":{"kind":"unsigned","team":null}}`},
		{core.Finding{Rule: "keyboard.unvouched", Key: "keyboard/", Evidence: map[string]string{"signature": "程序文件不在了"}},
			`{"interpreter":false,"program":null,"signature":{"kind":"deleted","team":null}}`},
		{core.Finding{Rule: "keyboard.unvouched", Key: "keyboard//usr/bin/python3", Evidence: map[string]string{"signature": "苹果签名的解释器，脚本没人担保"}},
			`{"interpreter":true,"program":"/usr/bin/python3","signature":{"kind":"apple","team":null}}`},
		{core.Finding{Rule: "keyboard.watchers", Evidence: map[string]string{"programs": "Raycast；1Password"}},
			`{"programs":["Raycast","1Password"]}`},
	} {
		if got := factsJSON(t, c.f); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.f.Rule, got, c.want)
		}
	}
}
