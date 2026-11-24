package core

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func explainFinding(v Verdict, evidence map[string]string) Finding {
	if evidence == nil {
		evidence = map[string]string{}
	}
	return Finding{Rule: "stale.project", Category: CatStaleProject, Severity: Medium, Verdict: v, Path: "/x/old-site", Bytes: Size(418 << 20),
		Title: "old-site 半年多没动过", Evidence: evidence}
}

// The scan shows the model's sentence only when it may not mislead: the same checks as the eval's.
func TestExplainMisleadingNotShown(t *testing.T) {
	info := explainFinding(Info, map[string]string{"would_lose": "old-site 有 3 个提交没推送"})
	safe := explainFinding(Safe, nil)
	say := func(text string, f Finding) bool {
		_, ok := ExplainAnswer(text, f, ExplainInput(f, "~/Projects/old-site"), 120)
		return ok
	}
	for _, c := range []struct {
		text string
		f    Finding
		ok   bool
		why  string
	}{
		{"old-site 半年多没动过，有 3 个提交没推送，删了就找不回来。", info, true, ""},
		{strings.Repeat("长", 121), info, false, "超过字数"},
		{"**注意**：有没推送的提交", info, false, "Markdown"},
		{"- 有没推送的提交", info, false, "列表"},
		{"先 git push 再删", info, false, "终端命令"},
		{"先运行 rm -rf ~/x", info, false, "终端命令"},
		{"详见 https://example.com", info, false, "网址"},
		{"已经帮你移到废纸篓了", info, false, "说已经做了"},
		{"这个可以放心删。", info, false, "仅供参考的说成放心删"},
		{"里面有你的工作，可以删掉腾出空间。", info, false, "仅供参考的劝删"},
		{"里面有只在这台 Mac 上的工作，不能「放心删」。", info, true, "否定的不算"},
		{"这是 pip 的缓存，放心删，用到时会重新下载。", safe, true, "放心删的就是放心删"},
		{"<think>想想</think>", info, false, "只有想的"},
	} {
		if got := say(c.text, c.f); got != c.ok {
			t.Errorf("%s（%s）: shown %v", c.text, c.why, got)
		}
	}
}

func madeUpFinding() Finding {
	return Finding{Rule: "leak.temp", Category: CatLeak, Severity: Medium, Verdict: Confirm, Path: "/x/photos-2023", Bytes: Size(8_200_000_000),
		Title: "临时目录里有 340 个 puppeteer-* 没被删掉", Evidence: map[string]string{"count": "340", "first": "2026-09-02", "last": "2026-10-19",
			"per_day": "174.5 MB", "pids": "901,902,903"}}
}

// 「不编数字」: a number with a unit must be one the input gives; dates and years it names are not counted.
func TestExplainMadeUpNumbersNotShown(t *testing.T) {
	f := madeUpFinding()
	input := ExplainInput(f, "~/photos-2023")
	for text, ok := range map[string]bool{
		"临时目录里堆了 340 个，已经占了 8.2 GB，每天还在涨 174.5 MB。": true,
		"每天涨 200 MB，一直这样会占满。":                       false,
		"差不多 3 周就涨了这么多。":                            false,
		"从 9 月 2 日到 10 月 19 日一直在堆。":                 true,
		"从 2026 年 9 月 2 日起一直在堆。":                    true,
		"从 9 月 5 日起一直在堆。":                           false,
		"像是 2023 年的照片留下的临时文件。":                      true,
		"像是 2019 年留下的。":                             false,
		"进程 902 还开着。":                               true,
		"有 902 个进程。":                                true,
		"有 ３４０ 个没删。":                                true,
	} {
		if _, got := ExplainAnswer(text, f, input, 120); got != ok {
			t.Errorf("%s: shown %v", text, got)
		}
	}
	given := ExplainGivenNumbers(input)
	for _, n := range []float64{340, 8.2, 174.5, 901, 902, 903} {
		if !given[n] {
			t.Errorf("%v not given", n)
		}
	}
}

// The same answers judged the same way as the eval's 「不编数字」: every answer the eval has recorded for an explain
// item, and a few of our own, checked by bench/run_eval.py and by the scan.
func TestMadeUpNumbersJudgedAsTheEval(t *testing.T) {
	const script = `
import glob, json, sys
sys.path.insert(0, sys.argv[1] + "/bench")
import run_eval as r
p = r.load_prompt("explain")
items = {i["id"]: i for i in json.load(open(sys.argv[1] + "/bench/evalsets/explain.json", encoding="utf-8"))["items"]}
cases = []
for path in sorted(glob.glob(sys.argv[1] + "/bench/results/*.json")):
    t = json.load(open(path, encoding="utf-8")).get("tasks", {}).get("explain")
    for res in (t or {}).get("results", []):
        for run in res["runs"]:
            if res["id"] in items and run.get("output"):
                cases.append((items[res["id"]]["input"], r.strip_think(run["output"])))
for line in sys.stdin.buffer.read().decode("utf-8").splitlines():
    c = json.loads(line)
    cases.append((c["input"], c["out"]))
for given, out in cases:
    ok = r.check_explain({"input": given, "expect": {"must_any": [], "must_not": []}}, out, p)["不编数字"]
    sys.stdout.buffer.write((json.dumps({"input": given, "out": out, "ok": ok}, ensure_ascii=False) + "\n").encode("utf-8"))
`
	f := Finding{Rule: "leak.temp", Category: CatLeak, Severity: Medium, Verdict: Confirm, Path: "/x/photos-2023", Bytes: Size(8_200_000_000),
		Title: "临时目录里有 340 个没被删掉", Evidence: map[string]string{"first": "2026-09-02", "pids": "901,902,903", "per_day": "174.5 MB"}}
	input := ExplainInput(f, "~/photos-2023")
	mine := []string{"从 2026 年 9 月 2 日起", "9 月 2 日", "2026 年 9 月", "9 月", "2 日", "2026 年 2 日", "2023 年", "0 月 0 日", "每天 174.5 MB",
		"每天 175 MB", "３４０ 个", "902 个", "903 项、904 条", "2026-09-02 那天 3 周前", "１２ 月 ３ 日"}
	var stdin []string
	for _, m := range mine {
		stdin = append(stdin, VObj(Field{"input", input}, Field{"out", VStr(m)}).Text())
	}
	compared, made := 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(python(t, script, strings.Join(stdin, "\n")), "\n"), "\n") {
		c, err := ParseValue([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		given, _ := c.Get("input")
		out, _ := c.Get("out")
		ok, _ := c.Get("ok")
		if ok.Kind != VBool {
			t.Fatalf("no ok: %s", line)
		}
		if got := ExplainMadeUpNumber(out.Str, given); got != !ok.Bool {
			t.Errorf("%s: made up %v, the eval says %v", out.Str, got, !ok.Bool)
		}
		compared++
		if !ok.Bool {
			made++
		}
	}
	if compared < len(mine)+300 || made == 0 {
		t.Errorf("compared %d, made up %d", compared, made)
	}
}

func TestExplainInputAsTheEvalset(t *testing.T) {
	f := explainFinding(Info, map[string]string{"would_lose": "old-site 有 3 个提交没推送", "repos": "1", "targets": "/a\n/b",
		ExplainNoteKey: "上一轮说的", SkillNoteKey: "x"})
	want := `{"结论": "仅供参考", "标题": "old-site 半年多没动过", "位置": "~/Projects/old-site", "大小": "438.3 MB", "依据": {"repos": "1", "would_lose": "old-site 有 3 个提交没推送"}}`
	if got := ExplainInput(f, "~/Projects/old-site").Text(); got != want {
		t.Errorf("input %s", got)
	}
	// Too long: the longest facts go until it fits.
	for k, w := range map[string]string{"hint": "很长", "why": "也长", "more": "又长", "most": "还长", "last": "长长", "tail": "长尾", "end": "末尾",
		"x1": "一一", "x2": "二二", "x3": "三三"} {
		f.Evidence[k] = strings.Repeat(w, 2000)
	}
	if n := ExplainInput(f, "~/Projects/old-site").Size(); n > explainMaxInput {
		t.Errorf("size %d", n)
	}
	if ExplainAsks(Finding{Rule: "skill.exfil", Category: CatSkill, Severity: High, Verdict: Info, Path: "/s", Title: "t"}) {
		t.Error("a skill's finding")
	}
	if ExplainAsks(explainFinding(Info, nil)) {
		t.Error("仅供参考、不高的不上卡片")
	}
	if !ExplainAsks(explainFinding(Confirm, nil)) {
		t.Error("要确认的")
	}
}

func TestIdentifyOnlySureNamesShown(t *testing.T) {
	note := func(raw string) (string, bool) {
		a, ok := IdentifyAnswer(raw)
		if !ok {
			return "", false
		}
		return IdentifyNote(a)
	}
	if n, ok := note(`{"name": "Postman", "what": "Postman 的工作区和登录状态", "kind": "app-data", "sure": true}`); !ok || n != "本机模型认的：Postman（Postman 的工作区和登录状态）" {
		t.Errorf("note %q", n)
	}
	if _, ok := note(`{"name": "不确定", "what": "看不出来", "kind": "unknown", "sure": false}`); ok {
		t.Error("not sure")
	}
	if _, ok := note(`{"name": "X", "what": "缓存，可以删", "kind": "cache", "sure": true}`); ok {
		t.Error("不说能不能删")
	}
	for _, bad := range []string{`{"name": "X", "what": "y", "kind": "trash", "sure": true}`, `{"name": "X", "what": "y", "kind": "cache"}`, "不是 JSON"} {
		if _, ok := IdentifyAnswer(bad); ok {
			t.Errorf("%s taken", bad)
		}
	}
	if a, ok := IdentifyAnswer("```json\n{\"name\": \"Gradle\", \"what\": \"Gradle 的缓存\", \"kind\": \"cache\", \"sure\": true}\n```"); !ok || a.Name != "Gradle" {
		t.Errorf("fenced: %v %v", a, ok)
	}

	// The metadata: names and dates only, in the evalset's shape.
	dir := filepath.Join(t.TempDir(), "la-identify")
	for _, p := range []string{"hub/models--a/x.safetensors", "hub/models--a/y.safetensors", "hub/z.json", "token"} {
		u := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(u), 0o755)
		os.WriteFile(u, []byte("x"), 0o644)
	}
	v, ok := IdentifyInput(dir, "~/.cache/huggingface", Size(38<<30), time.Now(), DefaultIdentifyLimits())
	if !ok {
		t.Fatal("not listed")
	}
	get := func(k string) string { x, _ := v.Get(k); return x.Text() }
	if get("路径") != `"~/.cache/huggingface"` || get("大小") != `"40.8 GB"` || get("文件数") != "4" {
		t.Errorf("input %s", v.Text())
	}
	if get("常见扩展名") != `["safetensors", "", "json"]` || get("前几项") != `["hub", "token", "hub/models--a", "hub/z.json"]` {
		t.Errorf("input %s", v.Text())
	}
	if _, ok := IdentifyInput(filepath.Join(dir, "gone"), "~/gone", nil, time.Now(), DefaultIdentifyLimits()); ok {
		t.Error("a folder that is not there")
	}
	home := "/tmp/la-home"
	if IdentifyAsks(Finding{Rule: "space.growth", Category: CatSpace, Severity: Medium, Verdict: Info, Path: "/tmp/la-home/Documents", Bytes: Size(1), Title: "t"}, home) {
		t.Error("人人都认得的不问")
	}
	if !IdentifyAsks(Finding{Rule: "space.growth", Category: CatSpace, Severity: Medium, Verdict: Info, Path: "/tmp/la-home/.qx7", Bytes: Size(1), Title: "t"}, home) {
		t.Error("a folder nobody knows")
	}
}

// The Login Items facts of a stale grant are for the window (data/overview), not for the model: its input is as before.
func TestExplainInputLeavesOutTheLeftBehindFacts(t *testing.T) {
	ev := map[string]string{"grants": "摄像头、登录项", "login_items": "Gone Meet"}
	f := Finding{Rule: "permission.stale-grant", Verdict: Confirm, Title: "t", Evidence: ev}
	before := ExplainInput(f, "")
	ev[LeftItemsKey], ev[LeftStartsKey], ev[LeftDaemonKey] = "Gone Meet", "1", "0"
	if after := ExplainInput(f, ""); !reflect.DeepEqual(before, after) {
		t.Errorf("input changed: %v", after)
	}
}
