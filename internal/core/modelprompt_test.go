package core

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the repository (two folders above this package).
func repoRoot(t *testing.T) string {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// python runs a script with the repository's bench/ importable; its standard output.
func python(t *testing.T, script, stdin string) string {
	t.Helper()
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no /usr/bin/python3")
	}
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", script, repoRoot(t))
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("python: %v\n%s", err, errOut.String())
	}
	return out.String()
}

// What the scan sends luoke-core is what the release eval sends: for every evalset item of the three tasks, the request
// body (system prompt, examples, the item, schema, sampling) byte for byte as bench/run_eval.py makes it, and the
// prompt's fingerprint as bench/prompts.py takes it.
func TestRequestBodiesAreTheEvalsBytes(t *testing.T) {
	const script = `
import json, sys
sys.path.insert(0, sys.argv[1] + "/bench")
import run_eval as r
for name in ("explain", "identify", "skills"):
    p = r.load_prompt(name)
    items = json.load(open(sys.argv[1] + "/bench/evalsets/" + name + ".json", encoding="utf-8"))["items"]
    for it in items:
        b = r.request_body(p["task"], r.messages_for(p["task"], p, it), p.get("schema"), p["max_tokens"], r.sampling(p))
        sys.stdout.buffer.write((name + "\t" + it["id"] + "\t" + p["sha256"] + "\t" + json.dumps(b, ensure_ascii=False) + "\n").encode("utf-8"))
`
	type made struct{ sha, body string }
	py := map[string]made{}
	for _, line := range strings.Split(strings.TrimSuffix(python(t, script, ""), "\n"), "\n") {
		f := strings.SplitN(line, "\t", 4)
		if len(f) != 4 {
			t.Fatalf("python line: %q", line)
		}
		py[f[0]+"/"+f[1]] = made{f[2], f[3]}
	}
	root := repoRoot(t)
	compared := 0
	for _, name := range []string{"explain", "identify", "skills"} {
		p, err := LoadPrompt(name, filepath.Join(root, "prompts"))
		if err != nil {
			t.Fatal(err)
		}
		if p.Task != "luoke-scan."+name {
			t.Errorf("%s: task %q", name, p.Task)
		}
		data, err := os.ReadFile(filepath.Join(root, "bench/evalsets", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		set, err := ParseValue(data)
		if err != nil {
			t.Fatal(err)
		}
		items, _ := set.Get("items")
		for _, it := range items.Arr {
			idv, _ := it.Get("id")
			input, _ := it.Get("input")
			want, ok := py[name+"/"+idv.Str]
			if !ok {
				t.Errorf("%s/%s: the eval did not make it", name, idv.Str)
				continue
			}
			if p.SHA256 != want.sha {
				t.Errorf("%s: fingerprint %s, the eval's %s", name, p.SHA256, want.sha)
			}
			body, err := p.Body(input)
			if err != nil {
				t.Fatal(err)
			}
			if body != want.body {
				t.Errorf("%s/%s: the body differs from the eval's", name, idv.Str)
			}
			compared++
		}
	}
	if compared != len(py) || compared < 128 {
		t.Errorf("compared %d of %d", compared, len(py))
	}
}

func TestPlaceholdersAllFilledNoneExtra(t *testing.T) {
	if s, err := fillPrompt("a{{x}}b{{x}}", map[string]string{"x": "1"}, "t"); err != nil || s != "a1b1" {
		t.Errorf("fill: %q %v", s, err)
	}
	if _, err := fillPrompt("a{{x}}", map[string]string{}, "t"); err == nil {
		t.Error("a placeholder not filled")
	}
	if _, err := fillPrompt("a", map[string]string{"x": "1"}, "t"); err == nil {
		t.Error("a value for no placeholder")
	}
	if _, err := LoadPrompt("explain", t.TempDir()); err == nil {
		t.Error("a folder without the task")
	}
}

func TestOrderedJSONWrittenAsPython(t *testing.T) {
	v, err := ParseValue([]byte(`{"b": 1, "a": [true, null, 2.5, -3], "c": "x\"\né😀", "b": 2}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Text(); got != `{"b": 2, "a": [true, null, 2.5, -3], "c": "x\"\né😀"}` {
		t.Errorf("text %s", got)
	}
	for _, bad := range []string{"{", "[1,]", `{"a" 1}`, "01x", `"\q"`} {
		if _, err := ParseValue([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	// JSONSerialization keeps the first of a repeated key.
	if f, err := ParseFoundation(`{"a": 1, "a": 2}`); err != nil || f.Text() != `{"a": 1}` {
		t.Errorf("first wins: %s %v", f.Text(), err)
	}
	w := VObj(Field{"a", VStr("引号\" 反斜杠\\ 换行\n 制表\t 回车\r 退格\b 换页\f 控制\x01 中文 emoji 👨‍👩‍👧 ⟨⟩")},
		Field{"b", VList(VInteger(3), VBoolean(true), VNullValue, VList(), VObj())})
	if got := w.Text(); got != `{"a": "引号\" 反斜杠\\ 换行\n 制表\t 回车\r 退格\b 换页\f 控制\u0001 中文 emoji 👨‍👩‍👧 ⟨⟩", "b": [3, true, null, [], {}]}` {
		t.Errorf("text %s", got)
	}
}

func TestThinkingTakenOut(t *testing.T) {
	for in, want := range map[string]string{"<think>abc": "", "abc</think>答案": "答案", "<think>x</think> 答 ": "答"} {
		if got := WithoutThinking(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
