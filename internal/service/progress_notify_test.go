package service

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A slow call whose request carries a progressToken says how far it got before it answers (tool protocol §5): MCP's
// notifications/progress, one line each, the token as it came (a string or a number), the message cut to one line's
// worth. Without a token, or called outside Serve, the answer is the only line.
func TestSlowCallSaysHowFarItGot(t *testing.T) {
	srv := NewServer("t", "0")
	srv.Tool("slow", ToolSpec{ReadOnly: true}, func(_ O, meta O) (ToolOutput, error) {
		p := srv.Progress(meta)
		p(1, 2, "正在删：甲的缓存")
		p(2, 2, strings.Repeat("长", 100))
		return ToolOutput{Text: "好了。"}, nil
	})
	serve := func(meta string) []map[string]any {
		var out bytes.Buffer
		in := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow","arguments":{},"_meta":{` + meta + `}}}`
		if code := srv.Serve(strings.NewReader(in), &out); code != 0 {
			t.Fatalf("exit %d", code)
		}
		var lines []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("not JSON: %q", l)
			}
			lines = append(lines, m)
		}
		return lines
	}

	lines := serve(`"progressToken":"overview/b-1"`)
	if len(lines) != 3 {
		t.Fatalf("want two notifications and the answer, got %v", lines)
	}
	for i, n := range lines[:2] {
		p, _ := n["params"].(map[string]any)
		if n["method"] != "notifications/progress" || n["id"] != nil || p["progressToken"] != "overview/b-1" ||
			p["progress"] != float64(i+1) || p["total"] != float64(2) {
			t.Errorf("notification %d: %v", i, n)
		}
	}
	if m := lines[0]["params"].(map[string]any)["message"]; m != "正在删：甲的缓存" {
		t.Errorf("message: %v", m)
	}
	if m, _ := lines[1]["params"].(map[string]any)["message"].(string); len([]rune(m)) != progressMessageMax || !strings.HasSuffix(m, "…") {
		t.Errorf("a long message is cut to %d: %q", progressMessageMax, m)
	}
	if lines[2]["id"] != float64(7) || lines[2]["result"] == nil {
		t.Errorf("the answer comes last: %v", lines[2])
	}

	if lines := serve(`"progressToken":42`); len(lines) != 3 || lines[0]["params"].(map[string]any)["progressToken"] != float64(42) {
		t.Errorf("a number token comes back as the number: %v", lines)
	}
	for _, meta := range []string{``, `"progressToken":""`, `"progressToken":{"a":1}`} {
		if lines := serve(meta); len(lines) != 1 || lines[0]["id"] != float64(7) {
			t.Errorf("_meta {%s}: only the answer, got %v", meta, lines)
		}
	}
	// Called directly (not served): nothing is written anywhere, nothing breaks.
	srv.Progress(O{"progressToken": "x"})(1, 1, "正在删")
	var none *Server
	none.Progress(O{"progressToken": "x"})(1, 1, "正在删")
}
