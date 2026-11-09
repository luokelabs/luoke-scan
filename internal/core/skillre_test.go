package core

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// testdata/skillre_icu.json: every pattern the skill and secret checks use, each with lines and what
// NSRegularExpression (ICU) found in them -- the first match and its groups, as UTF-16 offset and length; "" none.
// Recorded from the Swift version's patterns over the eval cases, the black-box fixtures and lines made of their
// pieces (Chinese next to words, full-width spaces, combining marks, odd line ends, case-folding look-alikes).
func TestPatternsAnswerAsICU(t *testing.T) {
	data, err := os.ReadFile("testdata/skillre_icu.json")
	if err != nil {
		t.Fatal(err)
	}
	var table []struct {
		P     string      `json:"p"`
		CI    bool        `json:"ci"`
		Cases [][2]string `json:"cases"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range table {
		r := buildICURegexp(e.P, e.CI)
		for _, c := range e.Cases {
			s := []rune(c[0])
			got := ""
			if m := r.find(s, 0); m != nil {
				var parts []string
				for g := 0; g < len(m)/2; g++ {
					if m[2*g] < 0 {
						parts = append(parts, "-1", "-1")
						continue
					}
					parts = append(parts, strconv.Itoa(aiUTF16Len(s[:m[2*g]])), strconv.Itoa(aiUTF16Len(s[m[2*g]:m[2*g+1]])))
				}
				got = strings.Join(parts, " ")
			}
			if got != c[1] {
				t.Errorf("%q (ci %v) on %q: ICU %q, here %q", e.P, e.CI, c[0], c[1], got)
			}
			n++
		}
	}
	if n < 500 {
		t.Fatalf("only %d cases", n)
	}
}

func TestRegexSyntax(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ci   bool
		want string
	}{
		{`(?<![A-Za-z0-9/_.-])sk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}`, "key=sk-test-fixture-000000000000", false, "sk-test-fixture-000000000000"},
		{`(?<![A-Za-z0-9/_.-])sk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}`, "/sk-learn-something-long-enough-0", false, ""},
		{`\bcurl\b`, "用curl下载", true, ""}, // ICU's \b: Chinese characters are word characters
		{`\bcurl\b`, "用 curl 下载", true, "curl"},
		{`a\s+b`, "a　b", false, "a　b"}, // a full-width space is \s
		{`x$`, "x\r", false, "x"},      // $ before a line terminator at the end
		{`[a-z]+?q`, "abcq", false, "abcq"},
		{`(?:ab|a)(?:bc|c)`, "abc", false, "abc"},
		{`KELVIN`, "Kelvin", true, "Kelvin"},
	} {
		got := ""
		s := []rune(c.s)
		if m := buildICURegexp(c.p, c.ci).find(s, 0); m != nil {
			got = string(s[m[0]:m[1]])
		}
		if got != c.want {
			t.Errorf("%q on %q: %q, want %q", c.p, c.s, got, c.want)
		}
	}
}

// testdata/graphemes_swift.json: strings of letters, marks, emoji, flags, joiners, Hangul jamo, Indic conjuncts and
// line ends, with Swift's String.count of each.
func TestCharactersCountAsSwift(t *testing.T) {
	data, err := os.ReadFile("testdata/graphemes_swift.json")
	if err != nil {
		t.Fatal(err)
	}
	var pairs [][2]json.RawMessage
	if err := json.Unmarshal(data, &pairs); err != nil {
		t.Fatal(err)
	}
	for _, p := range pairs {
		var s string
		var n int
		json.Unmarshal(p[0], &s)
		json.Unmarshal(p[1], &n)
		if g := graphemeCount(s); g != n {
			t.Errorf("%+q: Swift counts %d, here %d", s, n, g)
		}
	}
}
