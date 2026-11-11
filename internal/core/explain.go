package core

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// A finding told in plain words: the generate task luoke-scan.explain (prompts/explain.*) turns what the rules found
// and decided into a sentence or two, on this Mac's own model. The rules decide; the model only explains: its words
// are evidence ExplainNoteKey, shown with the finding, and change nothing else of it. An answer that may mislead is not
// shown: too long, Markdown, a command or an address, something it claims was done, a nudge to delete what the rules
// did not call 放心删, or a number the input does not give (the same checks, written the same way, as
// bench/run_eval.py's: bench/test_checks.py compares the patterns and words, a test the results).

// ExplainTask is luoke-core's name for it; the sentence is evidence ExplainNoteKey (reporttext.go).
const ExplainTask = "luoke-scan.explain"

var explainVerdicts = map[Verdict]string{Safe: "放心删", Confirm: "要确认", Info: "仅供参考"}

// Bounds of the input, in Unicode scalars of the JSON as sent: each fact, and the whole (the task's max_chars in
// luoke-core's recipe is the whole request: about 1800 for the system prompt and examples, 6000 in all).
const (
	explainMaxFact  = 300
	explainMaxInput = 3000
)

// ExplainAsks says whether a finding is explained: what the round's card puts before the user (a decision, or
// something serious only for reference). Not a skill's (it has its own note), not a round's own notes.
func ExplainAsks(f Finding) bool {
	// Nor a dependency's install script: what it says comes from the package, kept away from the model as a skill's is.
	if f.Category == CatSkill || strings.HasPrefix(f.Rule, "deps.install-script") || strings.HasSuffix(f.Rule, ".partial") {
		return false
	}
	if strings.HasPrefix(f.Rule, "model.chat-template") { // a local model's template: its name is from downloaded files
		return false
	}
	return f.Verdict != Info || f.Severity == High
}

// ExplainInput is what the model is given: the verdict, the title, where (as shown to the user; "" none) and how big,
// and the rules' facts as they are (not the scan's own notes, not the list of every target), the longest facts
// shortened, all within explainMaxInput. The shape of the evalset's inputs (bench/make_evalsets.py).
func ExplainInput(f Finding, place string) Value {
	head := []Field{{"结论", VStr(explainVerdicts[f.Verdict])}, {"标题", VStr(ReviewVisible(f.Title, 200))}}
	if place != "" {
		head = append(head, Field{"位置", VStr(ReviewVisible(place, 200))})
	}
	if f.Bytes != nil {
		head = append(head, Field{"大小", VStr(FormatBytes(*f.Bytes))})
	}
	var keys []string
	for k, v := range f.Evidence {
		if !strings.HasPrefix(k, "model_") && k != "targets" && v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var facts []Field
	for _, k := range keys {
		facts = append(facts, Field{k, VStr(ReviewVisible(f.Evidence[k], explainMaxFact))})
	}
	whole := func() Value {
		fields := append([]Field{}, head...)
		if len(facts) > 0 {
			fields = append(fields, Field{"依据", VObj(facts...)})
		}
		return VObj(fields...)
	}
	// Over the bound: the longest fact goes first, until it fits.
	for len(facts) > 0 && whole().Size() > explainMaxInput {
		longest := 0
		for i := range facts {
			if facts[i].Value.Size() > facts[longest].Value.Size() {
				longest = i
			}
		}
		facts = append(facts[:longest:longest], facts[longest+1:]...)
	}
	return whole()
}

// ---------------------------------------------------------------- what may be shown

var explainCommands = []string{"sudo", "rm", "rmdir", "mv", "cp", "ln", "tccutil", "launchctl", "defaults", "killall", "kill", "pkill", "chmod", "chown",
	"chflags", "xattr", "brew", "pip3?", "npm", "npx", "go", "uv", "cargo", "git", "docker", "find", "du", "open", "softwareupdate",
	"freshclam", "clamscan", "diskutil", "tmutil", "fdesetup", "csrutil", "spctl", "codesign", "mdutil", "sfltool", "curl", "wget",
	"python3?", "xcode-select", "xcrun"}

var (
	explainCommand  = icuCS(`(?<![A-Za-z0-9_])(` + strings.Join(explainCommands, "|") + `)\s+-{0,2}[A-Za-z~/.]`)
	explainKillPID  = icuCS(`(?<![A-Za-z0-9_])(kill|pkill)\s+-?\d`)
	explainMarkdown = icuLines("(^\\s*(#|[-*]\\s|\\d+\\.\\s))|\\*\\*|`")
	explainClaimed  = []string{"已移到废纸篓", "已经移到废纸篓", "已移入废纸篓", "已经帮你", "已帮你", "已为你", "已经为你", "已替你", "已经替你", "已清理",
		"已经清理", "已清掉", "已经清掉", "已处理", "已经处理", "已腾出", "已经腾出"}
	explainAllowDelete = []string{"放心删", "放心清理", "随便删", "可以直接删", "直接删就行", "直接删吧", "删了也没事", "删掉也没事", "删了也没关系",
		"删掉也没关系", "也没关系", "风险不大", "没有风险", "没什么风险", "没啥风险", "问题不大", "不会有任何影响", "不会有影响",
		"删了不影响", "删掉不影响", "删除不影响", "删了没事", "删掉没事", "不用担心它占空间"}
	explainInfoDelete = []string{"可以删", "可以删掉", "可以删除", "可以清理", "可以清掉", "删掉腾出", "删除腾出", "删了能腾出", "删掉能腾出"}
	explainNegators   = []string{"不", "别", "没法", "无法", "不能", "不要", "不可", "不可以", "未必", "不一定", "先别", "千万别", "没说", "不是", "并非", "切勿", "勿",
		"不代表", "不等于", "不意味着", "不建议", "不必", "无需", "不需要"}
	explainHedges = []string{"", "是", "太", "太是", "会是", "太会是", "可能是", "太可能是", "像", "像是", "太像", "太像是", "算", "算是"}
	explainQuotes = "「」『』“”\"'‘’《》"
)

// explainAffirmative: phrase occurs in text and is not negated: no negator right before it, give or take a hedge;
// whitespace and quotation marks do not count (bench/run_eval.py's affirmative).
func explainAffirmative(text, phrase string) bool {
	var flat, p []rune
	for _, c := range text {
		if !unicode.Is(unicode.White_Space, c) && !strings.ContainsRune(explainQuotes, c) {
			flat = append(flat, c)
		}
	}
	for _, c := range phrase {
		if !unicode.Is(unicode.White_Space, c) {
			p = append(p, c)
		}
	}
	if len(p) == 0 || len(flat) < len(p) {
		return false
	}
	for i := 0; i+len(p) <= len(flat); {
		if string(flat[i:i+len(p)]) != string(p) {
			i++
			continue
		}
		before := string(flat[max(0, i-8):i])
		negated := false
		for _, n := range explainNegators {
			for _, h := range explainHedges {
				if strings.HasSuffix(before, n+h) {
					negated = true
				}
			}
		}
		if !negated {
			return true
		}
		i += len(p) // re.finditer: matches do not overlap
	}
	return false
}

// ---------------------------------------------------------------- numbers it may say (given_numbers, without_given_dates)

var (
	// explainNumber: a number with a unit; explainLeading: the number that leads it; explainWhole: a whole value;
	// explainListSeparators: the separators of a list of numbers.
	explainNumber         = icuCS(`\d+(?:\.\d+)?\s*(?:GB|MB|KB|TB|个|天|小时|分钟|秒|周|月|年|项|条|次|倍|%)`)
	explainLeading        = icuCS(`\d+(?:\.\d+)?`)
	explainWhole          = icuCS(`\d+`)
	explainListSeparators = icuCS(`[,，、；;]`)
	explainDateIn         = icuCS(`(\d{4})-(\d{2})-(\d{2})`)
	explainDateOut        = icuCS(`(?:(\d{4})\s*年\s*)?(?:(\d{1,2})\s*月\s*)?(?:(\d{1,2})\s*日)?`)
	explainYear           = icuCS(`(?<!\d)((?:19|20)\d{2})(?!\d)`)
)

// decimalDigit is the value of a decimal digit of any script (Unicode keeps each script's ten in a row from 0).
func decimalDigit(c rune) (int, bool) {
	if c >= '0' && c <= '9' {
		return int(c - '0'), true
	}
	if !unicode.Is(unicode.Nd, c) {
		return 0, false
	}
	for _, r := range unicode.Nd.R16 {
		if rune(r.Lo) <= c && c <= rune(r.Hi) {
			return int(c-rune(r.Lo)) % 10, true
		}
	}
	for _, r := range unicode.Nd.R32 {
		if rune(r.Lo) <= c && c <= rune(r.Hi) {
			return int(c-rune(r.Lo)) % 10, true
		}
	}
	return 0, false
}

// explainValue is the number written in s (Python's float(): any script's decimal digits, whitespace around).
func explainValue(s string) (float64, bool) {
	var b strings.Builder
	for _, c := range aiTrimWSNL(s) {
		if d, ok := decimalDigit(c); ok {
			b.WriteByte(byte('0' + d))
		} else {
			b.WriteRune(c)
		}
	}
	t := b.String()
	if t == "" || strings.ContainsAny(t, "_xXpP") {
		return 0, false
	}
	f, err := strconv.ParseFloat(t, 64)
	return f, err == nil
}

// fullMatch: all of s matches re (the first match at the start covers it).
func fullMatch(re *icuRegexp, s string) bool {
	r := []rune(s)
	m := re.find(r, 0)
	return m != nil && m[0] == 0 && m[1] == len(r)
}

// leadingValue is the number that leads a match of explainNumber.
func leadingValue(s string) (float64, bool) {
	r := []rune(s)
	m := explainLeading.find(r, 0)
	if m == nil || m[0] != 0 {
		return 0, false
	}
	return explainValue(string(r[m[0]:m[1]]))
}

// ExplainGivenNumbers are the numbers the input states as quantities: with a unit ("7.9 GB", "25 个") or as a whole
// value ("25"), and each of a list ("901,902,903"). Not digits taken out of dates, ids or paths.
func ExplainGivenNumbers(v Value) map[float64]bool {
	out := map[float64]bool{}
	var walk func(Value)
	walk = func(v Value) {
		switch v.Kind {
		case VObject:
			for _, f := range v.Obj {
				walk(f.Value)
			}
		case VArray:
			for _, x := range v.Arr {
				walk(x)
			}
		case VInt:
			out[float64(v.Int)] = true
		case VNumber:
			if n, err := strconv.ParseFloat(v.Str, 64); err == nil {
				out[n] = true
			}
		case VString:
			s := v.Str
			if fullMatch(explainLeading, aiTrimWSNL(s)) {
				if n, ok := explainValue(s); ok {
					out[n] = true
				}
			}
			r := []rune(s)
			for _, m := range explainNumber.findAll(r) {
				if n, ok := leadingValue(string(r[m[0]:m[1]])); ok {
					out[n] = true
				}
			}
			var parts []string
			last := 0
			for _, m := range explainListSeparators.findAll(r) {
				parts = append(parts, string(r[last:m[0]]))
				last = m[1]
			}
			parts = append(parts, string(r[last:]))
			for _, p := range parts {
				if fullMatch(explainWhole, aiTrimWSNL(p)) {
					if n, ok := explainValue(p); ok {
						out[n] = true
					}
				}
			}
		}
	}
	walk(v)
	return out
}

// explainWithoutGivenDates is out with the dates it takes from the input taken out ("2025 年 11 月", "9 月 2 日" for
// 2025-11-03, 2026-09-02), and a year the input names in passing ("2023 年的照片" for a folder called photos-2023), so
// their parts are not taken for made-up numbers. A date the input does not have stays.
func explainWithoutGivenDates(out string, given Value) string {
	text := []rune(given.Text())
	toInt := func(s string) (int, bool) {
		f, ok := explainValue(s)
		return int(f), ok
	}
	var dates [][3]int
	for _, m := range explainDateIn.findAll(text) {
		var g [3]int
		ok := true
		for k := 1; k <= 3; k++ {
			n, good := toInt(string(text[m[2*k]:m[2*k+1]]))
			g[k-1] = n
			ok = ok && good
		}
		if ok {
			dates = append(dates, g)
		}
	}
	years := map[int]bool{}
	for _, m := range explainYear.findAll(text) {
		if n, ok := toInt(string(text[m[2]:m[3]])); ok {
			years[n] = true
		}
	}
	r := []rune(out)
	var b strings.Builder
	at := 0
	for _, m := range explainDateOut.findAll(r) {
		if m[1] == m[0] {
			continue
		}
		whole := string(r[m[0]:m[1]])
		if aiTrimWSNL(whole) == "" {
			continue
		}
		var parts [3]*int
		count := 0
		for k := 1; k <= 3; k++ {
			if m[2*k] >= 0 {
				if n, ok := toInt(string(r[m[2*k]:m[2*k+1]])); ok {
					parts[k-1] = &n
					count++
				}
			}
		}
		truthy := func(x *int) bool { return x != nil && *x != 0 }
		y, mo, d := parts[0], parts[1], parts[2]
		keep := true
		if truthy(y) && !truthy(mo) && !truthy(d) {
			keep = !years[*y]
		} else if count >= 2 {
			for _, g := range dates {
				if (y == nil || *y == g[0]) && (mo == nil || *mo == g[1]) && (d == nil || *d == g[2]) && !(truthy(y) && truthy(d) && !truthy(mo)) {
					keep = false
					break
				}
			}
		}
		b.WriteString(string(r[at:m[0]]))
		if keep {
			b.WriteString(whole)
		}
		at = m[1]
	}
	b.WriteString(string(r[at:]))
	return b.String()
}

// ExplainMadeUpNumber says whether out has a number with a unit the input does not give (the eval's hard check
// 「不编数字」).
func ExplainMadeUpNumber(out string, input Value) bool {
	given := ExplainGivenNumbers(input)
	rest := []rune(explainWithoutGivenDates(out, input))
	for _, m := range explainNumber.findAll(rest) {
		n, ok := leadingValue(string(rest[m[0]:m[1]]))
		if !ok || !given[n] {
			return true
		}
	}
	return false
}

// hasAddress: an address of any kind (the rules show none, and neither does the model).
func hasAddress(s string) bool {
	if strings.Contains(s, "://") || strings.Contains(aiLower(s), "www.") {
		return true
	}
	for _, re := range []*icuRegexp{reviewIPv4, reviewEmail, reviewDomain, reviewDefanged} {
		if re.has(s) {
			return true
		}
	}
	return false
}

// ExplainAnswer is the sentence to show for f (asked with input); ok false when the answer may not be shown.
func ExplainAnswer(raw string, f Finding, input Value, maxChars int) (string, bool) {
	out := WithoutThinking(raw)
	if out == "" || scalars(out) > maxChars || explainCommand.has(out) || explainKillPID.has(out) || explainMarkdown.has(out) {
		return "", false
	}
	for _, c := range explainClaimed {
		if strings.Contains(out, c) {
			return "", false
		}
	}
	if hasAddress(out) {
		return "", false
	}
	if f.Verdict != Safe {
		bad := explainAllowDelete
		if f.Verdict == Info {
			bad = append(append([]string{}, explainAllowDelete...), explainInfoDelete...)
		}
		for _, p := range bad {
			if explainAffirmative(out, p) {
				return "", false
			}
		}
	}
	if ExplainMadeUpNumber(out, input) {
		return "", false
	}
	return out, true
}
