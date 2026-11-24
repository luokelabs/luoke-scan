package core

import "strings"

// What a skill names without doing it, next to the lists of strings (skillListedLines):
//
//   - in a shell script, what a test compares a value with (`[[ "$cmd" == *"mkfs"* ]]`, `[ "$1" = mkfs ]`) and the
//     patterns of a `case`: a guard that refuses a command names it there and never runs it;
//   - in prose, one of a parenthesised list of bare names that trails off (`(rm -rf, dd, mkfs, etc)`): examples of a
//     kind of command, as a prompt gives them to a model, not steps to take. The shape is not enough: the sentence
//     must not be telling anyone to run them (`run the setup steps (csrutil disable, spctl --master-disable, etc)`),
//     and it must read as examples: it is about catching or refusing, it says "such as", or the list follows the name
//     of a kind (`Destructive operations (…)`).
//
// Only the compared word and the patterns are taken out of the line; what stands after them on it is read as before
// (`[[ "$m" == quick ]] || dd if=/dev/zero of=/dev/rdisk2`). When in doubt the line is left as it is: a substitution
// or `$'…'` anywhere on it (their quotes pair differently, and a substitution runs), a quote left open, a word with
// `;`, `&`, `|`, `<`, `>` or a parenthesis outside quotes, anything that is not ASCII. And as with the lists: in a
// script that runs strings (eval, sh -c, a line that is a variable) everything counts.

const skillCaseWord = `(?:"[^"\\$\x{60}]*"|'[^']*'|\\.|[^\s"'\\|()<>;&$\x{60}])+`

var (
	// A case's patterns at the start of a line (after `case … in` on it, or on a line of their own), up to the `)`.
	skillCasePattern = icuCS(`^\s*(case\s+(?:"[^"]*"|\S+)\s+in\s+)?\(?\s*(` + skillCaseWord + `(?:\s*\|\s*` + skillCaseWord + `)*)\s*\)`)
	// Lines after which a pattern comes next: `case … in`, and the end of a branch.
	skillCaseOpens = icuCS(`\bcase\s+\S.*\sin\s*$`)
	skillCaseNext  = icuCS(`;;&?\s*$|;&\s*$`)
	skillShebangSh = icuCS(`^#!.*\b(?:ba|z|k|da)?sh\b`)
	skillBareName  = icuCS(`^[\w.+-]+(?:\s+[\w.+-]+){0,3}$`)
	skillAndSoOn   = icuCI(`^(?:etc\.?|\.\.\.|…|and\s+so\s+on|and\s+(?:the\s+)?(?:like|more|others)|等|等等|之类)$`)
	// Telling someone to do it.
	skillListDo = icuCI(`\b(?:run(?:s|ning)?|ran|execut(?:e|es|ed|ing)|do|done|perform(?:s|ed|ing)?|invok(?:e|es|ed|ing)|call(?:s|ed|ing)?|us(?:e|es|ed|ing)|appl(?:y|ies|ied|ying)|start(?:s|ed|ing)?|launch(?:es|ed|ing)?|issu(?:e|es|ed|ing)|enter(?:s|ed|ing)?|typ(?:e|ed|ing)|proceed|carr(?:y|ied)\s+out)\b|运行|执行|跑|使用|调用|输入|启动|照做`)
	// Catching, refusing, keeping away from: what such a word governs is not asked for.
	skillListGuard = icuCI(`\b(?:detect\w*|block(?:s|ed|ing)?|den(?:y|ies|ied|ying)|refus(?:e|es|ed|ing)|reject(?:s|ed|ing)?|avoid(?:s|ed|ing)?|never|prevent(?:s|ed|ing)?|forbid(?:s|den)?|prohibit(?:s|ed|ing)?|disallow(?:s|ed)?|do\s*n[o']?t|must\s*n[o']?t|should\s*n[o']?t|flag(?:s|ged|ging)?|warn(?:s|ed|ing)?|(?:look|check|scan|watch|analy[sz]e)(?:s|ed|ing)?\s+for)\b|识别|拦截|禁止|避免|检测|拒绝|不要|不得|切勿|阻止`)
	// Between a guarding word and a doing word, what starts a clause of its own.
	skillListTurn   = icuCI(`[,:，：、—]|\s-\s|\b(?:and|then|but|instead|just)\b|然后|再|并|而是`)
	skillListSuchAs = icuCI(`\b(?:such\s+as|like|e\.g\.?|for\s+example|for\s+instance|including)(?![\w])|例如|比如|诸如|譬如`)
	// The name of a kind before the list: a few words, the last one a plural for things of a sort.
	skillListKind = icuCI(`^(?:[a-z][a-z-]*\s+){0,3}(?:operations|commands|actions|patterns|changes|calls|tools|utilities|programs|binaries|flags|examples|cases|categories|kinds|types|behaviou?rs|activities|writes|deletions|modifications)$|^[\x{4e00}-\x{9fff}]{0,10}(?:操作|命令|行为|动作|写法|模式|工具)$`)
	// Not a kind but things to get done.
	skillListToDo = icuCI(`\b(?:setup|set-up|install\w*|required?|requirements?|prerequisites?|necessary|needed|first|initial|must|should|todo|to-do|next|now)\b|必须|需要|先|安装|准备|步骤`)
	skillListMark = icuCS(`^(?:[-*+>#]+|\(?\d{1,2}[.)]|\(?[a-zA-Z][.)])\s+`)
)

// skillShellScript says whether a script is a shell's, by its name or its first line.
func skillShellScript(path, text string) bool {
	switch strings.ToLower(aiNSExt(aiNSLast(path))) {
	case "sh", "bash", "zsh", "ksh", "command":
		return true
	}
	first, _, _ := strings.Cut(text, "\n")
	return skillShebangSh.has(first)
}

type shellWord struct {
	from, to int
	// plain: nothing in it but text and quoted text.
	plain bool
}

// skillShellWords are a line's words as a shell splits them, quoted text kept together; false when a quote is left
// open.
func skillShellWords(s []rune) ([]shellWord, bool) {
	var words []shellWord
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		w := shellWord{from: i, plain: true}
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			switch s[i] {
			case '\\':
				i += 2
			case '\'':
				i++
				for i < len(s) && s[i] != '\'' {
					i++
				}
				if i >= len(s) {
					return nil, false
				}
				i++
			case '"':
				i++
				for i < len(s) && s[i] != '"' {
					if s[i] == '\\' {
						i++
					}
					i++
				}
				if i >= len(s) {
					return nil, false
				}
				i++
			case ';', '&', '|', '(', ')', '<', '>':
				w.plain = false
				i++
			default:
				i++
			}
		}
		if i > len(s) {
			i = len(s)
		}
		w.to = i
		for _, r := range s[w.from:w.to] {
			if r >= 0x80 {
				w.plain = false
			}
		}
		words = append(words, w)
	}
	return words, true
}

func skillIsASCII(s []rune) bool {
	for _, r := range s {
		if r >= 0x80 {
			return false
		}
	}
	return true
}

// skillWithoutTests is a shell line without what its tests compare with: the word after `==`, `=`, `!=` or `=~`
// between `[[` and `]]` or `[` and `]`, both on the line.
func skillWithoutTests(s []rune) []rune {
	str := string(s)
	if !strings.Contains(str, "[ ") || strings.Contains(str, "$(") || strings.Contains(str, "`") || strings.Contains(str, "$'") {
		return s
	}
	words, ok := skillShellWords(s)
	if !ok {
		return s
	}
	word := func(k int) string { return string(s[words[k].from:words[k].to]) }
	var cut [][2]int
	for i := 0; i < len(words); i++ {
		closer := ""
		switch word(i) {
		case "[[":
			closer = "]]"
		case "[":
			closer = "]"
		default:
			continue
		}
		j := i + 1
		for j < len(words) && !strings.HasPrefix(word(j), closer) {
			j++
		}
		if j == len(words) {
			break
		}
		for k := i + 1; k+1 < j; k++ {
			switch word(k) {
			case "==", "=", "!=", "=~":
				if words[k+1].plain {
					cut = append(cut, [2]int{words[k+1].from, words[k+1].to})
				}
				k++
			}
		}
		i = j
	}
	if len(cut) == 0 {
		return s
	}
	out := make([]rune, 0, len(s))
	at := 0
	for _, c := range cut {
		out = append(append(out, s[at:c[0]]...), '"', '"')
		at = c[1]
	}
	return append(out, s[at:]...)
}

// skillWithoutCompared is a shell script without what it only compares with (see above), line for line; the script
// itself when it runs strings.
func skillWithoutCompared(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, len(lines))
	changed, pattern := false, false
	for i, l := range lines {
		out[i] = l
		t := aiTrimWS(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		s := []rune(strings.TrimSuffix(l, "\r"))
		r := skillWithoutTests(s)
		if m := skillCasePattern.find(r, 0); m != nil && (pattern || m[2] >= 0) && skillIsASCII(r[m[4]:m[5]]) {
			r = append(append(append([]rune{}, r[:m[4]]...), '"', '"'), r[m[5]:]...)
		}
		pattern = skillCaseOpens.hasRunes(s) || skillCaseNext.hasRunes(s)
		if len(r) != len(s) || string(r) != string(s) {
			out[i], changed = string(r), true
		}
	}
	if !changed {
		return text
	}
	if skillRunsStrings(out, skillStringRuns(out)) {
		return text
	}
	return strings.Join(out, "\n")
}

// skillNamedInList says whether a match is one of a parenthesised list of bare names that trails off: three or more
// items between commas, each a name of at most four words (no path, address, pipe or assignment in it), the last one
// "etc" or the like.
func skillNamedInList(s []rune, m []int) bool {
	from, to := m[0], m[1]
	for from < to && (skillSpace(s[from]) || strings.ContainsRune("(（,，、", s[from])) {
		from++
	}
	for to > from && (skillSpace(s[to-1]) || strings.ContainsRune(")）,，、", s[to-1])) {
		to--
	}
	if from >= to {
		return false
	}
	open, shut := -1, -1
	for i, depth := from-1, 0; i >= 0; i-- {
		if s[i] == ')' || s[i] == '）' {
			depth++
		} else if s[i] == '(' || s[i] == '（' {
			if depth == 0 {
				open = i
				break
			}
			depth--
		}
	}
	for i, depth := to, 0; i < len(s); i++ {
		if s[i] == '(' || s[i] == '（' {
			depth++
		} else if s[i] == ')' || s[i] == '）' {
			if depth == 0 {
				shut = i
				break
			}
			depth--
		}
	}
	if open < 0 || shut < 0 || (open > 0 && s[open-1] == '$') {
		return false
	}
	separator := func(r rune) bool { return r == ',' || r == '，' || r == '、' }
	for _, r := range s[from:to] {
		if separator(r) {
			return false
		}
	}
	items := strings.FieldsFunc(string(s[open+1:shut]), separator)
	if len(items) < 3 {
		return false
	}
	for i, item := range items {
		item = strings.Trim(aiTrimWS(item), "`'\"*")
		if i == len(items)-1 {
			if !skillAndSoOn.has(item) {
				return false
			}
		} else if !skillBareName.has(item) {
			return false
		}
	}
	return skillListOfExamples(s, open, shut)
}

// skillListOfExamples says whether the sentence around a list (its parentheses at open and shut) gives the list as
// examples: nothing in it tells anyone to do something (a doing word counts unless a guarding word governs it:
// "refuse to run", "never use"), and it is about catching or refusing, says "such as", or names a kind right before
// the list. When in doubt it does not.
func skillListOfExamples(s []rune, open, shut int) bool {
	ends := func(i int) bool {
		switch s[i] {
		case '\n', '!', '?', ';', '。', '！', '？', '；':
			return true
		case '.':
			return i+1 >= len(s) || skillSpace(s[i+1])
		}
		return false
	}
	from, to := open, shut+1
	for from > 0 && !ends(from-1) {
		from--
	}
	for to < len(s) && !ends(to) {
		to++
	}
	sentence := append(append(append([]rune{}, s[from:open]...), ' '), s[shut+1:to]...)
	guards := skillListGuard.findAll(sentence)
	for _, do := range skillListDo.findAll(sentence) {
		governed := false
		for _, g := range guards {
			if g[0] <= do[0] && do[0]-g[1] <= 60 && (g[1] >= do[0] || !skillListTurn.hasRunes(sentence[g[1]:do[0]])) {
				governed = true
			}
		}
		if !governed {
			return false
		}
	}
	if len(guards) > 0 || skillListSuchAs.hasRunes(sentence) {
		return true
	}
	// The name of a kind: what stands before the list, after the last colon and a list's marker.
	before := string(s[from:open])
	if i := strings.LastIndexAny(before, ":："); i >= 0 {
		before = before[i+1:]
	}
	before = aiTrimWS(before)
	for {
		cut := aiTrimWS(skillListMark.replaceString(before, ""))
		if cut == before {
			break
		}
		before = cut
	}
	before = strings.Trim(before, "*_`\"' ")
	return skillListKind.has(before) && !skillListToDo.has(before)
}

func skillSpace(r rune) bool { return r == ' ' || r == '\t' || r == 0x3000 || r == 0xA0 }
