package core

import "strings"

// One command at a time (luoke-scan#235).
//
// The checks used to judge a physical line: any "never" or "dangerous" before a match on the line made it talk, a
// command continued over two lines was two halves, and a pipeline was whatever one pattern could span. Here a script
// is first put into the units a shell runs, and the checks are applied to those:
//
//   - a logical line: a command continued with a backslash at the end of a line is put on its first line
//     (skillJoinContinued), where its hits are reported;
//   - a command: a logical line is cut at `;`, `&&`, `||`, `|`, `&` outside quotes, `$(…)`, back quotes and `${…}`
//     (shellLex). Each command knows where it stands on the line, which pipeline it belongs to and which stage of it
//     it is; a comment at the end of the line belongs to none;
//   - a pipeline: the commands joined by `|`. The patterns are matched against one pipeline at a time, the rest of
//     the line blanked (skillReading.show), so every pipeline is read as if it stood on a line of its own;
//   - what a match's words are (shellScope): a negation ("never", "do not") or a word about risks ("malicious",
//     "detect") makes a match talk only when it stands in the same command and outside quotes, or in the same quoted
//     string as the match (`echo "never run rm -rf ~"` prints a sentence). What a substitution runs is run whatever
//     stands around it, so only its own command counts there;
//   - a pipeline's stages (shellPiped): a download in one stage and, in a later one, a shell or interpreter that runs
//     what comes in, also behind the commands that only wrap another (xargs, env, nohup, timeout, sudo…).
//
// Used by skillScanFileWith (skillReading): every pattern, the writes to places that matter, and the pairs made of
// their hits (a key read and data sent) go through it for a shell script. A script that is not a shell's is cut at
// `;` only (scriptStatement).
//
// Prose is read sentence by sentence, but for the lines of a fenced code block: those are commands the agent is told
// to run, so a continued command is joined and the line's own words are judged command by command, as a shell's when
// the fence names no language or a shell (skillFenceShell), else statement by statement. What stands around the block
// (its section, the sentence that leads to it) still speaks for all of it, and so do the words about risks in a
// comment at the end of the line: in the instructions a comment is read too (skillReading.prose). A block that names
// plain text or Markdown (skillFenceText) and a line that is a table's row (it begins with `|`) stay sentences.
//
// The install checks have their own idea of what talks (installscript.go: words never do). They take two things from
// here: a continued command is read joined as well (installReadings), and a pipeline's stages (shellPiped).
//
// A line is lexed on its own, as if it began outside quotes; a string that goes on over several lines makes that
// wrong for the lines it crosses. So nothing here trusts the side of a quote it seems to be on more than it must:
//
//   - a quote (or substitution) left open on the line runs to its end, as a string of its own (shellLine.ok is false);
//   - the words outside a quoted string speak for a match inside it only when the match stands in the string's first
//     command: were the "string" in truth the code after a string closed (`never"; rm -rf ~; echo "`), a command of
//     its own in it comes after a separator;
//   - a `#` begins a comment only when no quote character follows it on the line.

// shellDepth is how far into quoted strings and substitutions the reading goes.
const shellDepth = 4

type shellSpan struct{ from, to int }

// shellNested is a quoted string or a substitution inside a command: its text, without the quotes or `$(` and `)`.
type shellNested struct {
	from, to int
	// runs: `$(…)`, back quotes, `<(…)`: a shell runs what is in it.
	runs bool
}

// shellCommand is one command of a line: s[from:to], without the separators around it.
type shellCommand struct {
	from, to int
	// pipeline counts the line's pipelines, stage the commands of one (from 0).
	pipeline, stage int
	nested          []shellNested
}

type shellLine struct {
	// ok: every quote, substitution and `${` on the line is closed. When not, what was left open runs to the end of
	// the line (a `${` is taken as text).
	ok bool
	// open: what was left open first (', ", `, ( or {).
	open     rune
	commands []shellCommand
	// comment: where a comment at the end of the line begins; the end of the line when there is none.
	comment int
	// hash: where the first # that may begin a comment stands, taken for one or not; -1 when there is none.
	hash int
}

// shellApostrophe says whether the ' at i stands inside a word (don't): it opens nothing.
func shellApostrophe(s []rune, i, lo, hi int) bool {
	return i > lo && i+1 < hi && rxIsWord(s[i-1]) && rxIsWord(s[i+1])
}

func shellIndex(s []rune, i, hi int, r rune) int {
	for ; i < hi; i++ {
		if s[i] == r {
			return i
		}
	}
	return -1
}

// shellBackquote is where the back quote opened before i closes; -1 when it does not.
func shellBackquote(s []rune, i, hi int) int {
	for i < hi {
		switch s[i] {
		case '\\':
			i += 2
		case '`':
			return i
		default:
			i++
		}
	}
	return -1
}

// shellDouble is where the double quote opened before i closes.
func shellDouble(s []rune, i, hi int) int {
	for i < hi {
		switch {
		case s[i] == '\\':
			i += 2
		case s[i] == '"':
			return i
		case s[i] == '$' && i+1 < hi && s[i+1] == '(':
			j := shellParen(s, i+2, hi)
			if j < 0 {
				return -1
			}
			i = j + 1
		case s[i] == '`':
			j := shellBackquote(s, i+1, hi)
			if j < 0 {
				return -1
			}
			i = j + 1
		default:
			i++
		}
	}
	return -1
}

// shellClosed is where what a ( or { opened before i closes, quotes and what is nested in it skipped.
func shellClosed(s []rune, i, hi int, open, shut rune) int {
	depth := 1
	for i < hi {
		j := i
		switch {
		case s[i] == '\\':
			i += 2
			continue
		case s[i] == '\'':
			if shellApostrophe(s, i, 0, hi) {
				break
			}
			j = shellIndex(s, i+1, hi, '\'')
		case s[i] == '"':
			j = shellDouble(s, i+1, hi)
		case s[i] == '`':
			j = shellBackquote(s, i+1, hi)
		case s[i] == open && (open == '(' || (i > 0 && s[i-1] == '$')):
			depth++
		case s[i] == shut:
			if depth--; depth == 0 {
				return i
			}
		}
		if j < 0 {
			return -1
		}
		i = j + 1
	}
	return -1
}

func shellParen(s []rune, i, hi int) int { return shellClosed(s, i, hi, '(', ')') }

func shellBlank(s []rune) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' {
			return false
		}
	}
	return true
}

// shellLex cuts s[lo:hi] into its commands.
func shellLex(s []rune, lo, hi int) shellLine {
	line := shellLine{ok: true, comment: hi, hash: -1}
	cur := shellCommand{from: lo}
	pipeline, stage := 0, 0
	end := func(at, next int, piped bool) {
		cur.to = at
		if !shellBlank(s[cur.from:cur.to]) {
			line.commands = append(line.commands, cur)
		}
		if piped {
			stage++
		} else {
			pipeline, stage = pipeline+1, 0
		}
		cur = shellCommand{from: next, pipeline: pipeline, stage: stage}
	}
	left := func(r rune) {
		if line.ok {
			line.ok, line.open = false, r
		}
	}
	word := true // at the start of a word, where a # begins a comment
	i := lo
scan:
	for i < hi {
		r, starts := s[i], word
		word = false
		open, shut, runs := -1, -1, false
		switch {
		case r == '\\':
			i += 2
			continue
		case r == '\'':
			if shellApostrophe(s, i, lo, hi) {
				i++
				continue
			}
			open, shut = i+1, shellIndex(s, i+1, hi, '\'')
		case r == '"':
			open, shut = i+1, shellDouble(s, i+1, hi)
		case r == '`':
			open, shut, runs = i+1, shellBackquote(s, i+1, hi), true
		case (r == '$' || r == '<' || r == '>') && i+1 < hi && s[i+1] == '(':
			open, shut, runs, r = i+2, shellParen(s, i+2, hi), true, '('
		case r == '$' && i+1 < hi && s[i+1] == '{':
			j := shellClosed(s, i+2, hi, '{', '}')
			if j < 0 {
				left('{')
				j = i + 1
			}
			i = j + 1
			continue
		case r == '#' && starts:
			if line.hash < 0 {
				line.hash = i
			}
			quoted := false
			for j := i + 1; j < hi && !quoted; j++ {
				quoted = shellQuoteAt(s, j, lo, hi)
			}
			if quoted {
				i++
				continue
			}
			line.comment = i
			break scan
		case r == ';':
			j := i + 1
			for j < hi && (s[j] == ';' || s[j] == '&') {
				j++
			}
			end(i, j, false)
			i, word = j, true
			continue
		case r == '&':
			switch {
			case i+1 < hi && s[i+1] == '&':
				end(i, i+2, false)
				i++
			case (i > lo && (s[i-1] == '>' || s[i-1] == '<')) || (i+1 < hi && s[i+1] == '>'):
				// a redirection: 2>&1, &>file
			default:
				end(i, i+1, false)
			}
			i, word = i+1, true
			continue
		case r == '|':
			switch {
			case i+1 < hi && s[i+1] == '|':
				end(i, i+2, false)
				i++
			case i+1 < hi && s[i+1] == '&':
				end(i, i+2, true)
				i++
			case i > lo && s[i-1] == '>':
				// >| file
			default:
				end(i, i+1, true)
			}
			i, word = i+1, true
			continue
		default:
			word = r == ' ' || r == '\t' || r == '('
			i++
			continue
		}
		// A quoted string or a substitution; left open, it runs to the end of the line.
		if shut < 0 {
			left(r)
			shut = hi
		}
		cur.nested = append(cur.nested, shellNested{open, shut, runs})
		i = shut + 1
	}
	end(line.comment, hi, false)
	return line
}

// shellQuoteAt says whether the character at i is a quote character (an apostrophe inside a word is not).
func shellQuoteAt(s []rune, i, lo, hi int) bool {
	switch s[i] {
	case '"', '`':
		return true
	case '\'':
		return !shellApostrophe(s, i, lo, hi)
	}
	return false
}

// shellScope adds to into the stretches of s[lo:hi] whose words are about what stands at [from, to):
//
//   - the commands the match stands in, without their quoted strings and substitutions;
//   - when the match begins inside a quoted string: that string, read the same way (the command in it that holds the
//     match), and the words around the string only when the match stands in the string's first command;
//   - when it begins inside a substitution: only the substitution's own command.
//
// It gives where the innermost command around the match begins, and whether the match stands in the first command of
// s[lo:hi] (and of every string it is nested in below that).
//
// spans: the line is one of Markdown's, where back quotes also set off a piece of code in a sentence ("Never run
// `rm -rf ~`"): what stands between them is read as a quoted string, not as a substitution.
func shellScope(s []rune, lo, hi, from, to, depth int, spans bool, into *[]shellSpan) (start int, first bool) {
	return shellScopeOf(shellLex(s, lo, hi), s, from, to, depth, spans, into)
}

// shellScopeOf is shellScope for a stretch already cut into its commands.
func shellScopeOf(line shellLine, s []rune, from, to, depth int, spans bool, into *[]shellSpan) (start int, first bool) {
	if to <= from {
		to = from + 1
	}
	start = -1
	var own []shellSpan
	var inner *shellNested
	for k := range line.commands {
		cmd := &line.commands[k]
		if cmd.to <= from || cmd.from >= to {
			continue
		}
		at := cmd.from
		for n := range cmd.nested {
			if start < 0 && cmd.nested[n].from <= from && from < cmd.nested[n].to {
				inner = &cmd.nested[n]
			}
			own = append(own, shellSpan{at, cmd.nested[n].from})
			at = cmd.nested[n].to
		}
		own = append(own, shellSpan{at, cmd.to})
		if start < 0 {
			start, first = cmd.from, cmd.pipeline == 0 && cmd.stage == 0
		}
	}
	if start < 0 {
		return from, false
	}
	if inner == nil {
		*into = append(*into, own...)
		return start, first
	}
	if to > inner.to {
		to = inner.to
	}
	if depth >= shellDepth {
		*into = append(append(*into, own...), shellSpan{inner.from, inner.to})
		return inner.from, first
	}
	at, within := shellScope(s, inner.from, inner.to, from, to, depth+1, spans, into)
	if inner.runs && !(spans && inner.from > 0 && s[inner.from-1] == '`') {
		return at, false
	}
	if within {
		*into = append(*into, own...)
	}
	return at, first && within
}

// shellUnit is the pipeline around a match that a pattern's own conditions (an official installer's address, a test
// that a file is there) are read from: the one it stands in on the line, or, when it stands in a quoted string or a
// substitution that holds several pipelines (a script: `sh -c "a; b | c"`), the one it stands in there. A string that
// is one pipeline is an argument of its command (`sqlite3 "$db" "INSERT …"`), read with it. several: s[lo:hi] holds
// more than one pipeline, here or further in.
func shellUnit(s []rune, lo, hi, from, to, depth int) (a, b int, several bool) {
	return shellUnitOf(shellLex(s, lo, hi), s, lo, hi, from, to, depth)
}

// shellUnitOf is shellUnit for a stretch already cut into its commands.
func shellUnitOf(line shellLine, s []rune, lo, hi, from, to, depth int) (a, b int, several bool) {
	if to <= from {
		to = from + 1
	}
	if n := len(line.commands); n > 0 {
		several = line.commands[0].pipeline != line.commands[n-1].pipeline
	}
	for k, cmd := range line.commands {
		if cmd.to <= from {
			continue
		}
		if cmd.from >= to {
			break
		}
		if depth < shellDepth {
			for _, n := range cmd.nested {
				if n.from <= from && from < n.to {
					end := to
					if end > n.to {
						end = n.to
					}
					if a, b, inside := shellUnit(s, n.from, n.to, from, end, depth+1); inside {
						return a, b, true
					}
				}
			}
		}
		first, last := k, k
		for first > 0 && line.commands[first-1].pipeline == cmd.pipeline {
			first--
		}
		for last+1 < len(line.commands) && line.commands[last+1].pipeline == cmd.pipeline {
			last++
		}
		return line.commands[first].from, line.commands[last].to, several
	}
	return lo, hi, several
}

// skillWords are where a line's words that can make a match talk begin: the negations (a "don't worry" is none), and
// the words about risks or (patterns: in a script) about patterns.
type skillWords struct{ negation, risk []int }

func skillWordsOf(c *skillChecks, s []rune, patterns bool) skillWords {
	var w skillWords
	worry := c.notWorry.findAll(s)
next:
	for _, m := range c.negation.findAll(s) {
		for _, n := range worry {
			if m[0] >= n[0] && m[0] < n[1] {
				continue next
			}
		}
		w.negation = append(w.negation, m[0])
	}
	for _, re := range []*icuRegexp{c.topic, c.patternLine} {
		if re == c.patternLine && !patterns {
			continue
		}
		for _, m := range re.findAll(s) {
			w.risk = append(w.risk, m[0])
		}
	}
	return w
}

// talk says whether the words in scope make what they stand around something talked about: a negation before index
// before, or a word about risks or about patterns anywhere in it.
func (w skillWords) talk(scope []shellSpan, before int) bool {
	in := func(i int) bool {
		for _, p := range scope {
			if i >= p.from && i < p.to {
				return true
			}
		}
		return false
	}
	for _, at := range w.negation {
		if at < before && in(at) {
			return true
		}
	}
	for _, at := range w.risk {
		if in(at) {
			return true
		}
	}
	return false
}

// skillScopeTalks is talk for the words of s.
func skillScopeTalks(c *skillChecks, s []rune, scope []shellSpan, before int) bool {
	return skillWordsOf(c, s, true).talk(scope, before)
}

// shellPipelines are where a line's pipelines stand, each from its first command to its last.
func shellPipelines(line shellLine) []shellSpan {
	var spans []shellSpan
	for k := 0; k < len(line.commands); {
		j := k
		for j+1 < len(line.commands) && line.commands[j+1].pipeline == line.commands[k].pipeline {
			j++
		}
		spans = append(spans, shellSpan{line.commands[k].from, line.commands[j].to})
		k = j + 1
	}
	return spans
}

// ---------------------------------------------------------------- a pipeline's stages

// shellWrapper is a command that runs the command named after its own options, on the same standard input.
type shellWrapper struct {
	// valued: its options (one letter) whose value is the next word.
	valued string
	// asks: its options that make it look a command up instead of running it (command -v).
	asks string
	// args: what comes in on standard input becomes the command's arguments (xargs).
	args bool
}

var shellWrappers = map[string]shellWrapper{
	"sudo": {valued: "ugCDhprtTU"}, "doas": {valued: "uC"}, "env": {valued: "uCS"}, "nohup": {}, "setsid": {},
	"command": {asks: "vV"}, "builtin": {}, "exec": {valued: "a"}, "nice": {valued: "n"}, "ionice": {valued: "cnp"},
	"time": {valued: "o"}, "timeout": {valued: "sk"}, "gtimeout": {valued: "sk"}, "stdbuf": {valued: "ioe"},
	"caffeinate": {valued: "tw"}, "chronic": {}, "unbuffer": {},
	"xargs": {valued: "IJLnPsEdaRS", args: true}, "gxargs": {valued: "IJLnPsEdaRS", args: true},
	"parallel": {valued: "jIN", args: true},
}

var (
	// A shell or interpreter, as stdinRunner names them.
	shellRunnerName = icuCS(`^(?:/\S*/)?(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|perl|ruby|node|php|osascript)$`)
	shellRunsStdin  = icuCI(`^` + stdinRunner + `|^(?:/\S*/)?(?:sh|bash|zsh|dash|ksh|fish|source|\.|python[0-9.]*|perl|ruby|node|php)\s+/dev/(?:stdin|fd/0)(?=\s|$)`)
	shellAssignment = icuCS(`^[A-Za-z_]\w*=`)
	shellNumber     = icuCS(`^\d+(?:\.\d+)?[smhd]?$`)
)

// shellRuns is the word of a command that names what it ends up running: after the keywords and assignments before
// it and the wrappers with their options (`sudo -u root env X=1 timeout 5 bash`: bash). at and end are that word's
// place on the line; args: a wrapper before it hands it standard input as arguments, repl the placeholder it puts
// them at. ok is false when there is no such word or the command cannot be split into words.
func shellRuns(s []rune, cmd shellCommand) (at, end int, args bool, repl string, ok bool) {
	text := s[cmd.from:cmd.to]
	words, split := skillShellWords(text)
	if !split {
		return 0, 0, false, "", false
	}
	word := func(k int) string { return string(text[words[k].from:words[k].to]) }
	repl = "{}"
	k := 0
	for k < len(words) {
		w := word(k)
		switch w {
		case "{", "(", "!", "if", "then", "else", "elif", "do", "while", "until":
			k++
			continue
		}
		if shellAssignment.has(w) {
			k++
			continue
		}
		name := strings.TrimLeft(w, "({")
		wrapper, is := shellWrappers[aiNSLast(name)]
		if !is {
			at = cmd.from + words[k].from + (len([]rune(w)) - len([]rune(name)))
			return at, cmd.from + words[k].to, args, repl, true
		}
		args = args || wrapper.args
		for k++; k < len(words); k++ {
			o := word(k)
			if strings.HasPrefix(o, "-") && o != "-" {
				if len(o) >= 2 && strings.ContainsRune(wrapper.asks, rune(o[1])) {
					return 0, 0, false, "", false
				}
				valued := len(o) >= 2 && strings.ContainsRune(wrapper.valued, rune(o[1]))
				if valued && wrapper.args && (o[1] == 'I' || o[1] == 'J') {
					if len(o) > 2 {
						repl = o[2:]
					} else if k+1 < len(words) {
						repl = strings.Trim(word(k+1), `"'`)
					}
				}
				if valued && len(o) == 2 {
					k++
				}
				continue
			}
			if !shellAssignment.has(o) && !shellNumber.has(o) {
				break
			}
		}
	}
	return 0, 0, false, "", false
}

// shellRunsInput says whether a stage of a pipeline ends up running what comes in: a shell or interpreter reading its
// standard input (as stdinRunner has it: `sh`, `bash -s`, `python3 -`, not `python3 -c …`), or one behind xargs
// that is given no script of its own (`xargs -I{} bash -c "{}"`, not `xargs python3 tool.py`, `xargs rm`).
func shellRunsInput(s []rune, cmd shellCommand) bool {
	at, end, args, repl, ok := shellRuns(s, cmd)
	if !ok {
		return false
	}
	if !args {
		return shellRunsStdin.hasRunes(s[at:cmd.to])
	}
	if !shellRunnerName.hasRunes(s[at:end]) {
		return false
	}
	rest := strings.Fields(string(s[end:cmd.to]))
	return len(rest) == 0 || strings.HasPrefix(rest[0], "-") || strings.Contains(rest[0], repl)
}

// shellPiped finds a pipeline in which one stage's command is what source matches (a download, a decoding) and a
// later stage runs what comes in; also inside quoted strings and substitutions (`sh -c "curl … | xargs sh"`). It
// gives the place from the source to the end of the running stage, the first one at or after index after; nil when
// there is none.
func shellPiped(s []rune, source *icuRegexp, after int) []int {
	return shellPipedIn(s, 0, len(s), source, after, 0)
}

func shellPipedIn(s []rune, lo, hi int, source *icuRegexp, after, depth int) []int {
	line := shellLex(s, lo, hi)
	for a, src := range line.commands {
		if a+1 >= len(line.commands) || line.commands[a+1].pipeline != src.pipeline {
			continue
		}
		at, end, _, _, ok := shellRuns(s, src)
		if !ok || at < after {
			continue
		}
		m := source.find(s, at)
		if m == nil || m[0] >= end || m[1] > src.to {
			continue
		}
		for b := a + 1; b < len(line.commands) && line.commands[b].pipeline == src.pipeline; b++ {
			if shellRunsInput(s, line.commands[b]) {
				return []int{m[0], line.commands[b].to}
			}
		}
	}
	if depth < shellDepth {
		for _, cmd := range line.commands {
			for _, n := range cmd.nested {
				if m := shellPipedIn(s, n.from, n.to, source, after, depth+1); m != nil {
					return m
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- logical lines

var (
	// The start of a here-document, with its delimiter.
	shellHeredoc = icuCS(`(?<!<)<<(?!<)-?\s*(?:\\|["'])?([A-Za-z_][\w.-]*)`)
	skillFenceAt = icuCS(`^\s{0,3}(?:\x{60}\x{60}\x{60}|~~~)`)
)

// skillShellFences are the languages a fence names whose code block is a shell's.
var skillShellFences = aiSet("sh", "bash", "zsh", "ksh", "dash", "fish", "shell", "console", "terminal", "shellsession",
	"shell-session", "sh-session", "bash-session", "shell-script")

// skillTextFences are the languages a fence names whose block is no code: sentences, read as the rest of the prose.
var skillTextFences = aiSet("text", "txt", "plain", "plaintext", "markdown", "md", "mdx")

// skillFenceTag is the language a fence names, in lower case; "" when it names none.
func skillFenceTag(line string) string {
	tag := strings.TrimLeft(strings.TrimLeft(aiTrimWS(line), "\x60~"), " \t{.")
	if i := strings.IndexAny(tag, " \t,:;{}"); i >= 0 {
		tag = tag[:i]
	}
	return strings.ToLower(tag)
}

// skillFenceShell says whether the code block a fence opens is read as a shell's: one that names no language, a
// shell or a terminal. Any other (python, js, yaml…) is read as a script that is not a shell's, but for one that
// names plain text or Markdown (skillFenceText).
func skillFenceShell(line string) bool {
	tag := skillFenceTag(line)
	return tag == "" || skillShellFences[tag]
}

// skillFenceText says whether a fence opens a block of plain text or Markdown: its lines are sentences.
func skillFenceText(line string) bool { return skillTextFences[skillFenceTag(line)] }

// skillLineMax is how much of a line the checks read (skillScanFileWith cuts a line there).
const skillLineMax = 4000

// shellContinued says whether a line ends in a backslash that continues it on the next one (an odd number of them).
func shellContinued(l string) bool {
	n := 0
	for n < len(l) && l[len(l)-1-n] == '\\' {
		n++
	}
	return n%2 == 1
}

// skillJoinContinued puts a command continued over several lines (a backslash at the end of a line) on its first
// line, as the shell reads it. The text keeps its lines: the ones taken up are left empty, so a hit is reported at
// the line the command starts on. script: a shell script, read whole; otherwise prose, where only the lines of a
// fenced code block are joined.
//
// A comment does not go on: a line that is only a comment, or ends in one, is left alone (`# … \` hides nothing of the
// next line). Each line is judged on its own, so where the backslash may not be a continuation the command is read
// both ways, joined and with the lines after it left as they are: inside single quotes, in a here-document, and
// whenever one of the lines has a # in it that is not plainly a comment's start (joined, it may turn out to be one).
// So is a command too long to be read whole on one line (skillLineMax): it is joined in stretches that overlap by
// half.
func skillJoinContinued(text string, script bool) string {
	if !strings.Contains(text, "\\\n") && !strings.Contains(text, "\\\r\n") {
		return text
	}
	lines := strings.Split(text, "\n")
	bare := func(i int) string { return strings.TrimSuffix(lines[i], "\r") }
	out := append([]string{}, lines...)
	// taken: the lines up to here were put on an earlier one; kept: they are left as they are, and not joined again.
	fenced, heredoc, taken, kept := false, "", -1, -1
	var cur []byte
	for i := range lines {
		l := bare(i)
		if !script {
			if skillFenceAt.has(l) {
				fenced = !fenced
				continue
			}
			if !fenced {
				continue
			}
		}
		inDoc := heredoc != ""
		if inDoc {
			if aiTrimWS(l) == heredoc {
				heredoc = ""
			}
		} else if script && strings.Contains(l, "<<") {
			if m := shellHeredoc.find([]rune(l), 0); m != nil {
				heredoc = string([]rune(l)[m[2]:m[3]])
			}
		}
		if i <= taken {
			out[i] = ""
			continue
		}
		if i <= kept || !shellContinued(l) {
			continue
		}
		if t := aiTrimWS(l); (strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#!")) || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "-- ") || strings.HasPrefix(t, "REM ") {
			continue
		}
		cur = cur[:0]
		j, sure, cut := i, !inDoc, false
		for last := l; shellContinued(last) && j+1 < len(lines); last = bare(j) {
			if len(cur)+len(last) >= skillLineMax {
				cut = true
				break
			}
			if !script && skillFenceAt.has(bare(j+1)) {
				break
			}
			body := []rune(last[:len(last)-1])
			lexed := shellLex(body, 0, len(body))
			if lexed.comment < len(body) {
				break
			}
			if (!lexed.ok && lexed.open == '\'') || strings.ContainsRune(last, '#') {
				sure = false
			}
			cur = append(cur, last[:len(last)-1]...)
			j++
		}
		if j == i {
			continue
		}
		out[i] = string(cur) + bare(j)
		switch {
		case cut || aiUTF16Len([]rune(out[i])) > skillLineMax:
			kept = i + (j-i)/2 // the next stretch overlaps this one by half
		case sure:
			taken = j
		default:
			kept = j
		}
	}
	return strings.Join(out, "\n")
}

// ---------------------------------------------------------------- code that is not a shell's

// scriptStatement is the statement of a line of code (Python, JavaScript…) around index at: the stretch between two
// `;` outside quotes. A comment at the end of the line (# or //) goes with the last statement. The whole line when
// its quotes do not pair up.
func scriptStatement(s []rune, at int) (lo, hi int) {
	lo, hi, _ = scriptCut(s, at)
	return lo, hi
}

// scriptCut is scriptStatement, and where the comment at the end of the line begins (the end of the line when there
// is none).
func scriptCut(s []rune, at int) (lo, hi, comment int) {
	lo, hi, comment = 0, len(s), len(s)
	var q rune
scan:
	for i := 0; i < len(s); i++ {
		r := s[i]
		switch {
		case q != 0:
			if r == '\\' {
				i++
			} else if r == q {
				q = 0
			}
		case r == '"' || r == '\'' || r == '`':
			q = r
		case r == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'), r == '/' && i+1 < len(s) && s[i+1] == '/' && (i == 0 || s[i-1] != ':'):
			comment = i
			break scan
		case r == ';':
			if i < at {
				lo = i + 1
			} else if hi == len(s) {
				hi = i
			}
		}
	}
	if q != 0 {
		return 0, len(s), len(s)
	}
	return lo, hi, comment
}

// ---------------------------------------------------------------- one line, as the checks read it

// skillReading is how the checks tell one line's commands apart: a shell script's by shellLex, another script's by
// scriptStatement; so the lines of a fenced code block in prose. (The rest of prose and the install checks do not go
// through it.) What it works out for the line is kept for the next pattern.
type skillReading struct {
	c     *skillChecks
	s     []rune
	shell bool
	// prose: a line of a fenced code block in the instructions, not of a script. The agent reads all of it, so what
	// differs is only what cannot make it quieter than a sentence would be: the words about risks in a comment at the
	// end of the line speak for its commands, a match inside that comment is judged by the whole line, what stands
	// between back quotes is read as a quoted string (shellScope), and the writing that defines a pattern (`\s`, regex)
	// is no word about risks.
	prose bool

	lexed bool
	line  shellLine
	spans []shellSpan
	// buf: blanks as long as the line, for showing one pipeline at a time.
	buf    []rune
	worded bool
	words  skillWords
}

func (r *skillReading) lex() shellLine {
	if !r.lexed {
		r.line, r.lexed = shellLex(r.s, 0, len(r.s)), true
		r.spans = shellPipelines(r.line)
		// In the instructions a comment is read too: matched like one more pipeline.
		if r.prose && r.line.comment < len(r.s) {
			r.spans = append(r.spans, shellSpan{r.line.comment, len(r.s)})
		}
	}
	return r.line
}

func (r *skillReading) talkWords() skillWords {
	if !r.worded {
		r.words, r.worded = skillWordsOf(r.c, r.s, !r.prose), true
	}
	return r.words
}

// pipelines are what the patterns are matched against: a shell's line one pipeline at a time (in the instructions
// also the comment at its end), any other line whole.
func (r *skillReading) pipelines() []shellSpan {
	if !r.shell {
		return []shellSpan{{0, len(r.s)}}
	}
	r.lex()
	return r.spans
}

// show is the line as one of its pipelines sees it, as if it stood on a line of its own: the pipeline in its place,
// blanks before it, nothing after it (not the other pipelines, the separators, a comment at the end). hide puts the
// blanks back before the next one is shown.
func (r *skillReading) show(p shellSpan) []rune {
	if !r.shell || (p.to == len(r.s) && shellBlank(r.s[:p.from])) {
		return r.s
	}
	if r.buf == nil {
		r.buf = make([]rune, len(r.s))
		for i := range r.buf {
			r.buf[i] = ' '
		}
	}
	copy(r.buf[p.from:p.to], r.s[p.from:p.to])
	return r.buf[:p.to]
}

func (r *skillReading) hide(p shellSpan) {
	for i := p.from; r.buf != nil && i < p.to; i++ {
		r.buf[i] = ' '
	}
}

// piped is shellPiped for the line; in the instructions also for what a comment at its end says to run.
func (r *skillReading) piped(v []rune, source *icuRegexp, after int) []int {
	m := shellPiped(v, source, after)
	if m == nil && r.shell && r.prose {
		if at := r.lex().comment + 1; at < len(v) {
			if after < at {
				after = at
			}
			m = shellPipedIn(v, at, len(v), source, after, 0)
		}
	}
	return m
}

// unit is the line as the pipeline around a match that its pattern's own conditions are read from sees it
// (shellUnit); v, the pipeline being shown, when that is the one.
func (r *skillReading) unit(v []rune, m []int) []rune {
	if !r.shell {
		return v
	}
	lo, hi, _ := shellUnitOf(r.lex(), r.s, 0, len(r.s), m[0], m[1], 0)
	if hi > len(v) {
		hi = len(v)
	}
	if lo >= hi || (shellBlank(v[:lo]) && shellBlank(v[hi:])) {
		return v
	}
	u := make([]rune, hi)
	for i := range u {
		u[i] = ' '
	}
	copy(u[lo:hi], v[lo:hi])
	return u
}

// talks says whether the command a match stands in talks about such things rather than does them.
func (r *skillReading) talks(m []int) bool {
	whole := []shellSpan{{0, len(r.s)}}
	if r.shell {
		comment := r.lex().comment
		if m[0] >= comment {
			return !r.prose || r.talkWords().talk(whole, m[0])
		}
		var scope []shellSpan
		shellScopeOf(r.line, r.s, m[0], m[1], 0, r.prose, &scope)
		if r.prose {
			scope = append(scope, shellSpan{comment, len(r.s)})
		}
		return r.talkWords().talk(scope, m[0])
	}
	lo, hi, comment := scriptCut(r.s, m[0])
	scope := []shellSpan{{lo, hi}}
	if r.prose {
		if scope = append(scope, shellSpan{comment, len(r.s)}); m[0] >= comment {
			scope = whole
		}
	}
	return r.talkWords().talk(scope, m[0])
}

// lineWriteTalks is how a sentence's write to a target is judged (skillScanFileWith): a word about risks anywhere in
// s, or a negation outside quotes before the writing.
func (r *skillReading) lineWriteTalks(t skillTarget, s []rune) bool {
	return r.c.topic.hasRunes(s) || skillNegatedBefore(r.c, s, skillWriteStart(t, s, false))
}

// writeTalks is talks for a write to a target, judged where the writing is (each redirection and copying command on
// the line; failing those, the target's path): the line talks only when every one of them does. What stands before
// the `>>` in the same command is what gets written (`echo Never ask >> ~/.claude/CLAUDE.md`), so a negation counts
// only from before that command. In a code block of the instructions (prose) a line may be a sentence as well
// ("Never append to ~/.zshrc with echo … >> ~/.zshrc"): there a negation counts from before the writing itself.
func (r *skillReading) writeTalks(t skillTarget) bool {
	if !r.shell {
		at := 0
		if m := t.path.find(r.s, 0); m != nil {
			at = m[0]
		}
		lo, hi, comment := scriptCut(r.s, at)
		sub := r.s[lo:hi]
		if r.prose {
			if at >= comment {
				return r.lineWriteTalks(t, r.s)
			}
			return r.c.topic.hasRunes(r.s[comment:]) || r.lineWriteTalks(t, sub)
		}
		return r.c.topic.hasRunes(sub) || r.c.patternLine.hasRunes(sub) || skillNegatedBefore(r.c, sub, skillWriteStart(t, sub, true))
	}
	var writes []int
	for _, re := range []*icuRegexp{t.redirect, t.copy} {
		for _, m := range re.findAll(r.s) {
			writes = append(writes, m[0])
		}
	}
	if len(writes) == 0 {
		if m := t.path.find(r.s, 0); m != nil {
			writes = append(writes, m[0])
		}
	}
	for _, at := range writes {
		comment := r.lex().comment
		if at >= comment {
			if r.prose && !r.lineWriteTalks(t, r.s) {
				return false
			}
			continue
		}
		var scope []shellSpan
		before, _ := shellScopeOf(r.line, r.s, at, at+1, 0, r.prose, &scope)
		if r.prose {
			before, scope = at, append(scope, shellSpan{comment, len(r.s)})
		}
		if !r.talkWords().talk(scope, before) {
			return false
		}
	}
	return true
}
