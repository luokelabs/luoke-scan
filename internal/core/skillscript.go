package core

import "strings"

// How a shell script's lines are read, where it differs from scriptCode (which does not know the language), and where
// on a line a write to a place that matters begins.

var (
	// A case's branch that begins with a star: `*)`, `*.txt)`, `*|-h)`, `* )`.
	shellStarBranch = icuCS(`^\*[^\s()]*\s*[)|]`)
)

// shellScriptCode is scriptCode for a shell script, called for each line in order. A shell has no block comments: a
// line that begins with a star is a case's branch (`*) rm -rf ~ ;;`) or a glob, and so is `/*)`. A star begins a
// comment's line only inside a block comment left open before it (block; C or JavaScript in a here-document), and a
// line shaped like a case's branch is code even there.
func shellScriptCode(line string, block *bool) (code string, only bool) {
	s := aiTrimWS(line)
	if *block {
		i := strings.Index(s, "*/")
		if i >= 0 {
			*block = false
		}
		if strings.HasPrefix(s, "*") && !shellStarBranch.has(s) {
			if i < 0 {
				return "", true
			}
			if s = aiTrimWS(s[i+2:]); s == "" {
				return "", true
			}
		}
	}
	for {
		switch {
		case strings.HasPrefix(s, "/*") && (len(s) == 2 || strings.ContainsRune(" \t*!", rune(s[2]))):
			i := strings.Index(s[2:], "*/")
			if i < 0 {
				*block = true
				return "", true
			}
			s = aiTrimWS(s[2+i+2:])
		case (strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "#!")) || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "-- ") ||
			strings.HasPrefix(s, "REM "):
			return "", true
		default:
			return s, false
		}
		if s == "" {
			return "", true
		}
	}
}

// skillQuoted says whether the character at index at of s stands inside quotes: "…", '…', “…” or 「…」. An apostrophe
// inside a word (don't) opens nothing.
func skillQuoted(s []rune, at int) bool {
	letter := func(i int) bool { return i >= 0 && i < len(s) && rxIsWord(s[i]) }
	var in rune
	for i := 0; i < at && i < len(s); i++ {
		r := s[i]
		switch {
		case r == '\\' && in != '\'':
			i++
		case in != 0:
			if r == in {
				in = 0
			}
		case r == '"':
			in = '"'
		case r == '\'' && !(letter(i-1) && letter(i+1)):
			in = '\''
		case r == '“':
			in = '”'
		case r == '「':
			in = '」'
		}
	}
	return in != 0
}

// skillWriteStart is where on a line the writing to a target begins: the redirection or the copying command,
// whichever comes first; in prose also the end of the words that say to write there ("do not" may stand before them
// or among them); failing those, the target's path. In a script it is the start of that command: what an echo prints
// before its `>>` is what gets written, not words about writing.
func skillWriteStart(t skillTarget, s []rune, script bool) int {
	at := -1
	first := func(i int) {
		if at < 0 || i < at {
			at = i
		}
	}
	if m := t.redirect.find(s, 0); m != nil {
		first(m[0])
	}
	if m := t.copy.find(s, 0); m != nil {
		first(m[0])
	}
	if !script && t.saidSeverity != "" {
		if m := t.said.find(s, 0); m != nil {
			first(m[1])
		}
	}
	if at < 0 {
		if m := t.path.find(s, 0); m != nil {
			at = m[0]
		} else {
			at = len(s)
		}
	}
	if script {
		start := 0
		for i := 0; i < at; i++ {
			if strings.ContainsRune(";&|(`", s[i]) && !skillQuoted(s, i) {
				start = i + 1
			}
		}
		at = start
	}
	return at
}

// skillNegatedBefore says whether the line says not to, before index at: a negation there that is not inside quotes
// (what is written into the file may say "do not" as well) and not a "don't worry".
func skillNegatedBefore(c *skillChecks, s []rune, at int) bool {
	worry := c.notWorry.findAll(s)
next:
	for _, m := range c.negation.findAll(s) {
		if m[0] >= at {
			break
		}
		for _, w := range worry {
			if m[0] >= w[0] && m[0] < w[1] {
				continue next
			}
		}
		if !skillQuoted(s, m[0]) {
			return true
		}
	}
	return false
}
