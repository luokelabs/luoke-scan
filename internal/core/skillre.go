package core

import (
	"strconv"
	"unicode"
	"unicode/utf16"
)

// The skill and secret checks were written for ICU's regular expressions (what NSRegularExpression runs): lookahead
// and lookbehind, and \b, \w, \s, \d by Unicode. Go's regexp has neither, so they run on this small backtracking
// matcher of the same syntax and the same answers: leftmost match, alternatives in order, greedy and lazy repeats,
// lookaround, case-insensitive matching by simple case folding, \b as ICU tells it (Unicode word characters,
// combining marks and format characters ignored), . and $ with ICU's line terminators. Only the part of the syntax
// the checks use; a pattern outside it panics when built (the patterns are fixed, so at start-up).

type rxKind uint8

const (
	rxOne       rxKind = iota // one character the predicate takes
	rxSeq                     // subs one after another
	rxAlt                     // the first of subs that leads to a match
	rxGroup                   // a capturing group
	rxRepeat                  // subs[0] min to max times (max -1: no limit)
	rxLook                    // lookahead or lookbehind
	rxBegin                   // ^ (start of the text)
	rxBeginLine               // ^ with anchorsMatchLines: the start, or after a line terminator not at the end
	rxEnd                     // $ (end, or before a line terminator at the end)
	rxWord                    // \b
	rxNotWord                 // \B
)

type rxNode struct {
	kind     rxKind
	subs     []*rxNode
	one      func(rune) bool
	cap      int
	min, max int
	lazy     bool
	ahead    bool
	neg      bool
	// single, when set: the node always matches exactly one character and captures nothing; it says whether it
	// matches at i (what repeats of it test in a loop instead of by recursion).
	single func(m *rxMatcher, i int) bool
}

// icuRegexp is a built pattern.
type icuRegexp struct {
	root *rxNode
	caps int
	src  string
	ci   bool
}

type rxMatcher struct {
	s    []rune
	caps []int
}

// icuCI builds a case-insensitive pattern (the checks' NSRegularExpression with .caseInsensitive).
func icuCI(p string) *icuRegexp { return buildICURegexp(p, true) }

// icuCS builds a case-sensitive pattern (String.range(of:options:.regularExpression)).
func icuCS(p string) *icuRegexp { return buildICURegexp(p, false) }

// icuLines builds a case-sensitive pattern whose ^ matches at the start of every line (.anchorsMatchLines).
func icuLines(p string) *icuRegexp {
	r := buildICURegexpWith(&rxParser{p: []rune(p), multiline: true})
	return r
}

func buildICURegexp(p string, ci bool) *icuRegexp {
	return buildICURegexpWith(&rxParser{p: []rune(p), ci: ci})
}

func buildICURegexpWith(ps *rxParser) *icuRegexp {
	p := string(ps.p)
	ci := ps.ci
	n := ps.alt()
	if ps.i < len(ps.p) {
		panic("regex: unexpected " + string(ps.p[ps.i:]) + " in " + p)
	}
	rxPrepare(n)
	return &icuRegexp{root: n, caps: ps.caps, src: p, ci: ci}
}

// ---------------------------------------------------------------- characters as ICU tells them

func rxLineTerminator(c rune) bool {
	return (c >= 0x0a && c <= 0x0d) || c == 0x85 || c == 0x2028 || c == 0x2029
}

// rxIsWord is ICU's \w: [\p{Alphabetic}\p{M}\p{Nd}\p{Pc}\u200c\u200d].
func rxIsWord(c rune) bool {
	if c < 0x80 {
		return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return unicode.IsLetter(c) || unicode.Is(unicode.Nl, c) || unicode.Is(unicode.Other_Alphabetic, c) || unicode.IsMark(c) ||
		unicode.Is(unicode.Nd, c) || unicode.Is(unicode.Pc, c) || c == 0x200C || c == 0x200D
}

// rxIsSpace is ICU's \s: White_Space.
func rxIsSpace(c rune) bool {
	if c < 0x80 {
		return c == ' ' || (c >= 0x09 && c <= 0x0d)
	}
	return unicode.Is(unicode.White_Space, c)
}

func rxIsDigit(c rune) bool {
	if c < 0x80 {
		return c >= '0' && c <= '9'
	}
	return unicode.Is(unicode.Nd, c)
}

// rxIgnoredAtBoundary: combining (Grapheme_Extend) and format characters, which \b looks past.
func rxIgnoredAtBoundary(c rune) bool {
	if c < 0x80 {
		return false
	}
	return unicode.Is(unicode.Mn, c) || unicode.Is(unicode.Me, c) || unicode.Is(unicode.Other_Grapheme_Extend, c) || unicode.Is(unicode.Cf, c)
}

func (m *rxMatcher) wordBoundary(i int) bool {
	cIsWord := false
	if i < len(m.s) {
		c := m.s[i]
		if rxIgnoredAtBoundary(c) {
			return false
		}
		cIsWord = rxIsWord(c)
	}
	prev := false
	for j := i - 1; j >= 0; j-- {
		if !rxIgnoredAtBoundary(m.s[j]) {
			prev = rxIsWord(m.s[j])
			break
		}
	}
	return cIsWord != prev
}

func (m *rxMatcher) atEnd(i int) bool {
	n := len(m.s)
	switch {
	case i >= n:
		return true
	case i == n-1:
		c := m.s[i]
		return rxLineTerminator(c) && !(c == '\n' && i > 0 && m.s[i-1] == '\r')
	case i == n-2:
		return m.s[i] == '\r' && m.s[i+1] == '\n'
	}
	return false
}

// foldOrbit is c and every character simple case folding makes the same as it.
func rxFoldOrbit(c rune) []rune {
	out := []rune{c}
	for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------- parsing

type rxParser struct {
	p         []rune
	i         int
	ci        bool
	multiline bool
	caps      int
}

func (ps *rxParser) more() bool { return ps.i < len(ps.p) }
func (ps *rxParser) peek() rune { return ps.p[ps.i] }
func (ps *rxParser) fail(why string) {
	panic("regex: " + why + " at " + strconv.Itoa(ps.i) + " in " + string(ps.p))
}

func (ps *rxParser) alt() *rxNode {
	alts := []*rxNode{ps.seq()}
	for ps.more() && ps.peek() == '|' {
		ps.i++
		alts = append(alts, ps.seq())
	}
	if len(alts) == 1 {
		return alts[0]
	}
	return &rxNode{kind: rxAlt, subs: alts}
}

func (ps *rxParser) seq() *rxNode {
	var items []*rxNode
	for ps.more() && ps.peek() != '|' && ps.peek() != ')' {
		a := ps.atom()
		a = ps.quantified(a)
		items = append(items, a)
	}
	if len(items) == 1 {
		return items[0]
	}
	return &rxNode{kind: rxSeq, subs: items}
}

func (ps *rxParser) number() (int, bool) {
	start := ps.i
	for ps.more() && ps.peek() >= '0' && ps.peek() <= '9' {
		ps.i++
	}
	if ps.i == start {
		return 0, false
	}
	n, _ := strconv.Atoi(string(ps.p[start:ps.i]))
	return n, true
}

func (ps *rxParser) quantified(a *rxNode) *rxNode {
	for ps.more() {
		min, max := -1, -1
		switch ps.peek() {
		case '*':
			min, max = 0, -1
			ps.i++
		case '+':
			min, max = 1, -1
			ps.i++
		case '?':
			min, max = 0, 1
			ps.i++
		case '{':
			save := ps.i
			ps.i++
			lo, ok := ps.number()
			if !ok {
				ps.i = save
				ps.fail("bad {")
			}
			hi := lo
			if ps.more() && ps.peek() == ',' {
				ps.i++
				if h, ok := ps.number(); ok {
					hi = h
				} else {
					hi = -1
				}
			}
			if !ps.more() || ps.peek() != '}' {
				ps.fail("bad {")
			}
			ps.i++
			min, max = lo, hi
		default:
			return a
		}
		lazy := false
		if ps.more() && ps.peek() == '?' {
			lazy = true
			ps.i++
		} else if ps.more() && ps.peek() == '+' {
			ps.fail("possessive repeats are not supported")
		}
		a = &rxNode{kind: rxRepeat, subs: []*rxNode{a}, min: min, max: max, lazy: lazy}
	}
	return a
}

func (ps *rxParser) charNode(pred func(rune) bool) *rxNode { return &rxNode{kind: rxOne, one: pred} }

func (ps *rxParser) literal(c rune) *rxNode {
	if ps.ci {
		orbit := rxFoldOrbit(c)
		if len(orbit) > 1 {
			return ps.charNode(func(r rune) bool {
				for _, o := range orbit {
					if r == o {
						return true
					}
				}
				return false
			})
		}
	}
	return ps.charNode(func(r rune) bool { return r == c })
}

func (ps *rxParser) atom() *rxNode {
	c := ps.peek()
	switch c {
	case '(':
		ps.i++
		var n *rxNode
		if ps.more() && ps.peek() == '?' {
			ps.i++
			if !ps.more() {
				ps.fail("bad (?")
			}
			switch k := ps.peek(); k {
			case ':':
				ps.i++
				n = ps.alt()
			case '=', '!':
				ps.i++
				n = &rxNode{kind: rxLook, ahead: true, neg: k == '!', subs: []*rxNode{ps.alt()}}
			case '<':
				ps.i++
				if !ps.more() || (ps.peek() != '=' && ps.peek() != '!') {
					ps.fail("named groups are not supported")
				}
				neg := ps.peek() == '!'
				ps.i++
				n = &rxNode{kind: rxLook, ahead: false, neg: neg, subs: []*rxNode{ps.alt()}}
			default:
				ps.fail("unsupported (?" + string(k))
			}
		} else {
			ps.caps++
			idx := ps.caps
			n = &rxNode{kind: rxGroup, cap: idx, subs: []*rxNode{ps.alt()}}
		}
		if !ps.more() || ps.peek() != ')' {
			ps.fail("missing )")
		}
		ps.i++
		return n
	case '[':
		return ps.class()
	case '.':
		ps.i++
		return ps.charNode(func(r rune) bool { return !rxLineTerminator(r) })
	case '^':
		ps.i++
		if ps.multiline {
			return &rxNode{kind: rxBeginLine}
		}
		return &rxNode{kind: rxBegin}
	case '$':
		ps.i++
		return &rxNode{kind: rxEnd}
	case '\\':
		ps.i++
		if !ps.more() {
			ps.fail("trailing \\")
		}
		e := ps.peek()
		ps.i++
		switch e {
		case 'b':
			return &rxNode{kind: rxWord}
		case 'B':
			return &rxNode{kind: rxNotWord}
		}
		if pred, ok := ps.escapeClass(e); ok {
			return ps.charNode(pred)
		}
		return ps.literal(ps.escapeChar(e))
	case '*', '+', '?', '{':
		ps.fail("nothing to repeat")
	}
	ps.i++
	return ps.literal(c)
}

// escapeClass: \s \S \w \W \d \D.
func (ps *rxParser) escapeClass(e rune) (func(rune) bool, bool) {
	switch e {
	case 's':
		return rxIsSpace, true
	case 'S':
		return func(r rune) bool { return !rxIsSpace(r) }, true
	case 'w':
		return rxIsWord, true
	case 'W':
		return func(r rune) bool { return !rxIsWord(r) }, true
	case 'd':
		return rxIsDigit, true
	case 'D':
		return func(r rune) bool { return !rxIsDigit(r) }, true
	}
	return nil, false
}

// escapeChar: \n \t \r \f \x{…} \uXXXX, else the character itself.
func (ps *rxParser) escapeChar(e rune) rune {
	switch e {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case 'f':
		return '\f'
	case 'x':
		if ps.more() && ps.peek() == '{' {
			ps.i++
			start := ps.i
			for ps.more() && ps.peek() != '}' {
				ps.i++
			}
			v, err := strconv.ParseUint(string(ps.p[start:ps.i]), 16, 32)
			if err != nil || !ps.more() {
				ps.fail("bad \\x{}")
			}
			ps.i++
			return rune(v)
		}
		ps.fail("bad \\x")
	case 'u':
		if ps.i+4 > len(ps.p) {
			ps.fail("bad \\u")
		}
		v, err := strconv.ParseUint(string(ps.p[ps.i:ps.i+4]), 16, 32)
		if err != nil {
			ps.fail("bad \\u")
		}
		ps.i += 4
		return rune(v)
	}
	if (e >= 'a' && e <= 'z') || (e >= 'A' && e <= 'Z') || (e >= '0' && e <= '9') {
		ps.fail("unsupported escape \\" + string(e))
	}
	return e
}

type rxRange struct{ lo, hi rune }

func (ps *rxParser) class() *rxNode {
	ps.i++ // [
	neg := false
	if ps.more() && ps.peek() == '^' {
		neg = true
		ps.i++
	}
	var ranges []rxRange
	var preds []func(rune) bool
	first := true
	for {
		if !ps.more() {
			ps.fail("missing ]")
		}
		c := ps.peek()
		if c == ']' && !first {
			ps.i++
			break
		}
		if c == '[' {
			ps.fail("nested sets are not supported")
		}
		first = false
		var lo rune
		if c == '\\' {
			ps.i++
			if !ps.more() {
				ps.fail("trailing \\")
			}
			e := ps.peek()
			ps.i++
			if pred, ok := ps.escapeClass(e); ok {
				preds = append(preds, pred)
				continue
			}
			lo = ps.escapeChar(e)
		} else {
			ps.i++
			lo = c
		}
		// A range, unless the - is the last thing in the set.
		if ps.i+1 < len(ps.p) && ps.p[ps.i] == '-' && ps.p[ps.i+1] != ']' {
			ps.i++
			hc := ps.peek()
			var hi rune
			if hc == '\\' {
				ps.i++
				e := ps.peek()
				ps.i++
				if _, ok := ps.escapeClass(e); ok {
					ps.fail("a range up to a class")
				}
				hi = ps.escapeChar(e)
			} else {
				ps.i++
				hi = hc
			}
			if hi < lo {
				ps.fail("backwards range")
			}
			ranges = append(ranges, rxRange{lo, hi})
			continue
		}
		ranges = append(ranges, rxRange{lo, lo})
	}
	in := func(r rune) bool {
		for _, g := range ranges {
			if r >= g.lo && r <= g.hi {
				return true
			}
		}
		for _, p := range preds {
			if p(r) {
				return true
			}
		}
		return false
	}
	set := in
	if ps.ci {
		// The set closed over case, as ICU builds it.
		set = func(r rune) bool {
			if in(r) {
				return true
			}
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				if in(f) {
					return true
				}
			}
			return false
		}
	}
	if neg {
		return ps.charNode(func(r rune) bool { return !set(r) })
	}
	return ps.charNode(set)
}

// ---------------------------------------------------------------- analysis

// rxPrepare marks the nodes that always match exactly one character (and capture nothing).
func rxPrepare(n *rxNode) {
	for _, s := range n.subs {
		rxPrepare(s)
	}
	n.single = rxSingleOf(n)
}

func rxZeroWidth(n *rxNode) bool {
	switch n.kind {
	case rxLook, rxBegin, rxBeginLine, rxEnd, rxWord, rxNotWord:
		return !rxHasCapture(n)
	}
	return false
}

func rxHasCapture(n *rxNode) bool {
	if n.kind == rxGroup {
		return true
	}
	for _, s := range n.subs {
		if rxHasCapture(s) {
			return true
		}
	}
	return false
}

func rxSingleOf(n *rxNode) func(m *rxMatcher, i int) bool {
	switch n.kind {
	case rxOne:
		one := n.one
		return func(m *rxMatcher, i int) bool { return i < len(m.s) && one(m.s[i]) }
	case rxAlt:
		var parts []func(m *rxMatcher, i int) bool
		for _, s := range n.subs {
			if s.single == nil {
				return nil
			}
			parts = append(parts, s.single)
		}
		return func(m *rxMatcher, i int) bool {
			for _, p := range parts {
				if p(m, i) {
					return true
				}
			}
			return false
		}
	case rxSeq:
		var before, after []*rxNode
		var char *rxNode
		for _, s := range n.subs {
			switch {
			case s.single != nil && char == nil:
				char = s
			case rxZeroWidth(s):
				if char == nil {
					before = append(before, s)
				} else {
					after = append(after, s)
				}
			default:
				return nil
			}
		}
		if char == nil {
			return nil
		}
		return func(m *rxMatcher, i int) bool {
			for _, a := range before {
				if !m.assert(a, i) {
					return false
				}
			}
			if !char.single(m, i) {
				return false
			}
			for _, a := range after {
				if !m.assert(a, i+1) {
					return false
				}
			}
			return true
		}
	}
	return nil
}

// rxLengths are the fewest and most characters a node can match (most -1: no limit); for lookbehind.
func rxLengths(n *rxNode) (int, int) {
	switch n.kind {
	case rxOne:
		return 1, 1
	case rxSeq:
		lo, hi := 0, 0
		for _, s := range n.subs {
			a, b := rxLengths(s)
			lo += a
			if hi >= 0 {
				if b < 0 {
					hi = -1
				} else {
					hi += b
				}
			}
		}
		return lo, hi
	case rxAlt:
		lo, hi := -1, 0
		for _, s := range n.subs {
			a, b := rxLengths(s)
			if lo < 0 || a < lo {
				lo = a
			}
			if hi >= 0 && (b < 0 || b > hi) {
				hi = b
			}
		}
		return lo, hi
	case rxGroup:
		return rxLengths(n.subs[0])
	case rxRepeat:
		a, b := rxLengths(n.subs[0])
		hi := -1
		if n.max >= 0 && b >= 0 {
			hi = n.max * b
		}
		return n.min * a, hi
	}
	return 0, 0
}

// ---------------------------------------------------------------- matching

// assert evaluates a zero-width node at i.
func (m *rxMatcher) assert(n *rxNode, i int) bool {
	return m.run(n, i, func(int) bool { return true })
}

func (m *rxMatcher) run(n *rxNode, i int, k func(int) bool) bool {
	switch n.kind {
	case rxOne:
		if i < len(m.s) && n.one(m.s[i]) {
			return k(i + 1)
		}
		return false
	case rxSeq:
		return m.seq(n.subs, i, k)
	case rxAlt:
		for _, a := range n.subs {
			if m.run(a, i, k) {
				return true
			}
		}
		return false
	case rxGroup:
		c := n.cap
		return m.run(n.subs[0], i, func(j int) bool {
			s0, s1 := m.caps[2*c], m.caps[2*c+1]
			m.caps[2*c], m.caps[2*c+1] = i, j
			if k(j) {
				return true
			}
			m.caps[2*c], m.caps[2*c+1] = s0, s1
			return false
		})
	case rxRepeat:
		return m.repeat(n, 0, i, k)
	case rxLook:
		saved := append([]int(nil), m.caps...)
		found := false
		if n.ahead {
			found = m.run(n.subs[0], i, func(int) bool { return true })
		} else {
			lo, hi := rxLengths(n.subs[0])
			for start := i - lo; start >= 0 && (hi < 0 || start >= i-hi); start-- {
				if m.run(n.subs[0], start, func(j int) bool { return j == i }) {
					found = true
					break
				}
			}
		}
		if n.neg {
			copy(m.caps, saved)
			if found {
				return false
			}
			return k(i)
		}
		if !found {
			copy(m.caps, saved)
			return false
		}
		if k(i) {
			return true
		}
		copy(m.caps, saved)
		return false
	case rxBegin:
		return i == 0 && k(i)
	case rxBeginLine:
		return (i == 0 || (i < len(m.s) && rxLineTerminator(m.s[i-1]))) && k(i)
	case rxEnd:
		return m.atEnd(i) && k(i)
	case rxWord:
		return m.wordBoundary(i) && k(i)
	case rxNotWord:
		return !m.wordBoundary(i) && k(i)
	}
	return false
}

func (m *rxMatcher) seq(items []*rxNode, i int, k func(int) bool) bool {
	if len(items) == 0 {
		return k(i)
	}
	// Runs of single characters in a row: no recursion for them.
	if items[0].single != nil && items[0].kind == rxOne {
		if !items[0].single(m, i) {
			return false
		}
		return m.seq(items[1:], i+1, k)
	}
	return m.run(items[0], i, func(j int) bool { return m.seq(items[1:], j, k) })
}

func (m *rxMatcher) repeat(n *rxNode, count, i int, k func(int) bool) bool {
	sub := n.subs[0]
	if sub.single != nil {
		if !n.lazy {
			cnt := 0
			for (n.max < 0 || cnt < n.max) && sub.single(m, i+cnt) {
				cnt++
			}
			for ; cnt >= n.min; cnt-- {
				if k(i + cnt) {
					return true
				}
			}
			return false
		}
		cnt := 0
		for cnt < n.min {
			if !sub.single(m, i+cnt) {
				return false
			}
			cnt++
		}
		for {
			if k(i + cnt) {
				return true
			}
			if n.max >= 0 && cnt >= n.max {
				return false
			}
			if !sub.single(m, i+cnt) {
				return false
			}
			cnt++
		}
	}
	if count < n.min {
		return m.run(sub, i, func(j int) bool { return m.repeat(n, count+1, j, k) })
	}
	more := func() bool {
		if n.max >= 0 && count >= n.max {
			return false
		}
		return m.run(sub, i, func(j int) bool {
			if j == i {
				return false // an empty pass ends the loop
			}
			return m.repeat(n, count+1, j, k)
		})
	}
	if !n.lazy {
		return more() || k(i)
	}
	return k(i) || more()
}

// find is the first match at or after from: [start, end, group 1 start, group 1 end, …] (-1: a group that took no
// part), in characters of s; nil when there is none.
func (r *icuRegexp) find(s []rune, from int) []int {
	m := &rxMatcher{s: s, caps: make([]int, 2*(r.caps+1))}
	for start := from; start <= len(s); start++ {
		for j := range m.caps {
			m.caps[j] = -1
		}
		end := -1
		if m.run(r.root, start, func(e int) bool { end = e; return true }) {
			m.caps[0], m.caps[1] = start, end
			return m.caps
		}
	}
	return nil
}

func (r *icuRegexp) hasRunes(s []rune) bool { return r.find(s, 0) != nil }

// has says whether the pattern matches anywhere in s.
func (r *icuRegexp) has(s string) bool { return r.find([]rune(s), 0) != nil }

// findAll are the matches one after another, not overlapping (after an empty one the search moves on by one).
func (r *icuRegexp) findAll(s []rune) [][]int {
	var out [][]int
	for from := 0; from <= len(s); {
		m := r.find(s, from)
		if m == nil {
			break
		}
		out = append(out, append([]int(nil), m...))
		if m[1] == m[0] {
			from = m[1] + 1
		} else {
			from = m[1]
		}
	}
	return out
}

// replaceAll puts with in place of every match.
func (r *icuRegexp) replaceAll(s []rune, with string) []rune {
	var out []rune
	last := 0
	for _, m := range r.findAll(s) {
		out = append(out, s[last:m[0]]...)
		out = append(out, []rune(with)...)
		last = m[1]
	}
	return append(out, s[last:]...)
}

// replaceString is replaceAll on a string.
func (r *icuRegexp) replaceString(s, with string) string {
	return string(r.replaceAll([]rune(s), with))
}

// rxEscape is NSRegularExpression.escapedPattern(for:): the characters with a meaning in a pattern behind a backslash.
func rxEscape(s string) string {
	var out []rune
	for _, c := range s {
		switch c {
		case '\\', '*', '?', '+', '[', '(', ')', '{', '}', '^', '$', '|', '.', '/':
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	return string(out)
}

// aiUTF16Len is how many UTF-16 code units the characters take (NSString's length).
func aiUTF16Len(s []rune) int {
	n := 0
	for _, c := range s {
		n += utf16.RuneLen(c)
	}
	return n
}
