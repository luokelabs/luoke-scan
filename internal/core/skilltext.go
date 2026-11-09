package core

import (
	"strconv"
	"strings"
	"unicode"
)

// Swift counts and cuts text by Character (an extended grapheme cluster: a letter with its combining marks, an emoji
// with its modifiers, a flag, "\r\n"); the findings' titles and evidence are cut the same way here. The cluster
// boundaries follow UAX #29 with the character properties Go has (no Indic conjunct rule).

type gcbClass uint8

const (
	gcbOther gcbClass = iota
	gcbCR
	gcbLF
	gcbControl
	gcbExtend
	gcbZWJ
	gcbRI
	gcbPrepend
	gcbSpacingMark
	gcbL
	gcbV
	gcbT
	gcbLV
	gcbLVT
)

func isPrependedConcatenationMark(r rune) bool {
	switch {
	case r >= 0x600 && r <= 0x605, r == 0x6DD, r == 0x70F, r == 0x890, r == 0x891, r == 0x8E2, r == 0x110BD, r == 0x110CD:
		return true
	}
	return false
}

func gcbOf(r rune) gcbClass {
	switch {
	case r == '\r':
		return gcbCR
	case r == '\n':
		return gcbLF
	case r < 0x20 || (r >= 0x7F && r < 0xA0):
		return gcbControl
	case r < 0x300:
		return gcbOther
	case r == 0x200D:
		return gcbZWJ
	case r == 0x200C:
		return gcbExtend
	case r >= 0x1F1E6 && r <= 0x1F1FF:
		return gcbRI
	case r >= 0x1F3FB && r <= 0x1F3FF, r >= 0xE0020 && r <= 0xE007F:
		return gcbExtend
	case r >= 0x1100 && r <= 0x115F, r >= 0xA960 && r <= 0xA97C:
		return gcbL
	case r >= 0x1160 && r <= 0x11A7, r >= 0xD7B0 && r <= 0xD7C6:
		return gcbV
	case r >= 0x11A8 && r <= 0x11FF, r >= 0xD7CB && r <= 0xD7FB:
		return gcbT
	case r >= 0xAC00 && r <= 0xD7A3:
		if (r-0xAC00)%28 == 0 {
			return gcbLV
		}
		return gcbLVT
	case isPrependedConcatenationMark(r):
		return gcbPrepend
	case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r), unicode.Is(unicode.Other_Grapheme_Extend, r):
		return gcbExtend
	case unicode.Is(unicode.Mc, r), r == 0xE33, r == 0xEB3:
		return gcbSpacingMark
	case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
		return gcbControl
	}
	return gcbOther
}

// gcbExtPict approximates Extended_Pictographic: the emoji blocks and the older symbols emoji use.
func gcbExtPict(r rune) bool {
	switch {
	case r == 0xA9, r == 0xAE, r == 0x203C, r == 0x2049, r == 0x2122, r == 0x2139, r >= 0x2194 && r <= 0x2199,
		r >= 0x21A9 && r <= 0x21AA, r >= 0x231A && r <= 0x231B, r == 0x2328, r == 0x2388, r == 0x23CF, r >= 0x23E9 && r <= 0x23F3,
		r >= 0x23F8 && r <= 0x23FA, r == 0x24C2, r >= 0x25AA && r <= 0x25AB, r == 0x25B6, r == 0x25C0, r >= 0x25FB && r <= 0x25FE,
		r >= 0x2600 && r <= 0x27BF, r >= 0x2934 && r <= 0x2935, r >= 0x2B05 && r <= 0x2B07, r >= 0x2B1B && r <= 0x2B1C,
		r == 0x2B50, r == 0x2B55, r == 0x3030, r == 0x303D, r == 0x3297, r == 0x3299:
		return true
	case r >= 0x1F000 && r <= 0x1FAFF:
		return !(r >= 0x1F1E6 && r <= 0x1F1FF) && !(r >= 0x1F3FB && r <= 0x1F3FF)
	case r >= 0x1FC00 && r <= 0x1FFFD:
		return true
	}
	return false
}

// incbLinker and incbConsonant: the viramas and consonants of the scripts whose conjuncts are one Character (GB9c).
func incbLinker(r rune) bool {
	switch r {
	case 0x094D, 0x09CD, 0x0ACD, 0x0B4D, 0x0C4D, 0x0D4D:
		return true
	}
	return false
}

func incbConsonant(r rune) bool {
	for _, g := range [][2]rune{{0x0915, 0x0939}, {0x0958, 0x095F}, {0x0978, 0x097F}, {0x0995, 0x09A8}, {0x09AA, 0x09B0}, {0x09B2, 0x09B2},
		{0x09B6, 0x09B9}, {0x09DC, 0x09DD}, {0x09DF, 0x09DF}, {0x09F0, 0x09F1}, {0x0A95, 0x0AA8}, {0x0AAA, 0x0AB0}, {0x0AB2, 0x0AB3},
		{0x0AB5, 0x0AB9}, {0x0AF9, 0x0AF9}, {0x0B15, 0x0B28}, {0x0B2A, 0x0B30}, {0x0B32, 0x0B33}, {0x0B35, 0x0B39}, {0x0B5C, 0x0B5D},
		{0x0B5F, 0x0B5F}, {0x0B71, 0x0B71}, {0x0C15, 0x0C28}, {0x0C2A, 0x0C39}, {0x0C58, 0x0C5A}, {0x0D15, 0x0D3A}} {
		if r >= g[0] && r <= g[1] {
			return true
		}
	}
	return false
}

// gcbStarts are the indexes in s where a Character starts (and len(s) at the end).
func gcbStarts(s []rune) []int {
	if len(s) == 0 {
		return []int{0}
	}
	out := []int{0}
	props := make([]gcbClass, len(s))
	for i, r := range s {
		props[i] = gcbOf(r)
	}
	riCount := 0 // regional indicators in a row before i
	pictBeforeZWJ := false
	inPict := false // in ExtPict Extend*
	if props[0] == gcbRI {
		riCount = 1
	}
	inPict = gcbExtPict(s[0])
	conjunct := 0 // 1: after a consonant (and marks), 2: and a virama since
	if incbConsonant(s[0]) {
		conjunct = 1
	}
	for i := 1; i < len(s); i++ {
		a, b := props[i-1], props[i]
		brk := true
		switch {
		case a == gcbCR && b == gcbLF:
			brk = false
		case a == gcbControl || a == gcbCR || a == gcbLF:
			brk = true
		case b == gcbControl || b == gcbCR || b == gcbLF:
			brk = true
		case a == gcbL && (b == gcbL || b == gcbV || b == gcbLV || b == gcbLVT):
			brk = false
		case (a == gcbLV || a == gcbV) && (b == gcbV || b == gcbT):
			brk = false
		case (a == gcbLVT || a == gcbT) && b == gcbT:
			brk = false
		case b == gcbExtend || b == gcbZWJ:
			brk = false
		case b == gcbSpacingMark:
			brk = false
		case a == gcbPrepend:
			brk = false
		case conjunct == 2 && incbConsonant(s[i]):
			brk = false
		case a == gcbZWJ && pictBeforeZWJ && gcbExtPict(s[i]):
			brk = false
		case a == gcbRI && b == gcbRI && riCount%2 == 1:
			brk = false
		}
		// The state for the next pair.
		switch {
		case incbConsonant(s[i]):
			conjunct = 1
		case incbLinker(s[i]) && conjunct >= 1:
			conjunct = 2
		case (b == gcbExtend || b == gcbZWJ) && conjunct >= 1:
		default:
			conjunct = 0
		}
		pictBeforeZWJ = b == gcbZWJ && inPict
		if gcbExtPict(s[i]) {
			inPict = true
		} else if b != gcbExtend {
			inPict = false
		}
		if b == gcbRI {
			if a == gcbRI && !brk {
				riCount++
			} else {
				riCount = 1
			}
		} else {
			riCount = 0
		}
		if brk {
			out = append(out, i)
		}
	}
	return append(out, len(s))
}

// graphemeCount is Swift's String.count.
func graphemeCount(s string) int { return len(gcbStarts([]rune(s))) - 1 }

// graphemePrefix is the first n Characters of s.
func graphemePrefix(s []rune, n int) []rune {
	starts := gcbStarts(s)
	if n >= len(starts)-1 {
		return s
	}
	return s[:starts[n]]
}

// aiCut is String(t.prefix(max)) + "…" when t has more than max Characters.
func aiCut(t string, max int) string {
	r := []rune(t)
	starts := gcbStarts(r)
	if len(starts)-1 > max {
		return string(r[:starts[max]]) + "…"
	}
	return t
}

// aiClean is text from a skill made safe to show: no control or invisible characters, at most max Characters.
func aiClean(s string, max int) string {
	var b strings.Builder
	for _, v := range s {
		if v >= 0x20 && v != 0x7F && !(v >= 0x80 && v <= 0x9F) && !(v >= 0x200B && v <= 0x200F) && !(v >= 0x202A && v <= 0x202E) &&
			!(v >= 0x2060 && v <= 0x2069) && v != 0xFEFF && !(v >= 0xE0000 && v <= 0xE007F) && !(v >= 0xFFF9 && v <= 0xFFFB) {
			b.WriteRune(v)
		}
	}
	return aiCut(aiTrimWS(b.String()), max)
}

// signalPlace is where a signal is, for the evidence: （file 第 1、2 行）.
func signalPlace(s SkillSignal) string {
	if s.File == "" {
		return ""
	}
	file := aiClean(s.File, 120)
	if len(s.Lines) == 0 {
		return "（" + file + "）"
	}
	var ls []string
	for i, l := range s.Lines {
		if i >= 4 {
			break
		}
		ls = append(ls, strconv.Itoa(l))
	}
	more := ""
	if len(s.Lines) > 4 {
		more = "等"
	}
	return "（" + file + " 第 " + strings.Join(ls, "、") + " 行" + more + "）"
}
