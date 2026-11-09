package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Value is a JSON value whose objects keep their order, written as Python's json.dumps(value, ensure_ascii=False)
// writes it: the eval (bench/run_eval.py) sends the input exactly as the scan does. Read back in order by ParseValue.
type Value struct {
	Kind ValueKind
	// Str: a string's text, or a number that is not a whole one as it was written.
	Str  string
	Int  int64
	Bool bool
	Arr  []Value
	Obj  []Field
}

// ValueKind is which kind of JSON value.
type ValueKind uint8

const (
	VNull ValueKind = iota
	VString
	VInt
	VNumber
	VBool
	VArray
	VObject
)

// Field is one key of an object, in order.
type Field struct {
	Key   string
	Value Value
}

func VStr(s string) Value              { return Value{Kind: VString, Str: s} }
func VInteger(n int64) Value           { return Value{Kind: VInt, Int: n} }
func VBoolean(b bool) Value            { return Value{Kind: VBool, Bool: b} }
func VList(a ...Value) Value           { return Value{Kind: VArray, Arr: nonNilValues(a)} }
func VObj(f ...Field) Value            { return Value{Kind: VObject, Obj: nonNilFields(f)} }
func VField(key string, v Value) Field { return Field{key, v} }

// VNullValue is JSON's null.
var VNullValue = Value{Kind: VNull}

func nonNilValues(a []Value) []Value {
	if a == nil {
		return []Value{}
	}
	return a
}

func nonNilFields(f []Field) []Field {
	if f == nil {
		return []Field{}
	}
	return f
}

// Text is the value as json.dumps(ensure_ascii=False) writes it: ", " and ": " between items.
func (v Value) Text() string {
	var b strings.Builder
	v.write(&b)
	return b.String()
}

func (v Value) write(b *strings.Builder) {
	switch v.Kind {
	case VNull:
		b.WriteString("null")
	case VString:
		writeQuoted(b, v.Str)
	case VInt:
		b.WriteString(strconv.FormatInt(v.Int, 10))
	case VNumber:
		b.WriteString(v.Str)
	case VBool:
		if v.Bool {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case VArray:
		b.WriteByte('[')
		for i, x := range v.Arr {
			if i > 0 {
				b.WriteString(", ")
			}
			x.write(b)
		}
		b.WriteByte(']')
	case VObject:
		b.WriteByte('{')
		for i, f := range v.Obj {
			if i > 0 {
				b.WriteString(", ")
			}
			writeQuoted(b, f.Key)
			b.WriteString(": ")
			f.Value.write(b)
		}
		b.WriteByte('}')
	}
}

func writeQuoted(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// Size is the length of Text in Unicode scalars (what Python's len counts), escapes included.
func (v Value) Size() int { return utf8.RuneCountInString(v.Text()) }

// escapedLen is a string's length once written into the JSON, without its quotes.
func escapedLen(s string) int { return VStr(s).Size() - 2 }

// Get is an object's value under key (the first with it).
func (v Value) Get(key string) (Value, bool) {
	if v.Kind != VObject {
		return Value{}, false
	}
	for _, f := range v.Obj {
		if f.Key == key {
			return f.Value, true
		}
	}
	return Value{}, false
}

// String is a string value's text.
func (v Value) String() (string, bool) { return v.Str, v.Kind == VString }

// Integer is a whole number's value.
func (v Value) Integer() (int64, bool) { return v.Int, v.Kind == VInt }

// Truthy is the value as Python's bool() takes it.
func (v Value) Truthy() bool {
	switch v.Kind {
	case VBool:
		return v.Bool
	case VInt:
		return v.Int != 0
	case VNumber:
		f, _ := strconv.ParseFloat(v.Str, 64)
		return f != 0
	case VString:
		return v.Str != ""
	case VArray:
		return len(v.Arr) > 0
	case VObject:
		return len(v.Obj) > 0
	}
	return false
}

// ParseValue reads JSON as Python's json.loads reads it, objects keeping their order (so Text writes it back as
// json.dumps would). A whole number is VInt; any other number keeps how it was written.
func ParseValue(data []byte) (Value, error) {
	text, ok := aiDecodeUTF8(data)
	if !ok {
		return Value{}, errors.New("不是 UTF-8")
	}
	return parseValueText(text, false)
}

// ParseFoundation reads JSON as Foundation's JSONSerialization takes it where that differs from json.loads: of a
// repeated key, the first is kept (what the Swift version's answers were read with).
func ParseFoundation(text string) (Value, error) { return parseValueText(text, true) }

func parseValueText(text string, firstWins bool) (Value, error) {
	p := &valueParser{s: []rune(text), firstWins: firstWins}
	p.space()
	v, err := p.value(0)
	if err != nil {
		return Value{}, err
	}
	p.space()
	if p.i != len(p.s) {
		return Value{}, p.fail("JSON 后面还有东西")
	}
	return v, nil
}

type valueParser struct {
	s         []rune
	i         int
	firstWins bool
}

func (p *valueParser) space() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\n' || p.s[p.i] == '\r' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *valueParser) fail(why string) error {
	return fmt.Errorf("JSON 第 %d 个字符：%s", p.i, why)
}

func (p *valueParser) value(depth int) (Value, error) {
	if depth >= 64 {
		return Value{}, p.fail("套得太深")
	}
	if p.i >= len(p.s) {
		return Value{}, p.fail("没写完")
	}
	switch p.s[p.i] {
	case '{':
		p.i++
		p.space()
		fields := []Field{}
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return VObj(fields...), nil
		}
		for {
			p.space()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return Value{}, p.fail("要一个键")
			}
			k, err := p.str()
			if err != nil {
				return Value{}, err
			}
			p.space()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return Value{}, p.fail("要冒号")
			}
			p.i++
			p.space()
			v, err := p.value(depth + 1)
			if err != nil {
				return Value{}, err
			}
			// json.loads keeps the last of a repeated key, where the first one was.
			replaced := false
			for j := range fields {
				if fields[j].Key == k {
					if !p.firstWins {
						fields[j].Value = v
					}
					replaced = true
					break
				}
			}
			if !replaced {
				fields = append(fields, Field{k, v})
			}
			p.space()
			if p.i >= len(p.s) {
				return Value{}, p.fail("没写完")
			}
			if p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.s[p.i] == '}' {
				p.i++
				return VObj(fields...), nil
			}
			return Value{}, p.fail("要逗号或 }")
		}
	case '[':
		p.i++
		p.space()
		items := []Value{}
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return VList(items...), nil
		}
		for {
			p.space()
			v, err := p.value(depth + 1)
			if err != nil {
				return Value{}, err
			}
			items = append(items, v)
			p.space()
			if p.i >= len(p.s) {
				return Value{}, p.fail("没写完")
			}
			if p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.s[p.i] == ']' {
				p.i++
				return VList(items...), nil
			}
			return Value{}, p.fail("要逗号或 ]")
		}
	case '"':
		s, err := p.str()
		return VStr(s), err
	case 't':
		return VBoolean(true), p.word("true")
	case 'f':
		return VBoolean(false), p.word("false")
	case 'n':
		return VNullValue, p.word("null")
	}
	return p.number()
}

func (p *valueParser) word(w string) error {
	ws := []rune(w)
	if p.i+len(ws) > len(p.s) || string(p.s[p.i:p.i+len(ws)]) != w {
		return p.fail("认不出")
	}
	p.i += len(ws)
	return nil
}

func (p *valueParser) number() (Value, error) {
	start := p.i
	digits := func() int {
		s := p.i
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
		return p.i - s
	}
	if p.i < len(p.s) && p.s[p.i] == '-' {
		p.i++
	}
	if digits() == 0 {
		return Value{}, p.fail("认不出")
	}
	whole := true
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		whole = false
		if digits() == 0 {
			return Value{}, p.fail("小数点后要有数字")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		whole = false
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return Value{}, p.fail("指数要有数字")
		}
	}
	literal := string(p.s[start:p.i])
	if whole {
		if n, err := strconv.ParseInt(literal, 10, 64); err == nil {
			return VInteger(n), nil
		}
	}
	return Value{Kind: VNumber, Str: literal}, nil
}

func (p *valueParser) str() (string, error) {
	p.i++
	var out []rune
	for {
		if p.i >= len(p.s) {
			return "", p.fail("字符串没写完")
		}
		c := p.s[p.i]
		p.i++
		if c == '"' {
			return string(out), nil
		}
		if c != '\\' {
			if c < 0x20 {
				return "", p.fail("字符串里有控制字符")
			}
			out = append(out, c)
			continue
		}
		if p.i >= len(p.s) {
			return "", p.fail("字符串没写完")
		}
		e := p.s[p.i]
		p.i++
		switch e {
		case '"':
			out = append(out, '"')
		case '\\':
			out = append(out, '\\')
		case '/':
			out = append(out, '/')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			u, err := p.hex4()
			if err != nil {
				return "", err
			}
			if u >= 0xD800 && u <= 0xDBFF && p.i+1 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
				save := p.i
				p.i += 2
				low, err := p.hex4()
				if err != nil {
					return "", err
				}
				if low >= 0xDC00 && low <= 0xDFFF {
					u = 0x10000 + ((u - 0xD800) << 10) + (low - 0xDC00)
				} else {
					p.i = save
				}
			}
			// A lone surrogate cannot be a string here; Python keeps it. None of the prompt files has one.
			if u >= 0xD800 && u <= 0xDFFF {
				return "", p.fail("单独的代理码点")
			}
			out = append(out, rune(u))
		default:
			return "", p.fail("认不出的转义")
		}
	}
}

func (p *valueParser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, p.fail(`\u 后要四位十六进制`)
	}
	n, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, p.fail(`\u 后要四位十六进制`)
	}
	p.i += 4
	return rune(n), nil
}
