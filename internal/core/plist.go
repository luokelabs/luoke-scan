package core

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Property lists, XML or binary (bplist00), decoded into map[string]any, []any, string, int64, float64, bool,
// time.Time and []byte. Only reading; what a rule needs of an Info.plist, a launchd job, a preference file.

// ReadPlist decodes the property list in a file (at most 16 MB).
func ReadPlist(path string) (any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return nil, err
	}
	return DecodePlist(data)
}

// ReadPlistDict decodes a file whose top is a dictionary; nil otherwise.
func ReadPlistDict(path string) map[string]any {
	v, err := ReadPlist(path)
	if err != nil {
		return nil
	}
	d, _ := v.(map[string]any)
	return d
}

func plistInt(path, key string) int {
	d := ReadPlistDict(path)
	if d == nil {
		return 0
	}
	switch v := d[key].(type) {
	case string:
		n, _ := strconv.Atoi(v)
		return n
	case int64:
		return int(v)
	}
	return 0
}

// PlistString is a string value of a dictionary, or "".
func PlistString(d map[string]any, key string) string {
	s, _ := d[key].(string)
	return s
}

// DecodePlist decodes a property list from its bytes.
func DecodePlist(data []byte) (any, error) {
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return decodeBinaryPlist(data)
	}
	return decodeXMLPlist(data)
}

var errPlist = errors.New("not a property list")

func decodeXMLPlist(data []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	for {
		t, err := d.Token()
		if err != nil {
			return nil, errPlist
		}
		if se, ok := t.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				continue
			}
			return xmlValue(d, se)
		}
	}
}

func xmlText(d *xml.Decoder) (string, error) {
	var sb strings.Builder
	for {
		t, err := d.Token()
		if err != nil {
			return "", err
		}
		switch v := t.(type) {
		case xml.CharData:
			sb.Write(v)
		case xml.EndElement:
			return sb.String(), nil
		case xml.StartElement:
			return "", errPlist
		}
	}
}

func xmlValue(d *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		out := map[string]any{}
		key := ""
		for {
			t, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch v := t.(type) {
			case xml.StartElement:
				if v.Name.Local == "key" {
					if key, err = xmlText(d); err != nil {
						return nil, err
					}
					continue
				}
				val, err := xmlValue(d, v)
				if err != nil {
					return nil, err
				}
				out[key] = val
			case xml.EndElement:
				return out, nil
			}
		}
	case "array":
		out := []any{}
		for {
			t, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch v := t.(type) {
			case xml.StartElement:
				val, err := xmlValue(d, v)
				if err != nil {
					return nil, err
				}
				out = append(out, val)
			case xml.EndElement:
				return out, nil
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	}
	s, err := xmlText(d)
	if err != nil {
		return nil, err
	}
	switch se.Name.Local {
	case "string":
		return s, nil
	case "integer":
		n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64)
		if err != nil {
			return nil, errPlist
		}
		return n, nil
	case "real":
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, errPlist
		}
		return f, nil
	case "date":
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
		if err != nil {
			return nil, errPlist
		}
		return t, nil
	case "data":
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, errPlist
		}
		return b, nil
	}
	return nil, errPlist
}

type bplist struct {
	data    []byte
	offsets []uint64
	refSize int
	depth   int
}

func decodeBinaryPlist(data []byte) (any, error) {
	if len(data) < 40 {
		return nil, errPlist
	}
	tr := data[len(data)-32:]
	offSize, refSize := int(tr[6]), int(tr[7])
	n, top, table := binary.BigEndian.Uint64(tr[8:]), binary.BigEndian.Uint64(tr[16:]), binary.BigEndian.Uint64(tr[24:])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || n > uint64(len(data)) || table+n*uint64(offSize) > uint64(len(data)) {
		return nil, errPlist
	}
	p := &bplist{data: data, refSize: refSize}
	p.offsets = make([]uint64, n)
	for i := uint64(0); i < n; i++ {
		p.offsets[i] = readUint(data[table+i*uint64(offSize):], offSize)
	}
	return p.object(top)
}

func readUint(b []byte, size int) uint64 {
	var v uint64
	for i := 0; i < size; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func (p *bplist) length(at uint64, low byte) (uint64, uint64, error) {
	if low != 0x0f {
		return uint64(low), at + 1, nil
	}
	if at+2 > uint64(len(p.data)) || p.data[at+1]>>4 != 0x1 {
		return 0, 0, errPlist
	}
	size := uint64(1) << (p.data[at+1] & 0x0f)
	if at+2+size > uint64(len(p.data)) {
		return 0, 0, errPlist
	}
	return readUint(p.data[at+2:], int(size)), at + 2 + size, nil
}

func (p *bplist) object(ref uint64) (any, error) {
	if ref >= uint64(len(p.offsets)) || p.depth > 64 {
		return nil, errPlist
	}
	p.depth++
	defer func() { p.depth-- }()
	at := p.offsets[ref]
	if at >= uint64(len(p.data)) {
		return nil, errPlist
	}
	marker := p.data[at]
	high, low := marker>>4, marker&0x0f
	switch high {
	case 0x0:
		switch marker {
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		}
		return nil, nil
	case 0x1:
		size := uint64(1) << low
		if at+1+size > uint64(len(p.data)) {
			return nil, errPlist
		}
		v := readUint(p.data[at+1:], int(size))
		return int64(v), nil
	case 0x2:
		size := uint64(1) << low
		if at+1+size > uint64(len(p.data)) {
			return nil, errPlist
		}
		if size == 4 {
			return float64(math.Float32frombits(uint32(readUint(p.data[at+1:], 4)))), nil
		}
		return math.Float64frombits(readUint(p.data[at+1:], 8)), nil
	case 0x3:
		if at+9 > uint64(len(p.data)) {
			return nil, errPlist
		}
		secs := math.Float64frombits(readUint(p.data[at+1:], 8))
		return time.Unix(978307200, 0).Add(time.Duration(secs * float64(time.Second))), nil
	case 0x4, 0x5, 0x6:
		n, start, err := p.length(at, low)
		if err != nil {
			return nil, err
		}
		if high == 0x6 {
			n *= 2
		}
		if start+n > uint64(len(p.data)) {
			return nil, errPlist
		}
		b := p.data[start : start+n]
		switch high {
		case 0x4:
			return append([]byte(nil), b...), nil
		case 0x5:
			return string(b), nil
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[2*i:])
		}
		return string(utf16.Decode(u)), nil
	case 0xa, 0xd:
		n, start, err := p.length(at, low)
		if err != nil {
			return nil, err
		}
		rs := uint64(p.refSize)
		count := n
		if high == 0xd {
			count = 2 * n
		}
		if start+count*rs > uint64(len(p.data)) {
			return nil, errPlist
		}
		if high == 0xa {
			out := make([]any, 0, n)
			for i := uint64(0); i < n; i++ {
				v, err := p.object(readUint(p.data[start+i*rs:], p.refSize))
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			return out, nil
		}
		out := map[string]any{}
		for i := uint64(0); i < n; i++ {
			k, err := p.object(readUint(p.data[start+i*rs:], p.refSize))
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errPlist
			}
			v, err := p.object(readUint(p.data[start+(n+i)*rs:], p.refSize))
			if err != nil {
				return nil, err
			}
			out[ks] = v
		}
		return out, nil
	}
	return nil, errPlist
}
