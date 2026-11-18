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
// time.Time, []byte and PlistUID. Only reading; what a rule needs of an Info.plist, a launchd job, a preference file,
// an archive (keyedarchive.go).

// PlistUID is a binary property list's UID: in an NSKeyedArchiver archive, the index of an object in $objects. An XML
// property list writes it as a dictionary {"CF$UID": n}, left as that.
type PlistUID uint64

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

// DecodePlist decodes a property list from its bytes. Any program can write the files a rule reads (a launch agent in
// ~/Library/LaunchAgents), so a malformed one is only "not a property list": the decoders check every length and
// offset, and a panic they missed is caught here rather than ending the scan. Objects a binary list shares are decoded
// once and shared in the result too, so values are read, never changed.
func DecodePlist(data []byte) (v any, err error) {
	defer func() {
		if recover() != nil {
			v, err = nil, errPlist
		}
	}()
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return decodeBinaryPlist(data)
	}
	return decodeXMLPlist(data)
}

var errPlist = errors.New("not a property list")

// maxPlistDepth is how deeply arrays and dictionaries may nest; deeper is not a property list a rule reads.
const maxPlistDepth = 64

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
			return xmlValue(d, se, 1)
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

func xmlValue(d *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > maxPlistDepth {
		return nil, errPlist
	}
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
				val, err := xmlValue(d, v, depth+1)
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
				val, err := xmlValue(d, v, depth+1)
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

// bplist is a binary property list being decoded. data is where its objects may be (the header to the offset table).
// Each object is decoded once and kept in done, so one that is shared many times over costs no more than once.
type bplist struct {
	data    []byte
	offsets []byte // the offset table
	offSize int
	count   uint64 // objects in the table
	refSize int
	depth   int
	done    map[uint64]any
}

func decodeBinaryPlist(data []byte) (any, error) {
	if len(data) < 40 {
		return nil, errPlist
	}
	end := uint64(len(data) - 32)
	tr := data[end:]
	offSize, refSize := int(tr[6]), int(tr[7])
	n, top, table := binary.BigEndian.Uint64(tr[8:]), binary.BigEndian.Uint64(tr[16:]), binary.BigEndian.Uint64(tr[24:])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || table < 8 || table > end || n > (end-table)/uint64(offSize) {
		return nil, errPlist
	}
	p := &bplist{data: data[:table], offsets: data[table:end], offSize: offSize, count: n, refSize: refSize, done: map[uint64]any{}}
	return p.object(top)
}

func readUint(b []byte, size int) uint64 {
	var v uint64
	for i := 0; i < size; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// fits says whether n items of size bytes from at lie within the objects. It divides rather than multiplies, so a
// length written huge cannot wrap around and pass.
func (p *bplist) fits(at, n, size uint64) bool {
	end := uint64(len(p.data))
	return at <= end && n <= (end-at)/size
}

func (p *bplist) length(at uint64, low byte) (uint64, uint64, error) {
	if low != 0x0f {
		return uint64(low), at + 1, nil
	}
	if !p.fits(at+1, 1, 1) || p.data[at+1]>>4 != 0x1 || p.data[at+1]&0x0f > 3 {
		return 0, 0, errPlist
	}
	size := uint64(1) << (p.data[at+1] & 0x0f)
	if !p.fits(at+2, size, 1) {
		return 0, 0, errPlist
	}
	return readUint(p.data[at+2:], int(size)), at + 2 + size, nil
}

// object decodes the object ref, or gives the one decoded before. Nesting deeper than maxPlistDepth, which a list that
// contains itself always reaches, is not a property list.
func (p *bplist) object(ref uint64) (any, error) {
	if ref >= p.count || p.depth >= maxPlistDepth {
		return nil, errPlist
	}
	if v, ok := p.done[ref]; ok {
		return v, nil
	}
	p.depth++
	v, err := p.decode(readUint(p.offsets[ref*uint64(p.offSize):], p.offSize))
	p.depth--
	if err != nil {
		return nil, err
	}
	p.done[ref] = v
	return v, nil
}

func (p *bplist) decode(at uint64) (any, error) {
	if at < 8 || at >= uint64(len(p.data)) {
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
		if low > 4 {
			return nil, errPlist
		}
		size := uint64(1) << low
		if !p.fits(at+1, size, 1) {
			return nil, errPlist
		}
		return int64(readUint(p.data[at+1:], int(size))), nil
	case 0x2:
		if (low != 2 && low != 3) || !p.fits(at+1, uint64(1)<<low, 1) {
			return nil, errPlist
		}
		if low == 2 {
			return float64(math.Float32frombits(uint32(readUint(p.data[at+1:], 4)))), nil
		}
		return math.Float64frombits(readUint(p.data[at+1:], 8)), nil
	case 0x8:
		size := uint64(low) + 1
		if size > 8 || !p.fits(at+1, size, 1) {
			return nil, errPlist
		}
		return PlistUID(readUint(p.data[at+1:], int(size))), nil
	case 0x3:
		if !p.fits(at+1, 8, 1) {
			return nil, errPlist
		}
		secs := math.Float64frombits(readUint(p.data[at+1:], 8))
		return time.Unix(978307200, 0).Add(time.Duration(secs * float64(time.Second))), nil
	case 0x4, 0x5, 0x6:
		n, start, err := p.length(at, low)
		if err != nil {
			return nil, err
		}
		size := uint64(1)
		if high == 0x6 {
			size = 2
		}
		if !p.fits(start, n, size) {
			return nil, errPlist
		}
		b := p.data[start : start+n*size]
		switch high {
		case 0x4:
			return append([]byte(nil), b...), nil
		case 0x5:
			return string(b), nil
		}
		u := make([]uint16, n)
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
		refs := uint64(1)
		if high == 0xd {
			refs = 2
		}
		if !p.fits(start, n, refs*rs) {
			return nil, errPlist
		}
		ref := func(i uint64) uint64 { return readUint(p.data[start+i*rs:], p.refSize) }
		if high == 0xa {
			out := make([]any, 0, n)
			for i := uint64(0); i < n; i++ {
				v, err := p.object(ref(i))
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			return out, nil
		}
		out := map[string]any{}
		for i := uint64(0); i < n; i++ {
			k, err := p.object(ref(i))
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errPlist
			}
			v, err := p.object(ref(n + i))
			if err != nil {
				return nil, err
			}
			out[ks] = v
		}
		return out, nil
	}
	return nil, errPlist
}
