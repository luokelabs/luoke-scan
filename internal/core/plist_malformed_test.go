package core

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// bplistOf writes a binary property list by hand: each object as its raw bytes (marker first), two-byte offsets,
// one-byte references, top the index of the top object.
func bplistOf(top uint64, objects ...[]byte) []byte {
	b := []byte("bplist00")
	var at []int
	for _, o := range objects {
		at = append(at, len(b))
		b = append(b, o...)
	}
	table := len(b)
	for _, a := range at {
		b = binary.BigEndian.AppendUint16(b, uint16(a))
	}
	tr := make([]byte, 32)
	tr[6], tr[7] = 2, 1
	binary.BigEndian.PutUint64(tr[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(tr[16:], top)
	binary.BigEndian.PutUint64(tr[24:], uint64(table))
	return append(b, tr...)
}

// withTrailer is a list with one field of its trailer (at, 8 bytes) changed.
func withTrailer(b []byte, at int, v uint64) []byte {
	b = append([]byte(nil), b...)
	binary.BigEndian.PutUint64(b[len(b)-32+at:], v)
	return b
}

// big is a length marker (0x13) followed by v in 8 bytes, the way a list writes a count of 15 or more.
func big(v uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte{0x13}, v)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// decodeBare decodes without DecodePlist's recover, so a panic in the decoder fails the test.
func decodeBare(t *testing.T, data []byte) (v any, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked: %v", r)
			err = errPlist
		}
	}()
	return decodeBinaryPlist(data)
}

// nested is n levels: arrays of one, each holding the next, down to true.
func nested(n int) []byte {
	var objs [][]byte
	for i := 0; i < n-1; i++ {
		objs = append(objs, []byte{0xa1, byte(i + 1)})
	}
	return bplistOf(0, append(objs, []byte{0x09})...)
}

func malformedBinaryPlists() map[string][]byte {
	ok := bplistOf(0, []byte{0xa1, 1}, []byte{0x51, 'a'})
	header := bplistOf(0, []byte{0x51, 'a'})
	binary.BigEndian.PutUint16(header[len(header)-34:], 2) // the one offset points into "bplist00"
	return map[string][]byte{
		// The count wraps start+count past zero and the array is made with that capacity.
		"array of 2^64-1 items": bplistOf(0, cat([]byte{0xaf}, big(^uint64(0)))),
		// Twice the count wraps to zero; reading the keys then runs off the end.
		"dictionary of 2^63 entries":  bplistOf(0, cat([]byte{0xdf}, big(1<<63))),
		"string longer than the file": bplistOf(0, cat([]byte{0x5f}, big(^uint64(0)))),
		"data longer than the file":   bplistOf(0, cat([]byte{0x4f}, big(^uint64(0)-3))),
		// Twice the length wraps to 2.
		"UTF-16 string whose length doubles past 2^64": bplistOf(0, cat([]byte{0x6f}, big(1<<63+1)), []byte{0, 'a'}),
		"length in 16 bytes":                           bplistOf(0, cat([]byte{0x5f, 0x14}, make([]byte, 16))),
		"length that is not an integer":                bplistOf(0, []byte{0x5f, 0x51, 'a'}),
		"length cut off by the offset table":           bplistOf(0, []byte{0x5f}),
		"real of 1 byte":                               bplistOf(0, []byte{0x20, 0x01}),
		"integer of 2^15 bytes":                        bplistOf(0, []byte{0x1f, 0x01}),
		"date cut off by the offset table":             bplistOf(0, []byte{0x33, 0, 0}),
		"UID cut off by the offset table":              bplistOf(0, []byte{0x83, 0}),
		"UID of 16 bytes":                              bplistOf(0, cat([]byte{0x8f}, make([]byte, 16))),
		"offset table at 2^64-1":                       withTrailer(ok, 24, ^uint64(0)),
		"offset table inside the header":               withTrailer(ok, 24, 4),
		"more objects than the offset table holds":     withTrailer(ok, 8, 3),
		"2^64-1 objects":                               withTrailer(ok, 8, ^uint64(0)),
		"top past the last object":                     withTrailer(ok, 16, 2),
		"object inside the header":                     header,
		"reference past the last object":               bplistOf(0, []byte{0xa1, 7}),
		"array that contains itself":                   bplistOf(0, []byte{0xa2, 0, 0}),
		"key that is not a string":                     bplistOf(0, []byte{0xd1, 1, 1}, []byte{0x10, 1}),
		"65 levels deep":                               nested(65),
		"unknown marker":                               bplistOf(0, []byte{0x70}),
		"too short":                                    []byte("bplist00"),
	}
}

// A list some program wrote wrong on purpose is "not a property list": no panic, no endless reading.
func TestMalformedBinaryPlistIsNotAPlist(t *testing.T) {
	for name, data := range malformedBinaryPlists() {
		t.Run(name, func(t *testing.T) {
			if v, err := decodeBare(t, data); !errors.Is(err, errPlist) {
				t.Errorf("= %#v, %v; want errPlist", v, err)
			}
			if v, err := DecodePlist(data); err == nil {
				t.Errorf("DecodePlist = %#v", v)
			}
		})
	}
}

// What is written by hand the way it should be (a dictionary, UTF-16, a real, a UID, 64 levels) decodes, so the cases above fail for what they break.
func TestBinaryPlistByHand(t *testing.T) {
	// 16 UTF-16 units, so the length is written after the marker (0x6f, then 0x10 0x10).
	units := []byte{0x6f, 0x10, 0x10, 0x87, 0xba, 0x58, 0xf3}
	for i := 0; i < 14; i++ {
		units = append(units, 0, '!')
	}
	v, err := decodeBare(t, bplistOf(0,
		[]byte{0xd3, 1, 2, 3, 4, 5, 6},
		[]byte{0x51, 'a'}, []byte{0x51, 'b'}, []byte{0x51, 'c'},
		[]byte{0x10, 7}, units,
		[]byte{0xa3, 7, 8, 9}, []byte{0x09}, []byte{0x23, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18}, []byte{0x81, 0x01, 0x02},
	))
	want := map[string]any{"a": int64(7), "b": "螺壳" + strings.Repeat("!", 14), "c": []any{true, 3.141592653589793, PlistUID(258)}}
	if err != nil || !reflect.DeepEqual(v, want) {
		t.Errorf("= %#v, %v", v, err)
	}
	if _, err := decodeBare(t, nested(64)); err != nil {
		t.Errorf("64 levels: %v", err)
	}
}

// Many levels each referring twice to the one below: each object is read once, so 40 levels take no time rather than
// 2^40 reads, and the result shares the objects the same way.
func TestSharedBinaryPlistObjectsAreReadOnce(t *testing.T) {
	var objs [][]byte
	for i := 0; i < 40; i++ {
		objs = append(objs, []byte{0xa2, byte(i + 1), byte(i + 1)})
	}
	data := bplistOf(0, append(objs, []byte{0x51, 'x'})...)
	done := make(chan any, 1)
	go func() {
		v, _ := DecodePlist(data)
		done <- v
	}()
	select {
	case v := <-done:
		for i := 0; i < 40; i++ {
			a, ok := v.([]any)
			if !ok || len(a) != 2 {
				t.Fatalf("level %d: %#v", i, v)
			}
			v = a[1]
		}
		if v != "x" {
			t.Errorf("leaf = %#v", v)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("still reading after 10 s")
	}
}

// XML nests no deeper than binary does: past 64 levels it is not a property list, rather than a recursion as deep as
// the file is long.
func TestDeepXMLPlistIsNotAPlist(t *testing.T) {
	nest := func(n int) []byte {
		return []byte("<plist>" + strings.Repeat("<array>", n-1) + "<true/>" + strings.Repeat("</array>", n-1) + "</plist>")
	}
	if _, err := DecodePlist(nest(64)); err != nil {
		t.Errorf("64 levels: %v", err)
	}
	if v, err := DecodePlist(nest(65)); err == nil {
		t.Errorf("65 levels = %#v", v)
	}
	if v, err := DecodePlist(nest(100000)); err == nil {
		t.Errorf("100000 levels = %#v", v)
	}
}

// Whatever the bytes, the binary decoder returns, without panicking.
func FuzzDecodeBinaryPlist(f *testing.F) {
	for _, data := range malformedBinaryPlists() {
		f.Add(data)
	}
	f.Add(bplistOf(0, []byte{0xd1, 1, 2}, []byte{0x51, 'a'}, []byte{0xa2, 3, 3}, []byte{0x10, 7}))
	f.Fuzz(func(t *testing.T, data []byte) {
		decodeBare(t, data)
	})
}
