package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Files with the same contents: what a copy holds of its own, and the hashes that tell copies apart. Turning a copy
// into a clone is the service's (it changes files).

// attrCmnExtPrivateSize is ATTR_CMNEXT_PRIVATESIZE (in forkattr, with FSOPT_ATTR_CMN_EXTENDED): x/sys does not name it.
const attrCmnExtPrivateSize = 0x00000008

// PrivateBytes are the bytes only this file holds (APFS): what deleting it, or making it a clone, gives back. 0 for a
// clone nobody changed; ok false when the volume does not say.
func PrivateBytes(path string) (int64, bool) {
	var buf [64]byte
	if getattrlist(path, attrs(unix.ATTR_CMN_RETURNED_ATTRS, attrCmnExtPrivateSize), buf[:], unix.FSOPT_ATTR_CMN_EXTENDED|unix.FSOPT_NOFOLLOW) != nil {
		return 0, false
	}
	// u_int32_t length; attribute_set_t returned (common, vol, dir, file, fork); then the size.
	if binary.LittleEndian.Uint32(buf[20:24])&attrCmnExtPrivateSize == 0 {
		return 0, false
	}
	return int64(binary.LittleEndian.Uint64(buf[24:32])), true
}

// SameContents says whether two files have the same bytes, read side by side (nothing kept). A read that fails (a
// folder, an I/O error) is not the end of the file: what it did not read may differ, so the answer is "not the same".
func SameContents(a, b string) bool {
	fa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer fb.Close()
	x, y := make([]byte, 1<<20), make([]byte, 1<<20)
	for {
		n, errA := io.ReadFull(fa, x)
		m, errB := io.ReadFull(fb, y)
		endA := errA == io.EOF || errA == io.ErrUnexpectedEOF
		endB := errB == io.EOF || errB == io.ErrUnexpectedEOF
		if (errA != nil && !endA) || (errB != nil && !endB) {
			return false
		}
		if n != m || !bytes.Equal(x[:n], y[:m]) {
			return false
		}
		if endA || endB {
			return endA && endB
		}
	}
}

// fileSample is the SHA-256 of the first and last 64 KiB: tells most same-size files apart without reading them.
func fileSample(path string, size int64) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 64<<10)); err != nil {
		return "", false
	}
	if size > 128<<10 {
		if _, err := f.Seek(size-(64<<10), io.SeekStart); err != nil {
			return "", false
		}
		if _, err := io.Copy(h, io.LimitReader(f, 64<<10)); err != nil {
			return "", false
		}
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// fileDigest is the SHA-256 of the whole file, 1 MiB at a time; ok false when it cannot be read or the round stops.
func fileDigest(path string, cancelled func() bool) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		if cancelled != nil && cancelled() {
			return "", false
		}
		n, err := io.ReadFull(f, buf)
		h.Write(buf[:n])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "", false
		}
	}
	return hex.EncodeToString(h.Sum(nil)), true
}
