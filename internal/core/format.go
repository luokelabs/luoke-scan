// Package core is what a round looks at and decides: facts about files, the rules, the report, the tool's own data.
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// RulePackVersion is the version of the built-in rules; every report records it.
const RulePackVersion = "0.1.0"

// FormatBytes writes a size the way macOS does for files (Foundation's ByteCountFormatter, .file: powers of 1000):
// "Zero KB", "1 byte", "999 bytes", "1 KB", "62.9 MB", "6.44 GB". KB without decimals, MB with one, GB and up with two,
// trailing zeros dropped; rounded half up, and into the next unit when it reaches 1000.
func FormatBytes(n int64) string {
	if n == 0 {
		return "Zero KB"
	}
	sign, v := "", n
	if v < 0 {
		sign, v = "-", -v
	}
	if v < 1000 {
		if v == 1 {
			return sign + "1 byte"
		}
		return sign + strconv.FormatInt(v, 10) + " bytes"
	}
	units := []struct {
		name     string
		decimals int
	}{{"KB", 0}, {"MB", 1}, {"GB", 2}, {"TB", 2}, {"PB", 2}, {"EB", 2}}
	unit := uint64(1000)
	for i, u := range units {
		scale := uint64(1)
		for j := 0; j < u.decimals; j++ {
			scale *= 10
		}
		// v/unit with u.decimals places, half up, in integers (no float rounding).
		scaled := (uint64(v)*scale*2/unit + 1) / 2
		if scaled >= 1000*scale && i < len(units)-1 {
			unit *= 1000
			continue
		}
		s := strconv.FormatUint(scaled/scale, 10)
		if u.decimals > 0 {
			frac := strconv.FormatUint(scaled%scale, 10)
			frac = strings.Repeat("0", u.decimals-len(frac)) + frac
			if frac = strings.TrimRight(frac, "0"); frac != "" {
				s += "." + frac
			}
		}
		return sign + s + " " + u.name
	}
	return sign + strconv.FormatInt(v, 10) + " bytes"
}

// ISODay is the day in this Mac's time zone, yyyy-MM-dd.
func ISODay(t time.Time) string { return t.Local().Format("2006-01-02") }

// ISOTime is an instant as the reports write it: UTC, to the second.
func ISOTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// ShortHash is 12 hex characters of the SHA-256 of the parts joined by NUL: short, stable ids.
func ShortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:6])
}
