package core

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The table is what Foundation's ByteCountFormatter (.file) writes on macOS, made with Swift.
func TestFormatBytesMatchesFoundation(t *testing.T) {
	f, err := os.Open("testdata/format_bytes.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 2)
		v, _ := strconv.ParseInt(parts[0], 10, 64)
		if got := FormatBytes(v); got != parts[1] {
			t.Errorf("FormatBytes(%d) = %q, want %q", v, got, parts[1])
		}
		n++
	}
	if n < 100 {
		t.Fatalf("only %d rows", n)
	}
}

func TestShortHash(t *testing.T) {
	if got := ShortHash("a", "b"); len(got) != 12 {
		t.Fatalf("%q", got)
	}
}
