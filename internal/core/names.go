package core

import (
	"net/url"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DisplayName: a file's or folder's name as the user reads it, for a finding's title and what a card or page says. A
// name kept with its characters percent-encoded (what some downloaders keep of a URL: 「%E9%A6%99%E6%B8%AF.pdf」) is
// shown decoded when that gives printable text without a slash; else as it is. Matching, keys and the report's paths
// keep the name as the file system has it.
func DisplayName(path string) string {
	name := filepath.Base(path)
	if !strings.Contains(name, "%") {
		return name
	}
	d, err := url.PathUnescape(name)
	if err != nil || d == name || !utf8.ValidString(d) || strings.Contains(d, "/") {
		return name
	}
	for _, r := range d {
		if !unicode.IsPrint(r) {
			return name
		}
	}
	return d
}
