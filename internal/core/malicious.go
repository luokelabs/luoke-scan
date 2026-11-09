package core

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The list of known malicious packages (OSV's MAL- entries, as OpenSSF's malicious-packages publishes them), kept in
// the data directory as one small text file and matched on this Mac only: the packages a project uses never leave it.
// Nothing here downloads anything; the list comes in through `luoke-scan malicious-import` from files already here.
//
// The file (MaliciousListName), UTF-8, one line each:
//
//	# luoke-scan malicious packages 1
//	# date 2026-10-15          how current the list is: the oldest of the ecosystems' days below
//	# entries 3
//	# date-eco npm 2026-10-15  per ecosystem, the newest "modified" day (UTC) of the entries imported for it
//	npm	@scope/name	MAL-2024-1	*                 every version
//	PyPI	evil-pkg	MAL-2024-2	=1.0.0 =1.0.1         these versions (name normalized, see MalName)
//	crates.io	bad-crate	MAL-2024-3	[1.0.0,1.2.0) [2.0.0,]   ranges: [introduced,fixed) or [introduced,last_affected]
//
// Fields are separated by one tab; names and versions never hold whitespace (an entry that would is left out).
//
// An import adds to the list: the records it reads replace the lines of the same MAL ids, and every other line stays,
// so importing npm's export and then PyPI's keeps both (osv.dev exports one ecosystem at a time).

// MaliciousListName is the list's file in the data directory.
const MaliciousListName = "malicious-packages.txt"

const malListHeader = "# luoke-scan malicious packages 1"

// MalEcosystems are the ecosystems the rule compares (OSV's spelling). Entries for others are left out of the list.
var MalEcosystems = []string{"npm", "PyPI", "crates.io"}

// Limits of what the list and its import read.
const (
	malMaxListBytes = 256 << 20
	malMaxOSVBytes  = 4 << 20
	malMaxZipBytes  = 2 << 30
	// malMaxName: longest package name or id kept (npm allows 214); malMaxSpec: longest version field on one line.
	malMaxName = 512
	malMaxSpec = 16 << 10
)

// malMaxImportFiles: OSV records one import reads at most (a variable for the tests).
var malMaxImportFiles = 2_000_000

// MalList is the list as loaded.
type MalList struct {
	// Date: how current the list is, "YYYY-MM-DD": the oldest of its ecosystems' days, each the newest entry imported
	// for it ("" when the entries said none).
	Date    string
	Entries int
	byKey   map[string][]malEntry
}

type malEntry struct {
	ID       string
	All      bool
	Versions []string
	Ranges   []malRange
}

// malRange: from Lo (inclusive) up to Hi, inclusive when HiIncl; Hi "" has no end.
type malRange struct {
	Lo, Hi string
	HiIncl bool
}

func malKey(eco, name string) string { return eco + "\x00" + MalName(eco, name) }

// MalName is a package name as the list compares it: PyPI's normalized as PEP 503 says (lowercase, runs of -, _ and .
// one -); crates.io's lowercase with _ as - (crates.io treats them as the same name); npm's as written.
func MalName(eco, name string) string {
	switch eco {
	case "PyPI":
		var b strings.Builder
		dash := false
		for _, c := range strings.ToLower(name) {
			if c == '-' || c == '_' || c == '.' {
				if !dash {
					b.WriteByte('-')
				}
				dash = true
				continue
			}
			dash = false
			b.WriteRune(c)
		}
		return b.String()
	case "crates.io":
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	}
	return name
}

// malVersion: a version as compared: without a leading "v" or "=", and PyPI's lowercase.
func malVersion(eco, v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimPrefix(v, "v")
	if eco == "PyPI" {
		v = strings.ToLower(v)
	}
	return v
}

// Match is the MAL ids the list has for this package at this version, sorted; none when it is not on the list.
func (l *MalList) Match(eco, name, version string) []string {
	if l == nil {
		return nil
	}
	entries := l.byKey[malKey(eco, name)]
	if len(entries) == 0 {
		return nil
	}
	v := malVersion(eco, version)
	var out []string
	for _, e := range entries {
		if e.matches(v) {
			out = append(out, e.ID)
		}
	}
	return aiSortedUnique(out)
}

func (e malEntry) matches(v string) bool {
	if e.All {
		return true
	}
	if v == "" {
		return false
	}
	for _, x := range e.Versions {
		if x == v {
			return true
		}
	}
	for _, r := range e.Ranges {
		if r.contains(v) {
			return true
		}
	}
	return false
}

// contains: only versions both sides can read as dotted numbers (an optional pre-release after "-") are compared;
// anything else is not taken as inside (a range never makes a guess into a finding).
func (r malRange) contains(v string) bool {
	if c, ok := compareVersions(v, r.Lo); !ok || c < 0 {
		return false
	}
	if r.Hi == "" {
		return true
	}
	c, ok := compareVersions(v, r.Hi)
	if !ok {
		return false
	}
	return c < 0 || (c == 0 && r.HiIncl)
}

type parsedVersion struct {
	nums []int
	pre  []string
}

// parseVersion reads "1.2.3", "1.2.3-beta.1", "1.2.3+build" (build ignored); ok false for anything else.
func parseVersion(v string) (parsedVersion, bool) {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var p parsedVersion
	core, pre, hasPre := strings.Cut(v, "-")
	if core == "" {
		return p, false
	}
	for _, part := range strings.Split(core, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || part == "" {
			return p, false
		}
		p.nums = append(p.nums, n)
	}
	if hasPre {
		if pre == "" {
			return p, false
		}
		p.pre = strings.Split(pre, ".")
	}
	return p, true
}

// compareVersions orders two versions as semver does (missing numbers are 0; a pre-release before its release).
func compareVersions(a, b string) (int, bool) {
	pa, ok1 := parseVersion(a)
	pb, ok2 := parseVersion(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < max(len(pa.nums), len(pb.nums)); i++ {
		x, y := 0, 0
		if i < len(pa.nums) {
			x = pa.nums[i]
		}
		if i < len(pb.nums) {
			y = pb.nums[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case len(pa.pre) == 0 && len(pb.pre) == 0:
		return 0, true
	case len(pa.pre) == 0:
		return 1, true
	case len(pb.pre) == 0:
		return -1, true
	}
	for i := 0; i < min(len(pa.pre), len(pb.pre)); i++ {
		x, y := pa.pre[i], pb.pre[i]
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				if nx < ny {
					return -1, true
				}
				return 1, true
			}
		case ex == nil:
			return -1, true
		case ey == nil:
			return 1, true
		default:
			if x != y {
				if x < y {
					return -1, true
				}
				return 1, true
			}
		}
	}
	switch {
	case len(pa.pre) < len(pb.pre):
		return -1, true
	case len(pa.pre) > len(pb.pre):
		return 1, true
	}
	return 0, true
}

// LoadMalList reads the list from the data directory; ok false when there is none (or it is not one).
func LoadMalList(dataDir string) (*MalList, bool) {
	path := filepath.Join(dataDir, MaliciousListName)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > malMaxListBytes {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	return parseMalList(f)
}

func parseMalList(r io.Reader) (*MalList, bool) {
	l := &MalList{byKey: map[string][]malEntry{}}
	br := bufio.NewReader(r)
	first := true
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, false
		}
		if line == "" && err == io.EOF {
			break
		}
		line = strings.TrimSuffix(line, "\n")
		if first {
			if line != malListHeader {
				return nil, false
			}
			first = false
			continue
		}
		if strings.HasPrefix(line, "#") {
			if d, ok := strings.CutPrefix(line, "# date "); ok {
				l.Date = strings.TrimSpace(d)
			}
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			continue
		}
		e := malEntry{ID: f[2]}
		for _, tok := range strings.Fields(f[3]) {
			switch {
			case tok == "*":
				e.All = true
			case strings.HasPrefix(tok, "="):
				e.Versions = append(e.Versions, tok[1:])
			case strings.HasPrefix(tok, "[") && (strings.HasSuffix(tok, ")") || strings.HasSuffix(tok, "]")):
				lo, hi, ok := strings.Cut(tok[1:len(tok)-1], ",")
				if ok && lo != "" {
					e.Ranges = append(e.Ranges, malRange{Lo: lo, Hi: hi, HiIncl: strings.HasSuffix(tok, "]")})
				}
			}
		}
		if !e.All && len(e.Versions) == 0 && len(e.Ranges) == 0 {
			continue
		}
		k := f[0] + "\x00" + f[1]
		l.byKey[k] = append(l.byKey[k], e)
		l.Entries++
		if err == io.EOF {
			break
		}
	}
	if first {
		return nil, false
	}
	return l, true
}

// ---------------------------------------------------------------- import

// osvEntry is the part of an OSV record the list keeps.
type osvEntry struct {
	ID        string  `json:"id"`
	Modified  string  `json:"modified"`
	Withdrawn *string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Versions []string `json:"versions"`
		Ranges   []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// MalImport is what an import read and kept.
type MalImport struct {
	Files     int // JSON records read (files, or zip members)
	Bad       int // not OSV, too large, unreadable
	NotMal    int // OSV records whose id does not start with MAL-
	Withdrawn int
	OtherEco  int // affected packages in ecosystems the rule does not compare
	Unusable  int // affected packages with nothing to compare (no versions, ranges it cannot read)
	Kept      int // lines this import gave
	Replaced  int // lines of the list before that this import's records replaced (same MAL ids)
	Total     int // lines in the list now
	Date      string
	// EcoDates: each ecosystem in the list now, with its day.
	EcoDates map[string]string
}

type malLine struct{ eco, name, id, spec string }

// ImportMalicious reads OSV records from path (one .json file holding a record or a list of them, a folder of them
// looked through to any depth, or a .zip of them, as osv.dev exports an ecosystem), keeps the MAL- ones, adds them to
// the list in the data directory (replacing the lines of the same ids; the rest stay) and writes it in one step (a
// temporary file renamed over the old one). Nothing is written when no MAL- entry is found; the old list stays.
func ImportMalicious(path, dataDir string, now time.Time) (MalImport, error) {
	var res MalImport
	latest := map[string]osvEntry{} // by id: the newest modified
	take := func(data []byte) {
		res.Files++
		var many []osvEntry
		t := bytes.TrimLeft(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), " \t\r\n")
		if len(t) > 0 && t[0] == '[' {
			if json.Unmarshal(t, &many) != nil {
				res.Bad++
				return
			}
		} else {
			var one osvEntry
			if json.Unmarshal(t, &one) != nil || one.ID == "" {
				res.Bad++
				return
			}
			many = []osvEntry{one}
		}
		for _, e := range many {
			if !strings.HasPrefix(e.ID, "MAL-") {
				res.NotMal++
				continue
			}
			if old, ok := latest[e.ID]; !ok || e.Modified > old.Modified {
				latest[e.ID] = e
			}
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return res, errors.New("找不到或读不了 " + path)
	}
	switch {
	case st.IsDir():
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // a folder that cannot be read: what else is there still counts
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || !strings.EqualFold(filepath.Ext(p), ".json") {
				return nil
			}
			if res.Files >= malMaxImportFiles {
				return malTooMany()
			}
			if data, ok := readCapped(p, malMaxOSVBytes); ok {
				take(data)
			} else {
				res.Files++
				res.Bad++
			}
			return nil
		})
	case strings.EqualFold(filepath.Ext(path), ".zip"):
		err = importZip(path, take, &res)
	default:
		if data, ok := readCapped(path, malMaxListBytes); ok {
			take(data)
		} else {
			res.Files++
			res.Bad++
		}
	}
	if err != nil {
		return res, err // a list cut short would read as complete: none is written
	}
	ecos := map[string]bool{}
	for _, e := range MalEcosystems {
		ecos[e] = true
	}
	var lines []malLine
	newest := ""
	newestByEco := map[string]string{}
	for _, e := range latest {
		if e.Withdrawn != nil && *e.Withdrawn != "" {
			res.Withdrawn++
			continue
		}
		var keptEcos []string
		for _, a := range e.Affected {
			eco := a.Package.Ecosystem
			if !ecos[eco] {
				res.OtherEco++
				continue
			}
			name := MalName(eco, a.Package.Name)
			spec, ok := osvSpec(eco, a.Versions, a.Ranges)
			if !ok || !malPlain(name) || !malPlain(e.ID) || len(name) > malMaxName || len(e.ID) > malMaxName {
				res.Unusable++
				continue
			}
			// A record listing very many versions goes on several lines, each short.
			for _, chunk := range malChunks(spec) {
				lines = append(lines, malLine{eco, name, e.ID, chunk})
			}
			keptEcos = append(keptEcos, eco)
		}
		if len(keptEcos) > 0 && len(e.Modified) >= 10 {
			day := e.Modified[:10]
			if day > newest {
				newest = day
			}
			for _, eco := range keptEcos {
				if day > newestByEco[eco] {
					newestByEco[eco] = day
				}
			}
		}
	}
	if len(lines) == 0 {
		return res, errors.New("没找到能用的 MAL- 条目")
	}
	if newest == "" {
		newest = now.UTC().Format("2006-01-02")
	}
	res.Kept = len(lines)
	// What this import is about: each ecosystem it kept lines for gets its newest day.
	ecoDates := map[string]string{}
	for _, l := range lines {
		ecoDates[l.eco] = newest
	}
	for eco := range ecoDates {
		if d := newestByEco[eco]; d != "" {
			ecoDates[eco] = d
		}
	}
	// The list before: its lines for ids this import did not read stay, with their ecosystems' days.
	old, oldDates := readMalLines(filepath.Join(dataDir, MaliciousListName))
	for _, l := range old {
		if _, again := latest[l.id]; again {
			res.Replaced++
			continue
		}
		lines = append(lines, l)
		if d := oldDates[l.eco]; d > ecoDates[l.eco] {
			ecoDates[l.eco] = d
		}
	}
	sort.Slice(lines, func(i, j int) bool {
		a, b := lines[i], lines[j]
		if a.eco != b.eco {
			return a.eco < b.eco
		}
		if a.name != b.name {
			return a.name < b.name
		}
		if a.id != b.id {
			return a.id < b.id
		}
		return a.spec < b.spec
	})
	// The list is as current as its least current ecosystem.
	date := ""
	var listEcos []string
	for eco, d := range ecoDates {
		listEcos = append(listEcos, eco)
		if date == "" || d < date {
			date = d
		}
	}
	sort.Strings(listEcos)
	res.Total, res.Date, res.EcoDates = len(lines), date, ecoDates
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\n# date %s\n# entries %d\n", malListHeader, date, len(lines))
	for _, eco := range listEcos {
		fmt.Fprintf(&b, "# date-eco %s %s\n", eco, ecoDates[eco])
	}
	for _, l := range lines {
		b.WriteString(l.eco + "\t" + l.name + "\t" + l.id + "\t" + l.spec + "\n")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return res, err
	}
	return res, WriteAtomic(filepath.Join(dataDir, MaliciousListName), b.Bytes(), 0o600)
}

// readMalLines: the lines of the list at path as written, and each ecosystem's day (a list from before the days were
// kept per ecosystem: its one day for each). None when there is no list, or the file is not one.
func readMalLines(path string) ([]malLine, map[string]string) {
	dates := map[string]string{}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > malMaxListBytes {
		return nil, dates
	}
	data, ok := readCapped(path, malMaxListBytes)
	if !ok || !bytes.HasPrefix(data, []byte(malListHeader+"\n")) {
		return nil, dates
	}
	var lines []malLine
	listDate := ""
	eachLine(data[len(malListHeader)+1:], func(line string) bool {
		if strings.HasPrefix(line, "#") {
			if d, ok := strings.CutPrefix(line, "# date "); ok {
				listDate = strings.TrimSpace(d)
			} else if rest, ok := strings.CutPrefix(line, "# date-eco "); ok {
				if eco, d, ok := strings.Cut(strings.TrimSpace(rest), " "); ok {
					dates[eco] = d
				}
			}
			return true
		}
		f := strings.Split(line, "\t")
		if len(f) == 4 {
			lines = append(lines, malLine{f[0], f[1], f[2], f[3]})
		}
		return true
	})
	for _, l := range lines {
		if dates[l.eco] == "" {
			dates[l.eco] = listDate
		}
	}
	return lines, dates
}

func importZip(path string, take func([]byte), res *MalImport) error {
	z, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer z.Close()
	var total uint64
	for _, f := range z.File {
		if f.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(f.Name), ".json") {
			continue
		}
		if res.Files >= malMaxImportFiles || total > malMaxZipBytes {
			return malTooMany()
		}
		if f.UncompressedSize64 > malMaxOSVBytes {
			res.Files++
			res.Bad++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			res.Files++
			res.Bad++
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, malMaxOSVBytes+1))
		rc.Close()
		total += uint64(len(data))
		if err != nil || len(data) > malMaxOSVBytes {
			res.Files++
			res.Bad++
			continue
		}
		take(data)
	}
	return nil
}

// malTooMany: more records than an import takes. The list is not written: one cut short would look complete.
func malTooMany() error {
	return fmt.Errorf("记录太多（超过 %d 份，或解开后超过 %d GB），只导入一部分的名单看着会像是全的", malMaxImportFiles, malMaxZipBytes>>30)
}

// malChunks splits a long fourth field at spaces into pieces of at most malMaxSpec bytes.
func malChunks(spec string) []string {
	if len(spec) <= malMaxSpec {
		return []string{spec}
	}
	var out []string
	cur := ""
	for _, tok := range strings.Fields(spec) {
		if cur != "" && len(cur)+1+len(tok) > malMaxSpec {
			out = append(out, cur)
			cur = ""
		}
		if cur != "" {
			cur += " "
		}
		cur += tok
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// readCapped reads a regular file of at most limit bytes, not through a link and not waiting on a pipe.
func readCapped(path string, limit int64) ([]byte, bool) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, false
	}
	return data, true
}

// malPlain: written into the list as is: nothing empty, no whitespace or control characters, none of the list's own
// marks.
func malPlain(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == 0x7f || c == ',' || c == '[' || c == ']' || c == '(' || c == ')' {
			return false
		}
	}
	return true
}

// osvSpec turns one affected package's versions and ranges into the list's fourth field. A range that starts at "0"
// with nothing ending it is every version. Only SEMVER and ECOSYSTEM ranges are read (GIT ranges name commits).
func osvSpec(eco string, versions []string, ranges []struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}) (string, bool) {
	var toks []string
	for _, r := range ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}
		lo, open := "", false
		flush := func(hi string, incl bool) {
			if !open {
				return
			}
			open = false
			if lo == "0" && hi == "" {
				toks = append(toks, "*")
				return
			}
			if !malPlain(lo) || (hi != "" && !malPlain(hi)) {
				return
			}
			close := ")"
			if incl {
				close = "]"
			}
			toks = append(toks, "["+lo+","+hi+close)
		}
		for _, ev := range r.Events {
			switch {
			case ev["introduced"] != "":
				flush("", false)
				lo, open = malVersion(eco, ev["introduced"]), true
			case ev["fixed"] != "":
				flush(malVersion(eco, ev["fixed"]), false)
			case ev["last_affected"] != "":
				flush(malVersion(eco, ev["last_affected"]), true)
			case ev["limit"] != "":
				flush(malVersion(eco, ev["limit"]), false)
			}
		}
		flush("", false)
	}
	for _, t := range toks {
		if t == "*" {
			return "*", true
		}
	}
	seen := map[string]bool{}
	for _, v := range versions {
		v = malVersion(eco, v)
		if malPlain(v) && !seen[v] {
			seen[v] = true
			toks = append(toks, "="+v)
		}
	}
	if len(toks) == 0 {
		return "", false
	}
	sort.Strings(toks)
	return strings.Join(toks, " "), true
}

// MalListDate is the list's date from its first lines, without loading it; ok false when there is no list.
func MalListDate(dataDir string) (string, bool) {
	data, ok := aiReadHead(filepath.Join(dataDir, MaliciousListName), 256)
	if !ok {
		return "", false
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 || lines[0] != malListHeader {
		return "", false
	}
	d, ok := strings.CutPrefix(lines[1], "# date ")
	return strings.TrimSpace(d), ok
}
