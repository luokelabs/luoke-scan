package core

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func osvRecord(id, modified, eco, name string, versions []string, ranges ...[]map[string]string) map[string]any {
	var rs []any
	for _, ev := range ranges {
		rs = append(rs, map[string]any{"type": "SEMVER", "events": ev})
	}
	aff := map[string]any{"package": map[string]any{"ecosystem": eco, "name": name}}
	if versions != nil {
		aff["versions"] = versions
	}
	if rs != nil {
		aff["ranges"] = rs
	}
	return map[string]any{"schema_version": "1.5.0", "id": id, "modified": modified, "published": modified,
		"summary": "Malicious code in " + name + " (" + eco + ")", "affected": []any{aff},
		"database_specific": map[string]any{"malicious-packages-origins": []any{}}}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMalName(t *testing.T) {
	for _, c := range []struct{ eco, in, want string }{
		{"PyPI", "Typing_Extensions", "typing-extensions"},
		{"PyPI", "zope.interface", "zope-interface"},
		{"PyPI", "a-_.b", "a-b"},
		{"crates.io", "Serde_JSON", "serde-json"},
		{"npm", "@Scope/Pkg_x", "@Scope/Pkg_x"},
	} {
		if got := MalName(c.eco, c.in); got != c.want {
			t.Errorf("%s %q: %q, want %q", c.eco, c.in, got, c.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.2.3", "1.2.3", 0, true},
		{"1.2", "1.2.0", 0, true},
		{"1.10.0", "1.9.9", 1, true},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1, true},
		{"1.0.0-alpha", "1.0.0", -1, true},
		{"1.0.0+build", "1.0.0", 0, true},
		{"0", "0.0.1", -1, true},
		{"1.0rc1", "1.0", 0, false},
		{"1.0.post1", "1.0", 0, false},
	} {
		got, ok := compareVersions(c.a, c.b)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s vs %s: %d %v, want %d %v", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

func TestImportAndMatch(t *testing.T) {
	src := t.TempDir()
	data := t.TempDir()
	// An OpenSSF-style tree: osv/malicious/<eco>/<name>/MAL-….json.
	writeJSON(t, filepath.Join(src, "osv/malicious/npm/evil-all/MAL-2025-1.json"),
		osvRecord("MAL-2025-1", "2025-01-02T03:04:05Z", "npm", "evil-all", nil, []map[string]string{{"introduced": "0"}}))
	writeJSON(t, filepath.Join(src, "osv/malicious/npm/@scope/evil/MAL-2025-2.json"),
		osvRecord("MAL-2025-2", "2025-02-01T00:00:00Z", "npm", "@scope/evil", []string{"1.0.1", "1.0.2"}))
	writeJSON(t, filepath.Join(src, "osv/malicious/pypi/Evil_Pkg/MAL-2025-3.json"),
		osvRecord("MAL-2025-3", "2025-03-01T00:00:00Z", "PyPI", "Evil_Pkg", []string{"0.1.0"}))
	writeJSON(t, filepath.Join(src, "osv/malicious/crates.io/bad_crate/MAL-2025-4.json"),
		osvRecord("MAL-2025-4", "2025-03-05T00:00:00Z", "crates.io", "bad_crate", nil,
			[]map[string]string{{"introduced": "1.0.0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"last_affected": "2.0.3"}}))
	// Left out: not MAL-, withdrawn, another ecosystem, nothing to compare, not OSV.
	writeJSON(t, filepath.Join(src, "osv/GHSA-xxxx.json"), osvRecord("GHSA-xxxx", "2026-01-01T00:00:00Z", "npm", "lodash", []string{"4.17.20"}))
	w := osvRecord("MAL-2025-5", "2026-02-01T00:00:00Z", "npm", "withdrawn-pkg", []string{"1.0.0"})
	w["withdrawn"] = "2026-02-02T00:00:00Z"
	writeJSON(t, filepath.Join(src, "osv/malicious/npm/withdrawn-pkg/MAL-2025-5.json"), w)
	writeJSON(t, filepath.Join(src, "osv/malicious/rubygems/x/MAL-2025-6.json"), osvRecord("MAL-2025-6", "2026-03-01T00:00:00Z", "RubyGems", "x", []string{"1.0"}))
	writeJSON(t, filepath.Join(src, "osv/malicious/npm/empty/MAL-2025-7.json"), osvRecord("MAL-2025-7", "2025-01-01T00:00:00Z", "npm", "empty", nil))
	os.WriteFile(filepath.Join(src, "osv/broken.json"), []byte("{"), 0o644)
	os.WriteFile(filepath.Join(src, "README.md"), []byte("not read"), 0o644)
	// The same id twice: the newer one is kept.
	writeJSON(t, filepath.Join(src, "osv/older/MAL-2025-2.json"),
		osvRecord("MAL-2025-2", "2024-12-01T00:00:00Z", "npm", "@scope/evil", []string{"9.9.9"}))

	res, err := ImportMalicious(src, data, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	// The list's day is its least current ecosystem's: npm's newest entry is from 2025-02-01.
	want := MalImport{Files: 10, Bad: 1, NotMal: 1, Withdrawn: 1, OtherEco: 1, Unusable: 1, Kept: 4, Total: 4, Date: "2025-02-01",
		EcoDates: map[string]string{"npm": "2025-02-01", "PyPI": "2025-03-01", "crates.io": "2025-03-05"}}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("import %+v\nwant   %+v", res, want)
	}
	raw, _ := os.ReadFile(filepath.Join(data, MaliciousListName))
	wantFile := malListHeader + "\n# date 2025-02-01\n# entries 4\n" +
		"# date-eco PyPI 2025-03-01\n# date-eco crates.io 2025-03-05\n# date-eco npm 2025-02-01\n" +
		"PyPI\tevil-pkg\tMAL-2025-3\t=0.1.0\n" +
		"crates.io\tbad-crate\tMAL-2025-4\t[1.0.0,1.2.0) [2.0.0,2.0.3]\n" +
		"npm\t@scope/evil\tMAL-2025-2\t=1.0.1 =1.0.2\n" +
		"npm\tevil-all\tMAL-2025-1\t*\n"
	if string(raw) != wantFile {
		t.Fatalf("list:\n%s\nwant:\n%s", raw, wantFile)
	}
	if st, _ := os.Stat(filepath.Join(data, MaliciousListName)); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if d, ok := MalListDate(data); !ok || d != "2025-02-01" {
		t.Errorf("date %q %v", d, ok)
	}

	l, ok := LoadMalList(data)
	if !ok || l.Entries != 4 || l.Date != "2025-02-01" {
		t.Fatalf("load %v %+v", ok, l)
	}
	for _, c := range []struct {
		eco, name, version string
		want               []string
	}{
		{"npm", "evil-all", "0.0.1", []string{"MAL-2025-1"}},     // every version
		{"npm", "evil-all", "", []string{"MAL-2025-1"}},          // even without one
		{"npm", "@scope/evil", "1.0.2", []string{"MAL-2025-2"}},  // scoped, exact
		{"npm", "@scope/evil", "v1.0.1", []string{"MAL-2025-2"}}, // a leading v
		{"npm", "@scope/evil", "1.0.3", nil},
		{"npm", "@scope/evil", "9.9.9", nil}, // only the older record had it
		{"npm", "evil", "1.0.1", nil},        // the unscoped name is someone else's
		{"npm", "Evil-All", "1.0.0", nil},    // npm names as written
		{"PyPI", "evil_pkg", "0.1.0", []string{"MAL-2025-3"}},
		{"PyPI", "EVIL.PKG", "0.1.0", []string{"MAL-2025-3"}},
		{"PyPI", "evil-pkg", "0.1.1", nil},
		{"crates.io", "bad_crate", "1.1.9", []string{"MAL-2025-4"}},
		{"crates.io", "bad-crate", "1.2.0", nil}, // fixed
		{"crates.io", "bad-crate", "0.9.0", nil},
		{"crates.io", "bad-crate", "2.0.3", []string{"MAL-2025-4"}}, // last affected
		{"crates.io", "bad-crate", "2.0.4", nil},
		{"crates.io", "bad-crate", "1.1.x", nil}, // cannot be compared: not a finding
		{"npm", "withdrawn-pkg", "1.0.0", nil},
		{"npm", "lodash", "4.17.20", nil},
	} {
		got := l.Match(c.eco, c.name, c.version)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s@%s: %v, want %v", c.eco, c.name, c.version, got, c.want)
		}
	}
}

func TestImportFileZipAndNothing(t *testing.T) {
	src := t.TempDir()
	data := t.TempDir()
	// A file holding a list of records, with a byte order mark.
	recs := []any{osvRecord("MAL-2026-10", "2026-05-01T00:00:00Z", "npm", "one", []string{"1.0.0"}),
		osvRecord("MAL-2026-11", "2026-05-02T00:00:00Z", "PyPI", "two", nil, []map[string]string{{"introduced": "0"}})}
	b, _ := json.Marshal(recs)
	os.WriteFile(filepath.Join(src, "list.json"), append([]byte("\xef\xbb\xbf"), b...), 0o644)
	res, err := ImportMalicious(filepath.Join(src, "list.json"), data, time.Now())
	if err != nil || res.Kept != 2 || res.Date != "2026-05-01" {
		t.Fatalf("file: %+v %v", res, err)
	}
	// A zip, as osv.dev exports an ecosystem: the MAL- ones only.
	zp := filepath.Join(src, "all.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	for _, r := range []map[string]any{osvRecord("MAL-2026-20", "2026-06-01T00:00:00Z", "npm", "three", []string{"3.0.0"}),
		osvRecord("GHSA-abcd", "2026-07-01T00:00:00Z", "npm", "four", []string{"1.0.0"})} {
		w, _ := zw.Create(r["id"].(string) + ".json")
		json.NewEncoder(w).Encode(r)
	}
	zw.Close()
	f.Close()
	res, err = ImportMalicious(zp, data, time.Now())
	// Added to the list: npm's day moves on, PyPI's stays (and is now the list's).
	if err != nil || res.Kept != 1 || res.NotMal != 1 || res.Total != 3 || res.Date != "2026-05-02" {
		t.Fatalf("zip: %+v %v", res, err)
	}
	l, _ := LoadMalList(data)
	if l.Match("npm", "one", "1.0.0") == nil || l.Match("npm", "three", "3.0.0") == nil || l.Match("PyPI", "two", "1") == nil {
		t.Fatal("the zip's import must add to the list")
	}
	// Nothing usable: an error, and the list stays.
	empty := t.TempDir()
	writeJSON(t, filepath.Join(empty, "GHSA.json"), osvRecord("GHSA-x", "2026-01-01T00:00:00Z", "npm", "x", []string{"1"}))
	if _, err := ImportMalicious(empty, data, time.Now()); err == nil {
		t.Fatal("no MAL- entries: want an error")
	}
	if l, ok := LoadMalList(data); !ok || l.Match("npm", "three", "3.0.0") == nil {
		t.Fatal("the old list must stay")
	}
	if _, err := ImportMalicious(filepath.Join(src, "missing"), data, time.Now()); err == nil {
		t.Fatal("missing path: want an error")
	}
}

func TestMalListRejects(t *testing.T) {
	if _, ok := parseMalList(strings.NewReader("npm\tx\tMAL-1\t*\n")); ok {
		t.Fatal("no header: not a list")
	}
	l, ok := parseMalList(strings.NewReader(malListHeader + "\n# date 2026-01-01\nnpm\tx\tMAL-1\t*\nbroken line\nnpm\ty\tMAL-2\t\n"))
	if !ok || l.Entries != 1 {
		t.Fatalf("%v %+v", ok, l)
	}
	if _, ok := LoadMalList(t.TempDir()); ok {
		t.Fatal("no file: no list")
	}
	var nilList *MalList
	if nilList.Match("npm", "x", "1") != nil {
		t.Fatal("nil list matches nothing")
	}
}

// More records than an import takes: an error, and no list that looks complete (the old one stays).
func TestImportTooMany(t *testing.T) {
	src, data := t.TempDir(), t.TempDir()
	for i, name := range []string{"a", "b", "c"} {
		writeJSON(t, filepath.Join(src, name+".json"), osvRecord("MAL-2026-"+strconv.Itoa(i), "2026-01-01T00:00:00Z", "npm", name, []string{"1.0.0"}))
	}
	old := malMaxImportFiles
	malMaxImportFiles = 2
	defer func() { malMaxImportFiles = old }()
	if _, err := ImportMalicious(src, data, time.Now()); err == nil || !strings.Contains(err.Error(), "记录太多") {
		t.Fatalf("folder: %v", err)
	}
	if _, ok := LoadMalList(data); ok {
		t.Fatal("a cut-short list was written")
	}
	zp := filepath.Join(t.TempDir(), "all.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	for i, name := range []string{"a", "b", "c"} {
		w, _ := zw.Create(name + ".json")
		json.NewEncoder(w).Encode(osvRecord("MAL-2026-"+strconv.Itoa(i), "2026-01-01T00:00:00Z", "npm", name, []string{"1.0.0"}))
	}
	zw.Close()
	f.Close()
	if _, err := ImportMalicious(zp, data, time.Now()); err == nil {
		t.Fatal("zip: want an error")
	}
	if _, ok := LoadMalList(data); ok {
		t.Fatal("a cut-short list was written from the zip")
	}
}

// A record listing very many versions: split into short lines at import, all of them still matched; a long line in a
// list (written by hand, or an older import) does not make the whole list unreadable.
func TestImportLongRecord(t *testing.T) {
	src, data := t.TempDir(), t.TempDir()
	var versions []string
	for i := 0; i < 20000; i++ {
		versions = append(versions, "1.0."+strconv.Itoa(i))
	}
	writeJSON(t, filepath.Join(src, "many.json"), osvRecord("MAL-2026-1", "2026-01-01T00:00:00Z", "npm", "many", versions))
	res, err := ImportMalicious(src, data, time.Now())
	if err != nil || res.Kept < 2 {
		t.Fatalf("%+v %v", res, err)
	}
	raw, _ := os.ReadFile(filepath.Join(data, MaliciousListName))
	for _, line := range strings.Split(string(raw), "\n") {
		if len(line) > malMaxSpec+100 {
			t.Fatalf("a line of %d bytes", len(line))
		}
	}
	l, ok := LoadMalList(data)
	if !ok || l.Match("npm", "many", "1.0.0") == nil || l.Match("npm", "many", "1.0.19999") == nil || l.Match("npm", "many", "1.0.20000") != nil {
		t.Fatal("split record not matched")
	}
	long := malListHeader + "\n# date 2026-01-01\nnpm\tx\tMAL-1\t" + strings.Repeat("=1.0.0 ", 300000) + "\nnpm\ty\tMAL-2\t*\n"
	l, ok = parseMalList(strings.NewReader(long))
	if !ok || l.Match("npm", "x", "1.0.0") == nil || l.Match("npm", "y", "9") == nil {
		t.Fatal("a long line made the list unreadable")
	}
}

// osv.dev exports one ecosystem at a time: importing npm's and then PyPI's keeps both. Records read again replace the
// lines of their ids (a withdrawn one goes), every other line stays, and each ecosystem keeps its own day.
func TestImportMerges(t *testing.T) {
	npm, pypi, data := t.TempDir(), t.TempDir(), t.TempDir()
	writeJSON(t, filepath.Join(npm, "MAL-2026-1.json"), osvRecord("MAL-2026-1", "2026-10-01T00:00:00Z", "npm", "evil-npm", []string{"1.0.0"}))
	writeJSON(t, filepath.Join(npm, "MAL-2026-2.json"), osvRecord("MAL-2026-2", "2026-10-02T00:00:00Z", "npm", "gone-later", []string{"2.0.0"}))
	writeJSON(t, filepath.Join(pypi, "MAL-2026-3.json"), osvRecord("MAL-2026-3", "2026-09-15T00:00:00Z", "PyPI", "evil-py", []string{"0.1.0"}))
	if _, err := ImportMalicious(npm, data, time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := ImportMalicious(pypi, data, time.Now())
	if err != nil || res.Kept != 1 || res.Replaced != 0 || res.Total != 3 || res.Date != "2026-09-15" ||
		!reflect.DeepEqual(res.EcoDates, map[string]string{"npm": "2026-10-02", "PyPI": "2026-09-15"}) {
		t.Fatalf("PyPI after npm: %+v %v", res, err)
	}
	l, ok := LoadMalList(data)
	if !ok || l.Entries != 3 || l.Match("npm", "evil-npm", "1.0.0") == nil || l.Match("PyPI", "evil-py", "0.1.0") == nil {
		t.Fatalf("both ecosystems must stay: %v %+v", ok, l)
	}
	// npm again, newer: one record changed, one withdrawn. Its lines are replaced; PyPI's stay.
	writeJSON(t, filepath.Join(npm, "MAL-2026-1.json"), osvRecord("MAL-2026-1", "2026-11-01T00:00:00Z", "npm", "evil-npm", []string{"1.0.0", "1.0.1"}))
	w := osvRecord("MAL-2026-2", "2026-11-02T00:00:00Z", "npm", "gone-later", []string{"2.0.0"})
	w["withdrawn"] = "2026-11-02T00:00:00Z"
	writeJSON(t, filepath.Join(npm, "MAL-2026-2.json"), w)
	res, err = ImportMalicious(npm, data, time.Now())
	if err != nil || res.Kept != 1 || res.Replaced != 2 || res.Total != 2 || res.Date != "2026-09-15" || res.EcoDates["npm"] != "2026-11-01" {
		t.Fatalf("npm again: %+v %v", res, err)
	}
	l, _ = LoadMalList(data)
	if l.Match("npm", "evil-npm", "1.0.1") == nil || l.Match("npm", "gone-later", "2.0.0") != nil || l.Match("PyPI", "evil-py", "0.1.0") == nil {
		t.Fatal("re-import: replaced by id, withdrawn removed, others kept")
	}
	// A list from before the days were kept per ecosystem: its one day for each.
	os.WriteFile(filepath.Join(data, MaliciousListName), []byte(malListHeader+"\n# date 2026-08-01\n# entries 1\ncrates.io\told-crate\tMAL-2026-9\t*\n"), 0o600)
	res, err = ImportMalicious(pypi, data, time.Now())
	if err != nil || res.Total != 2 || res.EcoDates["crates.io"] != "2026-08-01" || res.Date != "2026-08-01" {
		t.Fatalf("old list: %+v %v", res, err)
	}
}
