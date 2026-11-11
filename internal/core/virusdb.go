package core

import (
	"bufio"
	assets "github.com/luokelabs/luoke-scan"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// packedFlag is set when building the copy that ships inside 螺壳 (-ldflags "-X …/internal/core.packedFlag=1"): that
// build takes no development flags and uses only the tools that came with it.
var packedFlag = ""

// Packed says whether this is the build that ships inside 螺壳.
func Packed() bool { return packedFlag == "1" }

// ReleaseTeam is the Team that signs luoke's releases, set when building a release (-ldflags "-X
// …/internal/core.ReleaseTeam=<team>", from the release workflow's settings; not written in the source). Empty in a
// development build: then no signature check against it passes.
var ReleaseTeam = ""

// VirusDB is ClamAV's database in the data directory: <data>/clamav, and the quick one in <data>/clamav-quick.
type VirusDB struct {
	Dir   string
	Tools Tools
}

func NewVirusDB(s *Store, t Tools) VirusDB {
	return VirusDB{Dir: filepath.Join(s.Dir, "clamav"), Tools: t}
}

var dbExtensions = map[string]bool{".cvd": true, ".cld": true, ".cud": true}

// Files are the database files.
func (db VirusDB) Files() []string {
	var out []string
	for _, c := range Children(db.Dir) {
		if dbExtensions[filepath.Ext(c)] {
			out = append(out, c)
		}
	}
	return out
}

// Date is when the newest database file was written.
func (db VirusDB) Date() (time.Time, bool) {
	var best time.Time
	for _, f := range db.Files() {
		if m, ok := Modified(f); ok && m.After(best) {
			best = m
		}
	}
	return best, !best.IsZero()
}

// DailyVersion is the daily database's version as sigtool reads it, or "".
func (db VirusDB) DailyVersion() string {
	sigtool := db.Tools.Path("sigtool")
	if sigtool == "" {
		return ""
	}
	for _, f := range db.Files() {
		if strings.TrimSuffix(filepath.Base(f), filepath.Ext(f)) == "daily" {
			return dbVersion(f, sigtool)
		}
	}
	return ""
}

func dbVersion(file, sigtool string) string {
	certs, done := ClamAVCerts()
	defer done()
	r := Run(sigtool, append([]string{"--info=" + file}, certs...), RunOpts{Env: CertsEnv(certs, nil), Timeout: 60 * time.Second})
	if r.Status != 0 {
		return ""
	}
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return ""
}

// Outcome of an update.
type Outcome struct {
	Kind    string // "updated", "upToDate", "notDue", "failed"
	Version string
	Next    time.Time
	Why     string
}

// settingsFile is freshclam's settings (packaging/freshclam.conf, carried inside this program and signed with it),
// written for this one run to a folder of its own (made, removed by the caller): never to the data directory, where
// they could be changed.
func settingsFile() (file, made string, ok bool) {
	settings, err := assets.FS.ReadFile("packaging/freshclam.conf")
	if err != nil {
		return "", "", false
	}
	dir, err := os.MkdirTemp("", "luoke-scan-freshclam.") // 700
	if err != nil {
		return "", "", false
	}
	f := filepath.Join(dir, "freshclam.conf")
	if os.WriteFile(f, settings, 0o600) != nil {
		os.RemoveAll(dir)
		return "", "", false
	}
	return f, dir, true
}

// Clone copies a file or a folder as an APFS clone (no space taken until either changes), else byte for byte.
func Clone(src, dst string) error {
	if unix.Clonefileat(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, 0) == nil {
		return nil
	}
	return copyTree(src, dst)
}

func copyTree(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		if err := os.MkdirAll(dst, st.Mode().Perm()); err != nil {
			return err
		}
		for _, c := range Children(src) {
			if err := copyTree(c, filepath.Join(dst, filepath.Base(c))); err != nil {
				return err
			}
		}
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, st.ModTime(), st.ModTime())
}

func dbKeys(dir string) map[string]bool {
	out := map[string]bool{}
	for _, c := range Children(dir) {
		if dbExtensions[filepath.Ext(c)] {
			m, _ := Modified(c)
			out[filepath.Base(c)+"@"+strconv.FormatFloat(float64(m.UnixNano())/1e9, 'f', -1, 64)] = true
		}
	}
	return out
}

// Update runs freshclam into a copy of the database, checks every file of what came with sigtool, and only then puts
// it in place; on any failure the old database stays. At most once a day unless force.
func (db VirusDB) Update(s *Store, now time.Time, force bool, timeout time.Duration) Outcome {
	if !force {
		if last, ok := s.Get("clamav.last_attempt"); ok {
			if f, err := strconv.ParseFloat(last, 64); err == nil {
				next := time.Unix(0, int64((f+86400)*1e9))
				if now.Before(next) {
					return Outcome{Kind: "notDue", Next: next}
				}
			}
		}
	}
	s.Set("clamav.last_attempt", strconv.FormatFloat(float64(now.UnixNano())/1e9, 'f', -1, 64))
	fail := func(why string) Outcome {
		s.Set("clamav.last_error", why)
		return Outcome{Kind: "failed", Why: why}
	}
	freshclam := db.Tools.Path("freshclam")
	if freshclam == "" {
		return fail("没有 freshclam")
	}
	data := filepath.Dir(db.Dir)
	staging, previous := filepath.Join(data, "clamav.staging"), filepath.Join(data, "clamav.previous")
	os.RemoveAll(staging)
	os.RemoveAll(previous)
	var err error
	if Exists(db.Dir) {
		err = Clone(db.Dir, staging)
	} else {
		err = os.MkdirAll(staging, 0o700)
	}
	if err != nil {
		return fail("准备临时目录失败：" + err.Error())
	}
	defer os.RemoveAll(staging)
	os.Remove(filepath.Join(data, "freshclam.conf")) // versions before 0.1.4 wrote it here, where it could be changed
	conf, made, ok := settingsFile()
	if !ok {
		return fail("写 freshclam.conf 失败")
	}
	defer os.RemoveAll(made)
	certs, done := ClamAVCerts()
	defer done()
	before := dbKeys(staging)
	r := Run(freshclam, append([]string{"--config-file=" + conf, "--datadir=" + staging, "--stdout"}, certs...),
		RunOpts{Env: CertsEnv(certs, nil), Timeout: timeout})
	// freshclam's state (cool-down after rate limiting) is kept whatever happens next.
	if state := filepath.Join(staging, "freshclam.dat"); Exists(state) {
		os.MkdirAll(db.Dir, 0o700)
		live := filepath.Join(db.Dir, "freshclam.dat")
		os.Remove(live)
		Clone(state, live)
	}
	if r.TimedOut {
		return fail("freshclam 超时")
	}
	text := strings.ToLower(r.Stdout)
	if strings.Contains(text, "cool-down") || strings.Contains(text, "error code 429") {
		return fail("上游限流，等冷却期过了再试")
	}
	if r.Status != 0 && r.Status != 1 {
		return fail("freshclam 失败（" + strconv.Itoa(r.Status) + "）")
	}
	var after []string
	for _, c := range Children(staging) {
		if dbExtensions[filepath.Ext(c)] {
			after = append(after, c)
		}
	}
	if len(after) == 0 {
		return fail("freshclam 结束了，但没有病毒库文件")
	}
	afterKeys := dbKeys(staging)
	if sameKeys(before, afterKeys) {
		s.Set("clamav.last_error", "")
		db.MakeQuick()
		return Outcome{Kind: "upToDate"}
	}
	sigtool := db.Tools.Path("sigtool")
	if sigtool == "" {
		return fail("没有 sigtool，无法校验新库，保留旧库")
	}
	for _, f := range after {
		if dbVersion(f, sigtool) == "" {
			return fail(filepath.Base(f) + " 校验没通过，保留旧库")
		}
	}
	if Exists(db.Dir) {
		if err := os.Rename(db.Dir, previous); err != nil {
			return fail("换库失败：" + err.Error())
		}
	}
	if err := os.Rename(staging, db.Dir); err != nil {
		if !Exists(db.Dir) && Exists(previous) {
			os.Rename(previous, db.Dir)
		}
		return fail("换库失败：" + err.Error())
	}
	os.RemoveAll(previous)
	version := db.DailyVersion()
	s.Set("clamav.version", version)
	s.Set("clamav.updated_at", strconv.FormatFloat(float64(now.UnixNano())/1e9, 'f', -1, 64))
	s.Set("clamav.last_error", "")
	db.MakeQuick()
	return Outcome{Kind: "updated", Version: version}
}

func sameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// QuickDir is the quick database: the full one without the signatures only for Windows programs.
func (db VirusDB) QuickDir() string { return filepath.Join(filepath.Dir(db.Dir), "clamav-quick") }

// QuickDirs are its parts, one folder per database file.
func (db VirusDB) QuickDirs() []string {
	files := db.Files()
	sort.Slice(files, func(i, j int) bool { return filepath.Base(files[i]) < filepath.Base(files[j]) })
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, filepath.Join(db.QuickDir(), filepath.Base(f)))
	}
	return out
}

const quickMark = "source.txt"

func fileMark(f string) string {
	var st syscall.Stat_t
	if syscall.Lstat(f, &st) != nil {
		return ""
	}
	return strconv.FormatInt(st.Size, 10) + " " + strconv.FormatInt(st.Mtimespec.Sec, 10) + "." + strconv.FormatInt(st.Mtimespec.Nsec, 10)
}

func (db VirusDB) partReady(f string) bool {
	m := fileMark(f)
	got, err := os.ReadFile(filepath.Join(db.QuickDir(), filepath.Base(f), quickMark))
	return m != "" && err == nil && string(got) == m
}

// QuickReady says whether the quick database matches the full one.
func (db VirusDB) QuickReady() bool {
	files := db.Files()
	if len(files) == 0 {
		return false
	}
	for _, f := range files {
		if !db.partReady(f) {
			return false
		}
	}
	return true
}

// MakeQuick makes (or remakes) the quick database from the full one; whether it is ready.
func (db VirusDB) MakeQuick() bool {
	files := db.Files()
	names := map[string]bool{}
	for _, f := range files {
		names[filepath.Base(f)] = true
	}
	leftovers := func() []string {
		var out []string
		for _, c := range Children(db.QuickDir()) {
			if !names[filepath.Base(c)] {
				out = append(out, c)
			}
		}
		return out
	}
	if db.QuickReady() && len(leftovers()) == 0 {
		return true
	}
	sigtool := db.Tools.Path("sigtool")
	if len(files) == 0 || sigtool == "" {
		return false
	}
	lock := TakeLock(filepath.Dir(db.Dir), "clamav-quick.lock", 120*time.Second)
	if lock == nil {
		return false
	}
	defer lock.Release()
	os.MkdirAll(db.QuickDir(), 0o700)
	for _, old := range leftovers() {
		os.RemoveAll(old)
	}
	for _, f := range files {
		if db.partReady(f) {
			continue
		}
		mark := fileMark(f)
		part := filepath.Join(db.QuickDir(), filepath.Base(f))
		staging := part + ".staging"
		unpacked := filepath.Join(staging, "unpacked")
		os.RemoveAll(staging)
		if os.MkdirAll(unpacked, 0o700) != nil {
			return false
		}
		ok := func() bool {
			certs, done := ClamAVCerts()
			defer done()
			if Run(sigtool, append([]string{"--unpack=" + f}, certs...), RunOpts{Dir: unpacked, Env: CertsEnv(certs, nil), Timeout: 600 * time.Second}).Status != 0 {
				return false
			}
			for _, piece := range Children(unpacked) {
				to := filepath.Join(staging, filepath.Base(piece))
				switch kind, field := quickPart(strings.TrimPrefix(filepath.Ext(piece), ".")); kind {
				case "drop":
				case "whole":
					if os.Rename(piece, to) != nil {
						return false
					}
				default:
					if !filterWindows(piece, to, field) {
						return false
					}
				}
			}
			os.RemoveAll(unpacked)
			if fileMark(f) != mark || WriteAtomic(filepath.Join(staging, quickMark), []byte(mark), 0o600) != nil {
				return false
			}
			os.RemoveAll(part)
			return os.Rename(staging, part) == nil
		}()
		os.RemoveAll(staging)
		if !ok {
			return false
		}
	}
	return db.QuickReady()
}

func quickPart(ext string) (string, int) {
	switch strings.ToLower(ext) {
	case "ldb", "ldu", "ndb", "ndu":
		return "withoutWindows", 0
	case "hdb", "hdu", "hsb", "hsu":
		return "withoutWindows", 2
	case "mdb", "mdu", "msb", "msu", "imp", "info", "cdiff", "sign", "":
		return "drop", 0
	}
	return "whole", 0
}

// filterWindows copies from to to line by line without the signatures for Windows programs (name in field field,
// fields separated by : or ;), streaming.
func filterWindows(from, to string, field int) bool {
	in, err := os.Open(from)
	if err != nil {
		return false
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return false
	}
	w := bufio.NewWriterSize(out, 1<<20)
	r := bufio.NewReaderSize(in, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && !windowsName(line, field) {
			if _, werr := w.Write(line); werr != nil {
				out.Close()
				return false
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			out.Close()
			return false
		}
	}
	if w.Flush() != nil {
		out.Close()
		return false
	}
	return out.Close() == nil
}

func windowsName(line []byte, field int) bool {
	i, f := 0, 0
	for f < field {
		for i < len(line) && line[i] != ':' && line[i] != ';' {
			i++
		}
		if i >= len(line) {
			return false
		}
		i++
		f++
	}
	rest := line[i:]
	return strings.HasPrefix(string(rest), "Win.") || strings.HasPrefix(string(rest), "PUA.Win.")
}
