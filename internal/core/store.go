package core

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Store is the tool's own data in its data directory (~/.luoke-scan inside 螺壳): facts about this Mac kept between
// rounds, and the last report. No database: each table is a snapshot (<name>.json) and a log of changes after it
// (<name>.log, one line per batch, with a CRC). Writers append under a shared lock; folding the log into a new snapshot
// takes the exclusive one. A table of another version, or one that cannot be read, is dropped and rebuilt: everything
// here is a cache the next round makes again.
type Store struct{ Dir string }

// tmExclusion is the value macOS writes to keep a folder out of Time Machine (a binary plist "com.apple.backupd").
var tmExclusion, _ = hex.DecodeString("62706c69737430305f1011636f6d2e6170706c652e6261636b75706408000000000000010100000000000000010000000000000000000000000000001c")

// OpenStore makes the data directory (700) and keeps it out of Time Machine.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	os.Chmod(dir, 0o700)
	setXattr(dir, "com.apple.metadata:com_apple_backup_excludeItem", tmExclusion)
	// The Swift version's database: not read, not migrated (11-05).
	for _, n := range []string{"scan.db", "scan.db-wal", "scan.db-shm"} {
		os.Remove(filepath.Join(dir, n))
	}
	return &Store{Dir: dir}, nil
}

func setXattr(path, name string, value []byte) {
	if len(value) > 0 {
		unix.Setxattr(path, name, value, 0)
	}
}

// Table is one kind of row, keyed by a string.
type Table[V any] struct {
	s       *Store
	name    string
	version int
}

// NewTable names a table and the version of its rows' shape.
func NewTable[V any](s *Store, name string, version int) Table[V] {
	return Table[V]{s: s, name: name, version: version}
}

type snapshot[V any] struct {
	Version int          `json:"version"`
	Rows    map[string]V `json:"rows"`
}

type change[V any] struct {
	Version int          `json:"version"`
	Set     map[string]V `json:"set,omitempty"`
	Del     []string     `json:"del,omitempty"`
	Reset   bool         `json:"reset,omitempty"`
}

func (t Table[V]) path(ext string) string { return filepath.Join(t.s.Dir, t.name+ext) }

func (t Table[V]) lock(how int) (*os.File, error) {
	f, err := os.OpenFile(t.path(".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlock(f *os.File) {
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

// Load reads the snapshot and replays the log. A line that is cut short or fails its CRC is skipped, and so is the
// rest of the log after it (what came later may depend on it); rows of another version are dropped.
func (t Table[V]) Load() map[string]V {
	f, err := t.lock(syscall.LOCK_SH)
	if err != nil {
		return map[string]V{}
	}
	defer unlock(f)
	return t.read()
}

func (t Table[V]) read() map[string]V {
	rows := map[string]V{}
	if data, err := os.ReadFile(t.path(".json")); err == nil {
		var s snapshot[V]
		if json.Unmarshal(data, &s) == nil && s.Version == t.version && s.Rows != nil {
			rows = s.Rows
		}
	}
	lf, err := os.Open(t.path(".log"))
	if err != nil {
		return rows
	}
	defer lf.Close()
	sc := bufio.NewScanner(lf)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		sp := bytes.IndexByte(line, ' ')
		if sp != 8 || fmt.Sprintf("%08x", crc32.ChecksumIEEE(line[sp+1:])) != string(line[:sp]) {
			break
		}
		var c change[V]
		if json.Unmarshal(line[sp+1:], &c) != nil || c.Version != t.version {
			break
		}
		if c.Reset {
			rows = map[string]V{}
		}
		for _, k := range c.Del {
			delete(rows, k)
		}
		for k, v := range c.Set {
			rows[k] = v
		}
	}
	return rows
}

// maxLog is how big a log grows before it is folded into the snapshot.
const maxLog = 1 << 20

// Apply records one batch: rows set (replaced whole) and keys removed. reset: everything before goes first.
func (t Table[V]) Apply(set map[string]V, del []string, reset bool) error {
	if len(set) == 0 && len(del) == 0 && !reset {
		return nil
	}
	payload, err := json.Marshal(change[V]{Version: t.version, Set: set, Del: del, Reset: reset})
	if err != nil {
		return err
	}
	line := append([]byte(fmt.Sprintf("%08x ", crc32.ChecksumIEEE(payload))), payload...)
	line = append(line, '\n')
	f, err := t.lock(syscall.LOCK_SH)
	if err != nil {
		return err
	}
	lf, err := os.OpenFile(t.path(".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		unlock(f)
		return err
	}
	_, err = lf.Write(line) // one write with O_APPEND: lines of other writers do not interleave with it
	st, _ := lf.Stat()
	lf.Close()
	unlock(f)
	if err == nil && st != nil && st.Size() > maxLog {
		t.Compact()
	}
	return err
}

// Replace makes rows the whole table.
func (t Table[V]) Replace(rows map[string]V) error {
	f, err := t.lock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock(f)
	return t.write(rows)
}

// Compact folds the log into a new snapshot.
func (t Table[V]) Compact() error {
	f, err := t.lock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock(f)
	return t.write(t.read())
}

func (t Table[V]) write(rows map[string]V) error {
	data, err := json.Marshal(snapshot[V]{Version: t.version, Rows: rows})
	if err != nil {
		return err
	}
	if err := WriteAtomic(t.path(".json"), data, 0o600); err != nil {
		return err
	}
	if err := os.Remove(t.path(".log")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// WriteAtomic writes a file whole or not at all: a temporary file in the same folder, then renamed over it.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	tmp.Chmod(mode)
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// meta is small facts by key: the virus database's state, watermarks, kept answers.
func (s *Store) meta() Table[string] { return NewTable[string](s, "meta", 1) }

// Get is a meta value; ok false when there is none.
func (s *Store) Get(key string) (string, bool) {
	v, ok := s.meta().Load()[key]
	return v, ok
}

// Set records a meta value.
func (s *Store) Set(key, value string) error {
	return s.meta().Apply(map[string]string{key: value}, nil, false)
}

// LastReportPath is where the last round's report is.
func (s *Store) LastReportPath() string { return filepath.Join(s.Dir, "last-report.json") }

// SaveReport keeps a round's report (600).
func (s *Store) SaveReport(r Report) error {
	data, err := EncodeJSON(r)
	if err != nil {
		return err
	}
	return WriteAtomic(s.LastReportPath(), data, 0o600)
}

// LastReport is the last round's report, or nil.
func (s *Store) LastReport() *Report {
	data, err := os.ReadFile(s.LastReportPath())
	if err != nil {
		return nil
	}
	var r Report
	if json.Unmarshal(data, &r) != nil {
		return nil
	}
	return &r
}

// RoundLock is a lock file in the data directory, held by one process at a time (flock).
type RoundLock struct{ f *os.File }

// TakeLock takes the named lock, waiting up to wait for whoever holds it; nil when still held then.
func TakeLock(dataDir, name string, wait time.Duration) *RoundLock {
	until := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(filepath.Join(dataDir, name), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil
		}
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			return &RoundLock{f}
		}
		f.Close()
		if !time.Now().Before(until) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Release lets the lock go.
func (l *RoundLock) Release() {
	if l != nil && l.f != nil {
		unlock(l.f)
	}
}

// LockHeld says whether some process holds the round's lock now.
func LockHeld(dataDir string) bool {
	l := TakeLock(dataDir, "round.lock", 0)
	if l == nil {
		return true
	}
	l.Release()
	return false
}

// trimSpace is strings.TrimSpace (kept short for the many places that need it).
func trimSpace(s string) string { return strings.TrimSpace(s) }
