package core

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() { Register("leak.temp-prefix", NewTempLeakRule) }

// TempLeakQuiet: temp entries touched within this long are left out (they may still be in use).
const TempLeakQuiet = 24 * time.Hour

// TempLeakRule finds many same-prefix entries piling up in the temp folder: something creates a temp folder each run
// and never removes it (e.g. a test suite that mkdtemps a full site build per case). Reports the group, its size and
// growth per day, so the source can be fixed rather than cleaned again. Each entry is walked once for its size and
// newest change; later rounds walk only entries FSEvents saw change.
type TempLeakRule struct {
	MinCount int
	MinBytes int64
	Quiet    time.Duration
	// Journal: incremental, like SpaceRule: an entry FSEvents saw no change under keeps the size and newest change from
	// its last walk (a temp folder can hold tens of thousands of entries), for at most Journal.MaxReuse.
	Journal JournalSource
}

// NewTempLeakRule makes the rule (the same for a fake home).
func NewTempLeakRule(l *Layout, f *Fakes) Rule {
	return &TempLeakRule{MinCount: 20, MinBytes: 100 * 1_048_576, Quiet: TempLeakQuiet, Journal: NewJournalSource()}
}

func (r *TempLeakRule) ID() string      { return "leak.temp-prefix" }
func (r *TempLeakRule) Emits() []string { return []string{"leak.temp-prefix"} }

func tempLeakSuffixChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// TempLeakPrefix is an entry's group: wings-AbC123 → wings; puppeteer_dev_chrome_profile-XyZ987 →
// puppeteer_dev_chrome_profile (a -, _ or . and six or more letters and digits at the end). macOS's own services keep a
// folder each, named by bundle id (com.apple.akd): not made per run, no group.
func TempLeakPrefix(name string) (string, bool) {
	if strings.HasPrefix(name, "com.apple.") {
		return "", false
	}
	i := strings.LastIndexAny(name, "-_.")
	if i <= 0 || len(name)-i-1 < 6 {
		return "", false
	}
	for j := i + 1; j < len(name); j++ {
		if !tempLeakSuffixChar(name[j]) {
			return "", false
		}
	}
	return name[:i], true
}

// TempEntry is what one walk of a temp folder entry found (WalkFacts), and up to which journal event it holds.
type TempEntry struct {
	EventID    uint64    `json:"eventID"`
	Inode      uint64    `json:"inode"`
	Bytes      int64     `json:"bytes"`
	Newest     time.Time `json:"newest"`   // zero: none
	Future     time.Time `json:"future"`   // zero: none
	Modified   time.Time `json:"modified"` // zero: not known
	MeasuredAt time.Time `json:"measuredAt"`
}

// TempEntriesTable keeps TempEntry by canonical path.
func TempEntriesTable(s *Store) Table[TempEntry] { return NewTable[TempEntry](s, "temp_entries", 1) }

// tempReadError says why the temp folder could not be read, as Foundation words it.
func tempReadError(dir string, err error) string {
	name := filepath.Base(dir)
	if errors.Is(err, fs.ErrPermission) {
		return "The file “" + name + "” couldn’t be opened because you don’t have permission to view it."
	}
	return "The file “" + name + "” couldn’t be opened."
}

func (r *TempLeakRule) Run(ctx *Context) ([]Finding, error) {
	if ctx.Tmp == "" {
		return nil, Skip("没有给临时目录")
	}
	tmp := ctx.Tmp
	if !Exists(tmp) {
		return nil, Skip("临时目录不存在：" + tmp)
	}
	d, err := os.Open(tmp)
	var names []string
	if err == nil {
		names, err = d.Readdirnames(-1)
		d.Close()
	}
	if err != nil {
		return nil, Skip("读不了临时目录：" + tempReadError(tmp, err)) // not "nothing there"
	}
	var table Table[TempEntry]
	known := map[string]TempEntry{}
	// Every folder kept from the last full round was found unchanged up to this event (one value, not a rewrite per
	// row).
	var watermark uint64
	if ctx.Store != nil {
		table = TempEntriesTable(ctx.Store)
		known = table.Load()
		v, _ := ctx.Store.Get("temp.verified")
		watermark = parseEventID(v)
	}
	var since *uint64
	if len(known) > 0 {
		var ids []uint64
		for _, k := range known {
			ids = append(ids, k.EventID)
		}
		m := max(watermark, *minEventID(ids))
		since = &m
	}
	inc, err := BeginIncrement(ctx, "fsevents.journal.temp", []string{tmp}, since, r.Journal, func() error {
		known, watermark = map[string]TempEntry{}, 0
		if ctx.Store == nil {
			return nil
		}
		if err := table.Apply(nil, nil, true); err != nil {
			return err
		}
		return ctx.Store.Set("temp.verified", "0")
	})
	if err != nil {
		return nil, err
	}
	write := func(rows map[string]TempEntry, forget []string) error {
		if ctx.Store == nil {
			return nil
		}
		return table.Apply(rows, forget, false)
	}
	rows := map[string]TempEntry{}
	var forget []string
	present := map[string]bool{}
	tmpKey := Canonical(tmp)
	// A group with fewer entries than a finding needs is never reported: its entries are not walked, and what was kept
	// of them goes (kept rows must all be checked against the journal each round, see temp.verified).
	counts := map[string]int{}
	for _, n := range names {
		if p, ok := TempLeakPrefix(n); ok {
			counts[p]++
		}
	}
	groups := map[string][]TempEntry{}
	for _, n := range names {
		p, ok := TempLeakPrefix(n)
		if !ok || counts[p] < r.MinCount {
			continue
		}
		u := filepath.Join(tmp, n)
		key := tmpKey + "/" + n
		present[key] = true
		ino := Inode(u)
		// Only folders are remembered: FSEvents names the folder something changed in, so a change to a plain file shows
		// up on the temp folder itself, not on the file. A file is just looked at again (cheap).
		if k, ok := known[key]; ok && k.Inode == ino && r.Journal.Reusable(k.MeasuredAt, ctx.Now) &&
			(k.Future.IsZero() || k.Future.After(ctx.Now)) && !inc.Changes.Touched(key, max(k.EventID, watermark)) {
			groups[p] = append(groups[p], k)
			continue
		}
		if ctx.IsCancelled() {
			write(rows, nil) // keep what was walked; the interruption is what counts
			return nil, Skip(Interrupted)
		}
		f, ok := WalkFacts(u, ctx.Now, ctx.IsCancelled)
		if !ok {
			write(rows, nil)
			return nil, Skip(Interrupted)
		}
		entry := TempEntry{EventID: inc.Start, Inode: ino, Bytes: f.Bytes, Newest: f.Newest, Future: f.Future, Modified: f.Modified,
			MeasuredAt: ctx.Now}
		if f.IsDir {
			rows[key] = entry
		} else if _, ok := known[key]; ok {
			forget = append(forget, key)
		}
		groups[p] = append(groups[p], entry)
	}
	for k := range known {
		if !present[k] {
			forget = append(forget, k)
		}
	}
	sort.Strings(forget)
	if err := write(rows, forget); err != nil {
		return nil, Skip("数据写不进去：" + err.Error())
	}
	if v := inc.Verified(); v > watermark && ctx.Store != nil {
		if err := ctx.Store.Set("temp.verified", strconv.FormatUint(v, 10)); err != nil {
			return nil, Skip("数据写不进去：" + err.Error())
		}
	}
	prefixes := make([]string, 0, len(groups))
	for p := range groups {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	var out []Finding
	quietSince := ctx.Now.Add(-r.Quiet)
	for _, p := range prefixes {
		var idle []TempEntry
		for _, e := range groups[p] {
			if e.Newest.Before(quietSince) {
				idle = append(idle, e)
			}
		}
		if len(idle) < r.MinCount {
			continue
		}
		var size int64
		for _, e := range idle {
			size += e.Bytes
		}
		if size < r.MinBytes {
			continue
		}
		var first, last time.Time
		for _, e := range idle {
			m := e.Modified
			if m.IsZero() || m.After(ctx.Now) {
				continue
			}
			if first.IsZero() || m.Before(first) {
				first = m
			}
			if last.IsZero() || m.After(last) {
				last = m
			}
		}
		days := 1
		firstDay, lastDay := "?", "?"
		if !first.IsZero() {
			days = max(1, int(math.Ceil(last.Sub(first).Seconds()/86400)))
			firstDay, lastDay = ISODay(first), ISODay(last)
		}
		severity := Low
		if size >= 1<<30 {
			severity = Medium
		}
		out = append(out, Finding{Rule: "leak.temp-prefix", Category: CatLeak, Severity: severity, Verdict: Confirm,
			Path: strings.TrimRight(tmp, "/") + "/" + p + "-*", Bytes: Size(size),
			Title: fmt.Sprintf("临时目录里有 %d 个 %s-* 没被删掉，共 %s", len(idle), p, FormatBytes(size)),
			Evidence: map[string]string{"prefix": p, "count": strconv.Itoa(len(idle)), "size": FormatBytes(size),
				"first": firstDay, "last": lastDay, "per_day": FormatBytes(size / int64(days)),
				"hint": "多半是某个程序每次运行都建一个临时目录、用完不删；找到它修掉，比反复清理更管用"}})
	}
	return out, nil
}
