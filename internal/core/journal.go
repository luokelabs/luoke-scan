package core

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ChangeEvent is one directory the journal saw something change in, with the event's id.
type ChangeEvent struct {
	ID   uint64
	Path string
}

// Changes is what changed on disk after some point, as the FSEvents journal saw it: directories, not files, and no
// walking. Swift: ScanCore/ChangeJournal.swift.
type Changes struct {
	// Unknown: the journal cannot answer (history gone, ids wrapped, a root moved, events dropped): everything changed.
	Unknown bool
	// Latest is the newest event id the replay delivered (0: none). Folders found untouched are known unchanged up to
	// here.
	Latest uint64
	// under is the newest event id at or under each directory (every event counts for all its ancestors); lost, per
	// subtree the journal lost detail for (everything under it counts as changed). Only these are kept, not the events.
	under, lost map[string]uint64
}

// NewChanges keeps events (directories something changed in, with the event id) and subtrees (directories the journal
// lost detail for).
func NewChanges(events, subtrees []ChangeEvent, unknown bool, latest uint64) Changes {
	c := Changes{Unknown: unknown, Latest: latest, under: map[string]uint64{}, lost: map[string]uint64{}}
	for _, list := range [][]ChangeEvent{events, subtrees} {
		for _, e := range list {
			for _, a := range journalSelfAndAncestors(JournalTrim(e.Path)) {
				c.under[a] = max(c.under[a], e.ID)
			}
		}
	}
	for _, e := range subtrees {
		p := JournalTrim(e.Path)
		c.lost[p] = max(c.lost[p], e.ID)
	}
	return c
}

// Everything is the answer of a journal that cannot tell: everything changed.
func Everything() Changes { return Changes{Unknown: true} }

func journalSelfAndAncestors(p string) []string {
	out, cur := []string{p}, p
	for {
		i := strings.LastIndexByte(cur, '/')
		if i <= 0 {
			break
		}
		cur = cur[:i]
		out = append(out, cur)
	}
	if p != "/" {
		out = append(out, "/")
	}
	return out
}

// Touched says whether anything at or under path (a canonical path) changed after event since; it looks up the path
// and its ancestors only, so asking for thousands of folders stays cheap.
func (c Changes) Touched(path string, since uint64) bool {
	if c.Unknown {
		return true
	}
	p := JournalTrim(path)
	if c.under[p] > since {
		return true
	}
	for _, a := range journalSelfAndAncestors(p) {
		if c.lost[a] > since {
			return true
		}
	}
	return false
}

// JournalTrim is one spelling per place: no trailing slash, and /private/tmp (what FSEvents reports) the same as /tmp
// (what Canonical gives back).
func JournalTrim(p string) string {
	s := p
	if len(s) > 1 && strings.HasSuffix(s, "/") {
		s = s[:len(s)-1]
	}
	for _, d := range []string{"/private/tmp", "/private/var", "/private/etc"} {
		if s == d || strings.HasPrefix(s, d+"/") {
			s = s[len("/private"):]
		}
	}
	return s
}

// JournalChanges replays the FSEvents journal for roots from event since up to now. It gives up after timeout or when
// cancelled says so (then: everything changed).
func JournalChanges(roots []string, since uint64, timeout time.Duration, cancelled func() bool) Changes {
	var paths []string
	for _, r := range roots {
		if c := Canonical(r); Exists(c) {
			paths = append(paths, c)
		}
	}
	if len(paths) == 0 {
		return Everything()
	}
	if cancelled == nil {
		cancelled = func() bool { return false }
	}
	return fseventsReplay(paths, since, timeout, cancelled)
}

// JournalCurrentID is the newest event id of the journal, system-wide (ids only grow; 0: no journal).
func JournalCurrentID() uint64 { return fseventsCurrentID() }

// JournalUUID is the identity of the journal of the volume path is on ("" not known); a different one means older
// ids mean nothing.
func JournalUUID(path string) string { return fseventsUUID(path) }

// JournalCache holds the journal replays of one round, so two rules asking about the same folders replay once. A
// replay that started earlier and covered more folders answers a later question too (Touched filters by event id).
// Only within a round: a replay knows nothing after it ran, so RunRound starts each round with a new one.
type JournalCache struct {
	mu   sync.Mutex
	done []journalReplayed
}

type journalReplayed struct {
	roots   map[string]bool
	since   uint64
	changes Changes
}

// NewJournalCache is an empty cache.
func NewJournalCache() *JournalCache { return &JournalCache{} }

// Changes is what replay answers for roots from since, or an earlier replay's answer that covers it. A nil cache
// replays every time.
func (j *JournalCache) Changes(roots []string, since uint64, replay func() Changes) Changes {
	if j == nil {
		return replay()
	}
	want := map[string]bool{}
	for _, r := range roots {
		want[JournalTrim(Canonical(r))] = true
	}
	j.mu.Lock()
	for _, d := range j.done {
		covered := d.since <= since
		for w := range want {
			covered = covered && d.roots[w]
		}
		if covered {
			j.mu.Unlock()
			return d.changes
		}
	}
	j.mu.Unlock()
	c := replay() // not under the lock: a replay can take a minute
	if !c.Unknown {
		j.mu.Lock()
		j.done = append(j.done, journalReplayed{roots: want, since: since, changes: c})
		j.mu.Unlock()
	}
	return c
}

// JournalSource is how an incremental check learns what changed (FSEvents), and how long it trusts that. Tests replace
// the functions.
type JournalSource struct {
	Replay         func(roots []string, since uint64, cancelled func() bool) Changes
	CurrentEventID func() uint64
	// JournalID is the identity of the journal of the volume path is on; "" not known.
	JournalID func(volume string) string
	// MaxReuse is the longest something found unchanged is reused before it is walked again anyway: the journal can
	// lose history (purged when the disk fills, turned off for a volume) without telling.
	MaxReuse time.Duration
}

// NewJournalSource is this Mac's journal.
func NewJournalSource() JournalSource {
	return JournalSource{
		Replay: func(roots []string, since uint64, cancelled func() bool) Changes {
			return JournalChanges(roots, since, 60*time.Second, cancelled)
		},
		CurrentEventID: JournalCurrentID,
		JournalID:      JournalUUID,
		MaxReuse:       7 * 24 * time.Hour,
	}
}

// Reusable says whether facts last really gathered at measuredAt may still be reused at now. One gathered "in the
// future" (the clock was wrong then) is not: otherwise the limit would not hold until the clock caught up.
func (j JournalSource) Reusable(measuredAt, now time.Time) bool {
	age := now.Sub(measuredAt)
	return age >= 0 && age < j.MaxReuse
}

// Increment is the start the incremental checks share: is the cache from this journal, what changed since the cached
// facts were gathered, and up to which event id "unchanged" is now known.
type Increment struct {
	Start   uint64
	Changes Changes
}

// Verified is up to where "found unchanged by the replay" holds (0: the replay saw nothing to go by).
func (i Increment) Verified() uint64 { return min(i.Changes.Latest, i.Start) }

// BeginIncrement starts an incremental check. since is where the replay starts (nil: nothing cached yet). The cache
// was made with the journals of every root's volume (stored under metaKey); when one is not the same any more, reset
// empties the cache and everything counts as changed. A journal that cannot be told this time counts everything as
// changed, without a reset.
func BeginIncrement(ctx *Context, metaKey string, roots []string, since *uint64, source JournalSource, reset func() error) (Increment, error) {
	start := source.CurrentEventID()
	// No folder to look at this round (none there, or none it may look at): nothing to replay, and nothing says the
	// journal changed, so the cache is kept as it is.
	if len(roots) == 0 {
		if ctx.IsCancelled() {
			return Increment{}, Skip(Interrupted)
		}
		return Increment{Start: start, Changes: Everything()}, nil
	}
	seen := map[string]bool{}
	for _, r := range roots {
		id := source.JournalID(r)
		if id == "" {
			if ctx.IsCancelled() {
				return Increment{}, Skip(Interrupted)
			}
			return Increment{Start: start, Changes: Everything()}, nil
		}
		seen[id] = true
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	id := strings.Join(ids, ",") // one volume: just its UUID
	if ctx.Store != nil {
		if was, ok := ctx.Store.Get(metaKey); !ok || was != id { // another journal: its old event ids mean nothing
			if err := reset(); err != nil {
				return Increment{}, err
			}
			if err := ctx.Store.Set(metaKey, id); err != nil {
				return Increment{}, err
			}
			since = nil
		}
	}
	if ctx.IsCancelled() {
		return Increment{}, Skip(Interrupted)
	}
	if since == nil {
		return Increment{Start: start, Changes: Everything()}, nil
	}
	from := *since
	return Increment{Start: start, Changes: ctx.Replays.Changes(roots, from, func() Changes {
		return source.Replay(roots, from, ctx.IsCancelled)
	})}, nil
}

// minEventID is the smallest of ids; nil when there are none.
func minEventID(ids []uint64) *uint64 {
	if len(ids) == 0 {
		return nil
	}
	m := ids[0]
	for _, id := range ids[1:] {
		m = min(m, id)
	}
	return &m
}

// parseEventID reads an event id kept as text; 0 when there is none.
func parseEventID(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}
