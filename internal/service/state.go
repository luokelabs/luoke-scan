package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// Ack is what the agent reported about an outbox item: shown, answered or dismissed.
type Ack struct {
	State string    `json:"state"`
	At    core.Time `json:"at"`
}

// Moved is what went to the Trash of one kind in an automatic clean.
type Moved struct {
	Kind  string   `json:"kind"`
	Items int      `json:"items"`
	Bytes int64    `json:"bytes"`
	Names []string `json:"names"`
}

// AutoDone is one automatic clean, told on a round's item (auto-done).
type AutoDone struct {
	ID         string           `json:"id"`
	At         core.Time        `json:"at"`
	Tools      []string         `json:"tools"`
	Bytes      int64            `json:"bytes"`
	Partial    []string         `json:"partial,omitempty"`
	Failed     []string         `json:"failed,omitempty"`
	Batch      string           `json:"batch,omitempty"`
	Moved      []Moved          `json:"moved,omitempty"`
	Unrecorded []string         `json:"unrecorded,omitempty"`
	ToolBytes  map[string]int64 `json:"toolBytes,omitempty"`
	Round      *core.Time       `json:"round,omitempty"`
	Told       *core.Time       `json:"told,omitempty"`
}

// State is what the user told us through the agent, kept in the data directory (agent-state.json).
type State struct {
	Ignored        map[string]core.Time `json:"ignored"`
	Acks           map[string]Ack       `json:"acks"`
	AutocleanOff   *core.Time           `json:"autocleanOff,omitempty"`
	AutocleanSince *core.Time           `json:"autocleanSince,omitempty"`
	Version        *int                 `json:"version,omitempty"`
	AutoDone       []AutoDone           `json:"autoDone"`
	AutoOff        map[string]core.Time `json:"autoOff,omitempty"`
	DonePlans      map[string]core.Time `json:"donePlans,omitempty"`
}

// neverOn: automatic cleaning off from the start (the user never turned it on).
var neverOn = core.Time{Time: time.Unix(0, 0).UTC()}

// NewState is a fresh state: automatic cleaning off until the user turns it on (version 3).
func NewState() State {
	off, v := neverOn, 3
	return State{Ignored: map[string]core.Time{}, Acks: map[string]Ack{}, AutocleanOff: &off, Version: &v, AutoDone: []AutoDone{}}
}

func readState(path string) (State, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, false
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return State{}, false
	}
	var s State
	if json.Unmarshal(data, &s) != nil {
		return State{}, false
	}
	if s.Ignored == nil {
		s.Ignored = map[string]core.Time{}
	}
	if s.Acks == nil {
		s.Acks = map[string]Ack{}
	}
	if s.AutoDone == nil {
		s.AutoDone = []AutoDone{}
	}
	// A key written and set to null in JSON is absent here: in Swift's files an absent autocleanOff means on.
	if _, has := raw["autocleanOff"]; !has {
		s.AutocleanOff = nil
	}
	return s.migrated(), true
}

// migrated: a file written before version 3 — automatic cleaning off until the user turns it on (0.1.4).
func (s State) migrated() State {
	if s.Version != nil && *s.Version >= 3 {
		return s
	}
	if s.Version == nil {
		if s.AutocleanSince == nil && s.AutocleanOff == nil {
			off := neverOn
			if n := len(s.AutoDone); n > 0 {
				off = s.AutoDone[n-1].At
			}
			s.AutocleanOff = &off
		}
	} else if s.AutocleanOff == nil {
		off := neverOn
		s.AutocleanOff = &off
	}
	s.AutocleanSince = nil
	v := 3
	s.Version = &v
	return s
}

// LoadState is the state, or a fresh one.
func LoadState(path string) State {
	if s, ok := readState(path); ok {
		return s
	}
	return NewState()
}

// KnownState is what the user decided when it can be known: the file, or a fresh state when there is none; ok
// false when the file is there but cannot be read (then nothing is done on the user's behalf).
func KnownState(path string) (State, bool) {
	if s, ok := readState(path); ok {
		return s, true
	}
	if core.Exists(path) {
		return State{}, false
	}
	return NewState(), true
}

// MutateState reads, changes and writes the state under an exclusive lock (rounds and requests are separate
// processes). A file that cannot be read is set aside, not written over, and automatic cleaning starts off.
func MutateState(path string, now time.Time, body func(*State)) State {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		defer func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }()
	}
	fresh := NewState()
	if _, ok := readState(path); !ok && core.Exists(path) {
		aside := fmt.Sprintf("%s.unreadable-%d", path, now.Unix())
		os.Rename(path, aside)
		fmt.Fprintf(os.Stderr, "[luoke-scan] 读不出 %s，已挪到 %s，从头记起（自动清先关着）\n", filepath.Base(path), aside)
		off := core.Time{Time: now}
		fresh.AutocleanOff = &off
	}
	s, ok := readState(path)
	if !ok {
		s = fresh
	}
	body(&s)
	s.save(path, now)
	return s
}

func (s State) save(path string, now time.Time) {
	// Acks of items long gone are not needed again, except those that come back every round while their cause is there
	// (a dismissed malware alert, the full-disk-access request): kept, at most 500.
	type kv struct {
		k string
		v Ack
	}
	var lasting []kv
	for k, v := range s.Acks {
		if hasPrefix(k, "security/") || hasPrefix(k, "needs-access/") {
			lasting = append(lasting, kv{k, v})
		}
	}
	acks := map[string]Ack{}
	for k, v := range s.Acks {
		if now.Sub(v.At.Time) < 60*24*time.Hour {
			acks[k] = v
		}
	}
	sort.Slice(lasting, func(i, j int) bool { return lasting[i].v.At.After(lasting[j].v.At.Time) })
	for i, e := range lasting {
		if i >= 500 {
			break
		}
		acks[e.k] = e.v
	}
	s.Acks = acks
	if len(s.AutoDone) > 20 {
		s.AutoDone = s.AutoDone[len(s.AutoDone)-20:]
	}
	if s.DonePlans != nil {
		kept := map[string]core.Time{}
		for k, v := range s.DonePlans {
			if now.Sub(v.Time) < 30*24*time.Hour {
				kept[k] = v
			}
		}
		s.DonePlans = kept
	}
	data, err := core.EncodeJSON(s)
	if err != nil {
		return
	}
	core.WriteAtomic(path, data, 0o600)
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// Target is what exactly would be moved, as seen when the plan was made; checked again before moving.
type Target struct {
	Path   string `json:"path"`
	Device int64  `json:"device"`
	Inode  uint64 `json:"inode"`
}

// PlanItem is one item of a plan.
type PlanItem struct {
	Key       string   `json:"key"`
	FindingID string   `json:"findingID"`
	Rule      string   `json:"rule"`
	Category  string   `json:"category"`
	Title     string   `json:"title"`
	Bytes     *int64   `json:"bytes,omitempty"`
	Targets   []Target `json:"targets"`
	Suggested string   `json:"suggested"`
	Options   []string `json:"options"`
	Label     string   `json:"label,omitempty"`
	Original  string   `json:"original,omitempty"`
	BundleID  string   `json:"bundleID,omitempty"`
}

// Plan is a clean-up the tool offered: only these items, only these choices, done only after the user clicks.
type Plan struct {
	ID       string     `json:"id"`
	Created  core.Time  `json:"created"`
	Scanned  *core.Time `json:"scanned,omitempty"`
	OutboxID string     `json:"outboxID,omitempty"`
	Items    []PlanItem `json:"items"`
	Admin    bool       `json:"admin,omitempty"`
	Sibling  string     `json:"sibling,omitempty"`
}

// Choices.
const (
	ChoiceTrash  = "trash"
	ChoiceKeep   = "keep"
	ChoiceIgnore = "ignore"
	ChoiceClone  = "clone"
	ChoiceDelete = "delete"
	ChoiceRemove = "remove"
)

// ChoiceLabels are what the card says for each choice.
var ChoiceLabels = map[string]string{ChoiceTrash: "移到废纸篓", ChoiceKeep: "先不动", ChoiceIgnore: "以后别提",
	ChoiceClone: "换成克隆（都留着，省空间）", ChoiceDelete: "删掉（只是失效的链接）", ChoiceRemove: "删掉（会自动重建）"}

// Clears: moved to the Trash, or (a rebuildable cache) deleted.
func Clears(choice string) bool { return choice == ChoiceTrash || choice == ChoiceRemove }

var planID = regexp.MustCompile(`^p-[0-9a-f]{12}$`)

func planPath(dir, id string) string { return filepath.Join(dir, id+".json") }

// LoadPlan reads a plan by id; ok false when there is none (or the id is not one).
func LoadPlan(dir, id string) (Plan, bool) {
	if !planID.MatchString(id) {
		return Plan{}, false
	}
	data, err := os.ReadFile(planPath(dir, id))
	if err != nil {
		return Plan{}, false
	}
	var p Plan
	if json.Unmarshal(data, &p) != nil {
		return Plan{}, false
	}
	return p, true
}

// Save keeps a plan (600, in a 700 folder).
func (p Plan) Save(dir string) {
	os.MkdirAll(dir, 0o700)
	data, err := core.EncodeJSON(p)
	if err != nil {
		return
	}
	core.WriteAtomic(planPath(dir, p.ID), data, 0o600)
}

// PrunePlans drops plans older than keep.
func PrunePlans(dir string, now time.Time, keep time.Duration) {
	for _, f := range core.Children(dir) {
		if ext := filepath.Ext(f); ext == ".json" || ext == ".empty" {
			if m, ok := core.Modified(f); ok && now.Sub(m) > keep {
				os.Remove(f)
			}
		}
	}
}
