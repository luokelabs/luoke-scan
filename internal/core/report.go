package core

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// Verdict is what the user is told they can do with a finding; only rules decide it.
type Verdict string

const (
	Safe    Verdict = "safe"    // 放心删: rebuildable, nothing of the user's lost
	Confirm Verdict = "confirm" // 要确认
	Info    Verdict = "info"    // 仅供参考: never offered for deletion
)

type Severity string

const (
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Rank orders severities: low < medium < high.
func (s Severity) Rank() int {
	switch s {
	case Medium:
		return 1
	case High:
		return 2
	}
	return 0
}

type Category string

const (
	CatCache        Category = "cache"
	CatLeak         Category = "leak"
	CatStaleProject Category = "stale-project"
	CatPersistence  Category = "persistence"
	CatSpace        Category = "space"
	CatLeftover     Category = "leftover"
	CatProcess      Category = "process"
	CatPermission   Category = "permission"
	CatPosture      Category = "posture"
	CatMalware      Category = "malware"
	CatSkill        Category = "skill"
	CatSupplyChain  Category = "supply-chain"
)

// Finding is one result of a round: an object, what it is, why, and what may be done.
type Finding struct {
	Rule     string            `json:"rule"`
	Category Category          `json:"category"`
	Severity Severity          `json:"severity"`
	Verdict  Verdict           `json:"verdict"`
	Path     string            `json:"path"`
	Bytes    *int64            `json:"bytes,omitempty"`
	Title    string            `json:"title"`
	Evidence map[string]string `json:"evidence"`
	// Key names the finding when its path does not (one app's data in several places). Empty: the path.
	Key string `json:"key,omitempty"`
}

// Size is a finding's size, or nil.
func Size(n int64) *int64 { return &n }

// ID is stable across rounds: the rule plus the location (or the key), hashed. The agent keys its cards on it.
func (f Finding) ID() string {
	if f.Key != "" {
		return f.Rule + "/" + ShortHash(f.Key)
	}
	if f.Path == "" {
		return f.Rule
	}
	place := f.Path
	if strings.HasPrefix(place, "/") {
		place = Place(place)
	}
	return f.Rule + "/" + ShortHash(place)
}

// Skipped is a rule that could not run: reported, never taken as "nothing found".
type Skipped struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// Report is one round.
type Report struct {
	Schema      string             `json:"schema"`
	RulePack    string             `json:"rulePack"`
	StartedAt   Time               `json:"startedAt"`
	FinishedAt  Time               `json:"finishedAt"`
	Findings    []Finding          `json:"findings"`
	Skipped     []Skipped          `json:"skipped"`
	Versions    map[string]string  `json:"versions"`
	RuleSeconds map[string]float64 `json:"ruleSeconds,omitempty"`
	StartedWall *Time              `json:"startedWall,omitempty"`
}

// Time is a time written as the reports write it (ISO 8601, UTC, whole seconds).
type Time struct{ time.Time }

func (t Time) MarshalJSON() ([]byte, error) { return json.Marshal(ISOTime(t.Time)) }

func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = v
	return nil
}

// EncodeJSON writes v as the Swift version did: indented, keys sorted, slashes and HTML characters not escaped.
func EncodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
