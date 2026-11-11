package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// A password plan shown again after an answer (no findings passed) still uses the plain titles, from the last round.
func TestAdminBodyFallsBackToTheLastRound(t *testing.T) {
	s := &Service{Store: &core.Store{Dir: t.TempDir()}}
	f := core.Finding{Rule: "leftover.app-data", Category: core.CatLeftover, Key: "com.example.gone",
		Path: "/Library/Caches/com.example.gone", Title: "com.example.gone 的数据还在，但这台 Mac 上没有这个应用",
		Evidence: map[string]string{"bundle_id": "com.example.gone"}}
	want, _ := s.plain(f)
	if want == "" || want == f.Title {
		t.Fatalf("this finding needs a plain title to test with: %q", want)
	}
	if err := s.Store.SaveReport(core.Report{Findings: []core.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	plan := Plan{ID: "p-0123456789ab", Admin: true, Items: []PlanItem{
		{Key: "a0", FindingID: s.fid(f), Title: f.Title, Options: []string{ChoiceTrash}, Suggested: ChoiceTrash}}}
	c := NewCard("x")
	s.adminBody(c, plan, nil)
	b, _ := json.Marshal(c.Messages())
	if !strings.Contains(string(b), want) || strings.Contains(string(b), "这台 Mac 上没有这个应用") {
		t.Fatalf("want the plain title %q in %s", want, b)
	}
}
