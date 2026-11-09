package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The skill eval (evals/skills/cases.json): synthetic skills, each written into a fake home of its own and run through
// SkillRule. A malicious case must be reported, at least as seriously as it says; a benign one must never be high, nor
// above what it allows. The eval of the instruction files (eval_agentfiles.go) takes the same cases and grading.

// SkillEvalSuite is a cases file.
type SkillEvalSuite struct {
	Version int             `json:"version"`
	Cases   []SkillEvalCase `json:"cases"`
}

// SkillEvalCase is one synthetic skill (or set of instruction files).
type SkillEvalCase struct {
	ID        string `json:"id"`
	Why       string `json:"why"`
	Malicious bool   `json:"malicious"`
	// Malicious: the concern the finding must name, and the least severity.
	Kind *string   `json:"kind"`
	Min  *Severity `json:"min"`
	// Benign: the most it may be reported as ("none": not at all). Default "low"; never "high".
	Max *string `json:"max"`
	// Place: where the skill goes, relative to the fake home (default .claude/skills); for instruction files "home".
	Place *string                  `json:"place"`
	Files map[string]SkillEvalFile `json:"files"`
	// Semantic, for the semantic check (SkillSemanticFiles): "unsure" when the case's description could be read as
	// covering what it does (a malicious one that says what it does), so the model's verdict on it is not graded.
	Semantic *string `json:"semantic"`
}

// SkillEvalFile is a file's contents: text, bytes (base64), bytes copies of fill, or a symbolic link to link.
type SkillEvalFile struct {
	Text     *string
	Base64   *string
	Fill     string
	FillSize int
	Link     *string
}

func (c *SkillEvalFile) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		c.Text = &s
		return nil
	}
	var o struct {
		Base64 *string `json:"base64"`
		Fill   *string `json:"fill"`
		Bytes  *int    `json:"bytes"`
		Link   *string `json:"link"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	switch {
	case o.Base64 != nil:
		c.Base64 = o.Base64
	case o.Link != nil:
		c.Link = o.Link
	default:
		if o.Fill == nil || o.Bytes == nil {
			return errors.New("a file is text, base64, fill and bytes, or link")
		}
		c.Fill, c.FillSize = *o.Fill, *o.Bytes
	}
	return nil
}

// LoadSkillEval reads a cases file.
func LoadSkillEval(path string) (SkillEvalSuite, error) {
	var s SkillEvalSuite
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	for _, c := range s.Cases {
		if c.Files == nil {
			return s, errors.New(c.ID + "：没有 files")
		}
	}
	return s, nil
}

// writeEvalFiles writes a case's files under base, in the order of their names; the files as written, links resolved.
func skillEvalWrite(c SkillEvalCase, base string) ([]string, error) {
	names := make([]string, 0, len(c.Files))
	for n := range c.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	var written []string
	for _, rel := range names {
		content := c.Files[rel]
		u := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(u), 0o755); err != nil {
			return nil, err
		}
		var err error
		switch {
		case content.Text != nil:
			err = os.WriteFile(u, []byte(*content.Text), 0o644)
		case content.Base64 != nil:
			data, derr := base64.StdEncoding.DecodeString(*content.Base64)
			if derr != nil {
				data = nil
			}
			err = os.WriteFile(u, data, 0o644)
		case content.Link != nil:
			err = os.Symlink(*content.Link, u)
		default:
			data := []byte(strings.Repeat(content.Fill, content.FillSize))
			if len(data) > content.FillSize {
				data = data[:content.FillSize]
			}
			err = os.WriteFile(u, data, 0o644)
		}
		if err != nil {
			return nil, err
		}
		written = append(written, Canonical(u))
	}
	return written, nil
}

// SkillEvalResult is what one case got.
type SkillEvalResult struct {
	ID        string
	Why       string
	Malicious bool
	Severity  Severity // "": not reported
	Rule      string
	Kinds     []string
	// Shown: what the user would be shown, the finding's title and evidence.
	Shown   []string
	OK      bool
	Problem string
}

// SkillEvalScore is an eval's results.
type SkillEvalScore struct {
	Results []SkillEvalResult
	Name    string
}

func (s SkillEvalScore) Passed() bool {
	for _, r := range s.Results {
		if !r.OK {
			return false
		}
	}
	return true
}

// Text is the summary: per malicious and benign, how many were reported and how seriously; the cases that failed.
func (s SkillEvalScore) Text() string {
	lines := []string{s.Name + "：" + strconv.Itoa(len(s.Results)) + " 个用例", "",
		"| | 用例 | 报了 | 高 | 中 | 低 |", "|---|---|---|---|---|---|"}
	for _, side := range []struct {
		name      string
		malicious bool
	}{{"恶意", true}, {"正常", false}} {
		var total, reported, high, medium, low int
		for _, r := range s.Results {
			if r.Malicious != side.malicious {
				continue
			}
			total++
			switch r.Severity {
			case High:
				high++
			case Medium:
				medium++
			case Low:
				low++
			}
			if r.Severity != "" {
				reported++
			}
		}
		lines = append(lines, "| "+side.name+" | "+strconv.Itoa(total)+" | "+strconv.Itoa(reported)+" | "+strconv.Itoa(high)+" | "+
			strconv.Itoa(medium)+" | "+strconv.Itoa(low)+" |")
	}
	for _, r := range s.Results {
		if !r.OK {
			lines = append(lines, "", r.ID+"（"+r.Why+"）："+r.Problem)
		}
	}
	lines = append(lines, "")
	if s.Passed() {
		lines = append(lines, "恶意的都报了，正常的没有报成高的：过")
	} else {
		lines = append(lines, "没过")
	}
	return strings.Join(lines, "\n")
}

// gradeCase grades what a case got: f is the finding for it, or nil.
func skillGradeCase(c SkillEvalCase, f *Finding) SkillEvalResult {
	r := SkillEvalResult{ID: c.ID, Why: c.Why, Malicious: c.Malicious, Kinds: []string{}, Shown: []string{}}
	if f != nil {
		r.Severity, r.Rule = f.Severity, f.Rule
		if k, ok := f.Evidence["kinds"]; ok {
			r.Kinds = []string{}
			for _, p := range strings.Split(k, ",") {
				if p != "" {
					r.Kinds = append(r.Kinds, p)
				}
			}
		}
		r.Shown = append(r.Shown, f.Title)
		for _, v := range f.Evidence {
			r.Shown = append(r.Shown, v)
		}
	}
	problem := ""
	if c.Malicious {
		switch {
		case f == nil:
			problem = "没报"
		case c.Min != nil && f.Severity.Rank() < c.Min.Rank():
			problem = "只报成 " + string(f.Severity) + "，至少要 " + string(*c.Min)
		case c.Kind != nil && !aiContains(r.Kinds, *c.Kind):
			problem = "没认出 " + *c.Kind + "（认出的是 " + strings.Join(r.Kinds, ",") + "）"
		}
	} else if f != nil {
		max := "low"
		if c.Max != nil {
			max = *c.Max
		}
		var allowed Severity
		switch max {
		case "low", "medium", "high":
			allowed = Severity(max)
		}
		if f.Severity == High {
			problem = "正常的报成了高：" + f.Title
		} else if allowed == "" || f.Severity.Rank() > allowed.Rank() {
			problem = "报成 " + string(f.Severity) + "，最多 " + max + "：" + f.Title
		}
	}
	r.OK, r.Problem = problem == "", problem
	return r
}

func aiContains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func skillEvalWorkDir(kind string) (string, error) {
	b := make([]byte, 16)
	rand.Read(b)
	root := filepath.Join(os.TempDir(), "luoke-scan-"+kind+"-eval-"+strings.ToUpper(hex.EncodeToString(b)))
	return root, os.MkdirAll(root, 0o700)
}

// RunSkillEval runs every case in a fake home of its own (removed afterwards).
func RunSkillEval(suite SkillEvalSuite) (SkillEvalScore, error) {
	root, err := skillEvalWorkDir("skill")
	if err != nil {
		return SkillEvalScore{}, err
	}
	defer os.RemoveAll(root)
	rule := &SkillRule{Places: SkillPlaces, Limits: DefaultSkillLimits()}
	score := SkillEvalScore{Name: "skill 静态检查评测"}
	for _, c := range suite.Cases {
		home := filepath.Join(root, c.ID, "home")
		place := ".claude/skills"
		if c.Place != nil {
			place = *c.Place
		}
		folder := filepath.Join(home, place, c.ID)
		if _, err := skillEvalWrite(c, folder); err != nil {
			return score, err
		}
		ctx := NewContext(home)
		ctx.Now = FixtureNow
		found, err := rule.Run(&ctx)
		if err != nil {
			return score, err
		}
		var f *Finding
		for i := range found {
			if found[i].Path == folder {
				f = &found[i]
				break
			}
		}
		score.Results = append(score.Results, skillGradeCase(c, f))
	}
	return score, nil
}

// EvalResultJSON is one case's result as --json writes it (kinds and shown sorted: no order is promised).
func SkillEvalResultJSON(r SkillEvalResult) map[string]any {
	kinds := append([]string{}, r.Kinds...)
	sort.Strings(kinds)
	shown := append([]string{}, r.Shown...)
	sort.Strings(shown)
	out := map[string]any{"id": r.ID, "malicious": r.Malicious, "severity": nil, "rule": nil, "kinds": kinds, "shown": shown,
		"ok": r.OK, "problem": nil}
	if r.Severity != "" {
		out["severity"] = string(r.Severity)
		out["rule"] = r.Rule
	}
	if r.Problem != "" {
		out["problem"] = r.Problem
	}
	return out
}
