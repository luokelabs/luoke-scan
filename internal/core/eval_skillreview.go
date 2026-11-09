package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The semantic check's evalset and the prompt's examples, made from synthetic skills with the input the scan sends
// (SkillReviewInput): bench/evalsets/skills.json from evals/skills/cases.json, prompts/skills.examples.json from
// evals/skills/examples.json. Written by luoke-scan make-skill-evalset and never by hand; a test checks they are
// current, so what the eval sends is what the scan would.

// SkillExample is a worked example for the prompt: a skill, written like a case, and the answer it should get.
type SkillExample struct {
	ID     string                   `json:"id"`
	Why    string                   `json:"why"`
	Place  *string                  `json:"place"`
	Files  map[string]SkillEvalFile `json:"files"`
	Output struct {
		Fits   bool   `json:"fits"`
		Does   string `json:"does"`
		Beyond []struct {
			File string `json:"file"`
			What string `json:"what"`
		} `json:"beyond"`
		Risk Severity `json:"risk"`
	} `json:"output"`
}

func (e SkillExample) asCase() SkillEvalCase {
	return SkillEvalCase{ID: e.ID, Why: e.Why, Place: e.Place, Files: e.Files}
}

// LoadSkillExamples reads an examples file.
func LoadSkillExamples(path string) ([]SkillExample, error) {
	var out []SkillExample
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	for _, e := range out {
		if e.Files == nil {
			return nil, fmt.Errorf("%s：没有 files", e.ID)
		}
		switch e.Output.Risk {
		case Low, Medium, High:
		default:
			return nil, fmt.Errorf("%s：risk 只能是 low、medium、high", e.ID)
		}
	}
	return out, nil
}

// skillEvalRead is a case's skill as the scan reads it, what the rules found in it, and the finding they make.
func skillEvalRead(c SkillEvalCase, root string) (Skill, []SkillSignal, *Finding, error) {
	home := filepath.Join(root, c.ID, "home")
	place := ".claude/skills"
	if c.Place != nil {
		place = *c.Place
	}
	folder := filepath.Join(home, place, c.ID)
	if _, err := skillEvalWrite(c, folder); err != nil {
		return Skill{}, nil, nil, err
	}
	ctx := NewContext(home)
	ctx.Now = FixtureNow
	for _, s := range FindSkills(&ctx, SkillPlaces, DefaultSkillLimits(), true).Skills {
		if s.Folder == folder {
			signals := SkillSignals(s)
			return s, signals, SkillFinding(s, signals, nil), nil
		}
	}
	return Skill{}, nil, nil, fmt.Errorf("%s：写好的 skill 没被找到", c.ID)
}

// skillExpectedFits is what the model should say about a case: a malicious one does not match its description, a
// benign one does; no expectation (ok false) for one marked "unsure".
func skillExpectedFits(c SkillEvalCase) (fits, ok bool, err error) {
	if c.Semantic == nil {
		return !c.Malicious, true, nil
	}
	if *c.Semantic == "unsure" {
		return false, false, nil
	}
	return false, false, fmt.Errorf("%s：semantic 只能是 unsure，不是 %s", c.ID, *c.Semantic)
}

// SkillSemanticFiles are the two files' contents. An item is hard (every tier must pass it) when the rules report the
// skill (only those are asked about) and it is benign (its risk must not be called high) or malicious and expected
// not to match (it must be called a mismatch); bench/run_eval.py has the checks.
func SkillSemanticFiles(cases SkillEvalSuite, examples []SkillExample) (evalset, shownExamples string, err error) {
	root, err := skillEvalWorkDir("skill-semantic")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(root)
	limits := DefaultSkillReviewLimits()
	var items []string
	for n, c := range cases.Cases {
		skill, signals, finding, err := skillEvalRead(c, root)
		if err != nil {
			return "", "", err
		}
		fits, sure, err := skillExpectedFits(c)
		if err != nil {
			return "", "", err
		}
		reported, expectFits := VNullValue, VNullValue
		if finding != nil {
			reported = VStr(string(finding.Severity))
		}
		if sure {
			expectFits = VBoolean(fits)
		}
		var files []Value
		for _, f := range skill.Files {
			files = append(files, VStr(ReviewShownPath(f.Path)))
		}
		never := map[string]bool{}
		for _, h := range append(ReviewHosts(skill), ReviewAddresses(skill)...) {
			never[h] = true
		}
		var neverList []Value
		for _, h := range sortedKeys(never) {
			neverList = append(neverList, VStr(h))
		}
		items = append(items, VObj(
			Field{"id", VStr(fmt.Sprintf("skills-%02d-", n+1) + c.ID)},
			Field{"hard", VBoolean(finding != nil && (!c.Malicious || (sure && !fits)))},
			Field{"why", VStr(c.Why)},
			Field{"reported", reported},
			Field{"input", SkillReviewInput(skill, signals, limits)},
			Field{"expect", VObj(
				Field{"fits", expectFits},
				Field{"benign", VBoolean(!c.Malicious)},
				Field{"files", VList(files...)},
				Field{"never", VList(neverList...)},
			)},
		).Text())
	}
	note := "合成的评测集（没有真实用户的数据），由 luoke-scan make-skill-evalset 从 evals/skills/cases.json 生成，不要手改。" +
		"input 是扫描会发的（SkillReview.input）；reported 是规则给的轻重（null：规则没报，上线时不会问模型，所以不是硬性条目）。hard 为真的是硬性条目。"
	evalset = "{\"task\": " + VStr(SkillReviewTask).Text() + ", \"version\": " + strconv.Itoa(cases.Version) + ", \"_说明\": " +
		VStr(note).Text() + ", \"items\": [\n" + strings.Join(items, ",\n") + "\n]}\n"
	var shown []string
	for _, e := range examples {
		skill, signals, _, err := skillEvalRead(e.asCase(), root)
		if err != nil {
			return "", "", err
		}
		o := e.Output
		var beyond []Value
		for _, b := range o.Beyond {
			beyond = append(beyond, VObj(Field{"file", VStr(b.File)}, Field{"what", VStr(b.What)}))
		}
		output := VObj(Field{"fits", VBoolean(o.Fits)}, Field{"does", VStr(o.Does)}, Field{"beyond", VList(beyond...)},
			Field{"risk", VStr(string(o.Risk))})
		shown = append(shown, VObj(Field{"input", SkillReviewInput(skill, signals, limits)}, Field{"output", output}).Text())
	}
	return evalset, "[\n" + strings.Join(shown, ",\n") + "\n]\n", nil
}
