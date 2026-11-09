package core

import (
	"os"
	"path/filepath"
)

// RunAgentFileEval is the eval of the checks on AI instruction files (evals/agentfiles/cases.json): the skill eval's
// cases and grading, each case's files written into a fake project of its own (place "home": into the fake home) and
// run through AgentFileRule. The finding graded is the most serious among the case's own files.
func RunAgentFileEval(suite SkillEvalSuite) (SkillEvalScore, error) {
	root, err := skillEvalWorkDir("agentfile")
	if err != nil {
		return SkillEvalScore{}, err
	}
	defer os.RemoveAll(root)
	rule := &AgentFileRule{Places: AgentFilePlaces, Limits: DefaultAgentFileLimits()}
	score := SkillEvalScore{Name: "给 AI 看的说明文件检查评测"}
	for _, c := range suite.Cases {
		home := filepath.Join(root, c.ID, "home")
		projects := filepath.Join(home, "Projects")
		base := filepath.Join(projects, c.ID)
		if c.Place != nil && *c.Place == "home" {
			base = home
		}
		if err := os.MkdirAll(projects, 0o755); err != nil {
			return score, err
		}
		written, err := skillEvalWrite(c, base)
		if err != nil {
			return score, err
		}
		ctx := NewContext(home)
		ctx.ProjectRoots, ctx.Now = []string{projects}, FixtureNow
		found, err := rule.Run(&ctx)
		if err != nil {
			return score, err
		}
		var f *Finding
		for i := range found {
			if !aiContains(written, Canonical(found[i].Path)) {
				continue
			}
			if f == nil || f.Severity.Rank() < found[i].Severity.Rank() {
				f = &found[i]
			}
		}
		score.Results = append(score.Results, skillGradeCase(c, f))
	}
	return score, nil
}
