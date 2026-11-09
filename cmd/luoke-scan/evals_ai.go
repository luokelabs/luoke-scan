package main

import (
	"fmt"
	"os"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// runAIEvals runs eval-skills and eval-agentfiles: the summary, or with --json each case's result; exit status 1 when
// a malicious case was missed or a benign one reported high, 2 when the eval could not run. false: not one of them.
func runAIEvals(command string) bool {
	var run func(core.SkillEvalSuite) (core.SkillEvalScore, error)
	cases := ""
	switch command {
	case "eval-skills":
		run, cases = core.RunSkillEval, "evals/skills/cases.json"
	case "eval-agentfiles":
		run, cases = core.RunAgentFileEval, "evals/agentfiles/cases.json"
	default:
		return false
	}
	if c, ok := last(take("--cases")); ok {
		cases = c
	}
	jsonOut := flag("--json")
	noExtra()
	suite, err := core.LoadSkillEval(cases)
	if err != nil {
		fail(fmt.Sprintf("评测没跑成：%v", err), 2)
	}
	score, err := run(suite)
	if err != nil {
		fail(fmt.Sprintf("评测没跑成：%v", err), 2)
	}
	if jsonOut {
		out := make([]map[string]any, 0, len(score.Results))
		for _, r := range score.Results {
			out = append(out, core.SkillEvalResultJSON(r))
		}
		data, _ := core.EncodeJSON(out)
		os.Stdout.Write(data)
		fmt.Println()
	} else {
		fmt.Println(score.Text())
	}
	if !score.Passed() {
		os.Exit(1)
	}
	return true
}
