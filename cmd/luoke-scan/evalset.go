package main

import (
	"fmt"
	"os"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// runMakeSkillEvalset writes the semantic check's evalset and the prompt's examples from the skill cases, with the
// input the scan sends (bench/evalsets/skills.json, prompts/skills.examples.json). false: not this command.
func runMakeSkillEvalset(command string) bool {
	if command != "make-skill-evalset" {
		return false
	}
	or := func(name, fallback string) string {
		if v, ok := last(take(name)); ok {
			return v
		}
		return fallback
	}
	cases := or("--cases", "evals/skills/cases.json")
	examples := or("--examples", "evals/skills/examples.json")
	evalset := or("--evalset", "bench/evalsets/skills.json")
	shown := or("--prompt-examples", "prompts/skills.examples.json")
	noExtra()
	suite, err := core.LoadSkillEval(cases)
	if err != nil {
		fail(fmt.Sprintf("没生成：%v", err), 2)
	}
	ex, err := core.LoadSkillExamples(examples)
	if err != nil {
		fail(fmt.Sprintf("没生成：%v", err), 2)
	}
	madeSet, madeShown, err := core.SkillSemanticFiles(suite, ex)
	if err != nil {
		fail(fmt.Sprintf("没生成：%v", err), 2)
	}
	if err := os.WriteFile(evalset, []byte(madeSet), 0o644); err != nil {
		fail(fmt.Sprintf("没生成：%v", err), 2)
	}
	if err := os.WriteFile(shown, []byte(madeShown), 0o644); err != nil {
		fail(fmt.Sprintf("没生成：%v", err), 2)
	}
	fmt.Println("写好了：" + evalset + "、" + shown)
	return true
}
