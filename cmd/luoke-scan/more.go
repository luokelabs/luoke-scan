package main

import (
	"fmt"
	"os"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// runMore runs the development commands (evals); false: not one of them.
func runMore(command string) bool {
	if runAIEvals(command) {
		return true
	}
	if command == "eval-cleanup" {
		cases := "evals/cleanup/cases.json"
		if c, ok := last(take("--cases")); ok {
			cases = c
		}
		jsonOut := flag("--json")
		noExtra()
		suite, err := core.LoadCleanupEval(cases)
		if err != nil {
			fail(fmt.Sprintf("评测没跑成：%v", err), 2)
		}
		score, err := core.RunCleanupEval(suite, nil)
		if err != nil {
			fail(fmt.Sprintf("评测没跑成：%v", err), 2)
		}
		if jsonOut {
			out := []map[string]any{}
			for _, r := range score.Results {
				out = append(out, map[string]any{"id": r.ID, "kind": string(r.Kind), "auto": r.Auto, "keep": r.Keep,
					"wrong": orEmpty(r.Wrong), "missed": orEmpty(r.Missed), "skipped": orEmpty(r.Skipped)})
			}
			data, _ := core.EncodeJSON(out)
			os.Stdout.Write(append(data, '\n'))
		} else {
			fmt.Println(score.Text())
		}
		if !score.Passed() {
			os.Exit(1)
		}
		return true
	}
	if runMakeSkillEvalset(command) {
		return true
	}
	return false
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
