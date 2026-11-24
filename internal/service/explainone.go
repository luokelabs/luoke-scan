package service

import (
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// scan_explain: one finding explained when the user asks (luoke-scan#166). It asks luoke-core's model the same
// question a round asks, with the same input, the same prompt and the same checks on the answer (hubtask.go): the
// round only gets to a few findings, this one to the finding the user is looking at. Nothing more of anyone's files
// reaches the model than a round already gives it, and the answer changes nothing the rules decided.
//
// Which task: a skill the rules reported gets the skills' review (the note only when the model says the skill does
// more than it says, as in a round); a finding a round explains (core.ExplainAsks: a decision, or something serious
// only for reference) gets explain. Nothing else is asked (state "unsupported"): a chat template's and an install
// script's findings, whose story is someone else's text that no task reads yet, and the rest only for reference, which
// a round does not ask about either.

// explainOneTimeout: how long one request may take (the model on this Mac answers in seconds; busy, in tens).
const explainOneTimeout = 60 * time.Second

// explainStates, in the answer's data: the note is there (done); nothing to show, because the model's answer did not
// pass the checks or it had nothing to add (none); luoke-core or the task is not there now (unavailable); luoke-core
// said it is busy (busy); no task reads this kind of finding (unsupported).
const (
	explainDone        = "done"
	explainNone        = "none"
	explainUnavailable = "unavailable"
	explainBusy        = "busy"
	explainUnsupported = "unsupported"
)

func (s *Service) explainOne(args O) (ToolOutput, error) {
	id, _ := args["finding_id"].(string)
	r := s.Store.LastReport()
	var f *core.Finding
	if r != nil {
		for i := range r.Findings {
			if s.fid(r.Findings[i]) == id {
				f = &r.Findings[i]
				break
			}
		}
	}
	if f == nil {
		return ToolOutput{}, Fail("stale", "上一轮里没有这一条。")
	}
	out := func(state string, note any, retryMs any) (ToolOutput, error) {
		text := "这一项现在没有本机模型的说明。"
		if n, ok := note.(O); ok {
			text = "本机模型的说明（仅供参考，不改结论）：" + n["text"].(string)
		}
		return ToolOutput{Text: text, Extra: O{"data": O{"type": "explained", "finding": id, "state": state, "note": note,
			"retryAfterMs": retryMs}}}, nil
	}

	kind, task, name := "explain", core.ExplainTask, "explain"
	switch {
	case core.SkillReviewAsks(*f):
		kind, task, name = "skill-review", core.SkillReviewTask, "skills"
	case !core.ExplainAsks(*f): // what a round asks explain about, no more
		return out(explainUnsupported, nil, nil)
	}
	// What the round already has
	for _, n := range modelNotesData(*f, r) {
		if n.(O)["kind"] == kind {
			return out(explainDone, n, nil)
		}
	}
	link := s.Config.Model
	if link == nil || !hubAvailable(link)[task] {
		return out(explainUnavailable, nil, nil)
	}
	prompt, err := core.LoadPromptFS(name, link.Prompts)
	if err != nil || prompt.Task != task {
		return out(explainUnavailable, nil, nil)
	}
	var input core.Value
	var skill core.Skill
	if kind == "skill-review" {
		ctx := s.Config.Context
		sk, ok := core.SkillOf(&ctx, *f)
		if !ok { // changed since the round: the rules have not seen what is there now
			return out(explainNone, nil, nil)
		}
		skill, input = sk, core.SkillReviewInput(sk, core.SkillSignals(sk), core.DefaultSkillReviewLimits())
	} else {
		place := ""
		if f.Path != "" {
			place = s.display(f.Path)
		}
		input = core.ExplainInput(*f, place)
	}
	answerKey := prompt.Key(input)
	raw, kept := s.Store.ModelAnswers(task)[answerKey]
	if !kept {
		body, err := prompt.Body(input)
		if err != nil {
			return out(explainUnavailable, nil, nil)
		}
		reply := hubGenerate(link, task, body, min(link.RequestTimeout, explainOneTimeout))
		switch {
		case reply.Kind == "refused" && reply.Code == "busy":
			var retry any
			if reply.RetryAfterMs != nil && *reply.RetryAfterMs >= 0 {
				retry = *reply.RetryAfterMs
			}
			return out(explainBusy, nil, retry)
		case reply.Kind != "answer":
			return out(explainUnavailable, nil, nil)
		}
		raw = reply.Text
	}
	now := s.now()
	fresh := map[string]string{}
	if !kept {
		fresh[answerKey] = raw
	}
	s.Store.WriteModelAnswers(task, fresh, map[string]bool{answerKey: true}, now, now.Add(-link.KeepFor))

	text, ok := "", false
	if kind == "skill-review" {
		if a, good := core.SkillReviewAnswer(raw, skill); good {
			if text, ok = core.SkillReviewNote(a); ok {
				text = strings.TrimPrefix(text, core.SkillNoteLead)
			}
		}
	} else {
		maxChars := 120
		if prompt.HasMaxChars() {
			maxChars = int(prompt.MaxChars)
		}
		text, ok = core.ExplainAnswer(raw, *f, input, maxChars)
	}
	if !ok || text == "" {
		return out(explainNone, nil, nil)
	}
	var at any
	if !kept {
		at = core.ISOTime(now)
	}
	return out(explainDone, O{"kind": kind, "source": "local-model", "task": task, "text": text, "at": at}, nil)
}
