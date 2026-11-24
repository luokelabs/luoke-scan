package service

import (
	"strings"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// What a finding has beyond its rule's verdict, for the page the agent draws (docs/data-resources.md 「本机模型的说明」
// and 「命中的依据」): what this Mac's model said about it, and where the rules found what they found.
//
// Both are content rather than codes, and both are marked as what they are. A model's note is the model's own
// sentence, shown as it is and changing nothing the rules decided. An excerpt is a line of someone else's file, read
// again when asked for and kept nowhere (core/hits.go); it goes to the page and to no model.

// modelNoteKinds: the notes a round's model tasks leave on a finding, in the order they are shown: the task, and the
// scan's own lead-in the stored note starts with (taken off: the label is the page's).
var modelNoteKinds = []struct{ kind, key, task, lead string }{
	{"identify", core.IdentifyNoteKey, core.IdentifyTask, core.IdentifyNoteLead},
	{"explain", core.ExplainNoteKey, core.ExplainTask, ""},
	{"skill-review", core.SkillNoteKey, core.SkillReviewTask, core.SkillNoteLead},
}

// modelNotesData: what the model said about f in the round r, [] when nothing. at: when that round finished (the
// notes are written as it ends).
func modelNotesData(f core.Finding, r *core.Report) A {
	out := A{}
	for _, k := range modelNoteKinds {
		text := strings.TrimPrefix(f.Evidence[k.key], k.lead)
		if text == "" {
			continue
		}
		var at any
		if r != nil {
			at = core.ISOTime(r.FinishedAt.Time)
		}
		out = append(out, O{"kind": k.kind, "source": "local-model", "task": k.task, "text": text, "at": at})
	}
	return out
}

// hitData: a place a finding was found, as codes, names and numbers (core.Hit).
func hitData(h core.Hit) O {
	lines := A{}
	for _, l := range h.Lines {
		lines = append(lines, l)
	}
	return O{"kinds": stringsA(h.Kinds), "severity": nilIfEmpty(h.Severity), "files": stringsA(h.Files), "part": nilIfEmpty(h.Part),
		"lines": lines, "linesMore": h.LinesMore, "declared": h.Declared}
}

// putHits adds to facts where the rules found it, as the round kept it: hits (nil for a round from before they were
// kept) and how many more there were.
func putHits(facts O, f core.Finding) {
	hits, more, ok := core.HitsOf(f)
	if !ok {
		facts["hits"], facts["hitsMore"] = nil, 0
		return
	}
	list := A{}
	for _, h := range hits {
		list = append(list, hitData(h))
	}
	facts["hits"], facts["hitsMore"] = list, more
}

// hasEvidence: a finding whose files can be read again for the lines the rules pointed at.
func hasEvidence(f core.Finding) bool {
	return (strings.HasPrefix(f.Rule, "skill.") || f.Rule == "model.chat-template") && f.Key != "" && strings.HasPrefix(f.Path, "/")
}

// evidenceData: the hits of f with the lines they point at, read now (core.SkillEvidence, core.ChatTemplateEvidence).
func (s *Service) evidenceData(f core.Finding) O {
	state, hits := core.EvidenceNone, []core.HitExcerpts(nil)
	if hasEvidence(f) {
		ctx := s.Config.Context
		if strings.HasPrefix(f.Rule, "skill.") {
			state, hits = core.SkillEvidence(&ctx, f)
		} else {
			state, hits = core.ChatTemplateEvidence(&ctx, f)
		}
	}
	list := A{}
	for _, h := range hits {
		excerpts := A{}
		for _, e := range h.Excerpts {
			var line any
			if e.Line > 0 {
				line = e.Line
			}
			x := O{"line": line, "text": e.Text, "cut": e.Cut, "redacted": e.Redacted, "source": "file"}
			if e.Kinds != nil {
				x["kinds"] = stringsA(e.Kinds)
			}
			excerpts = append(excerpts, x)
		}
		d := hitData(h.Hit)
		d["excerpts"] = excerpts
		list = append(list, d)
	}
	return O{"state": state, "hits": list}
}

// findingEntry: a finding as data/overview's attention lists it. category: the category it can also be cleaned from
// (nil: none).
func (s *Service) findingEntry(x core.Finding, r *core.Report, category any) O {
	var path any
	if strings.HasPrefix(x.Path, "/") {
		path = x.Path
	}
	return O{"finding": s.fid(x), "rule": x.Rule, "severity": string(x.Severity), "urgent": isUrgent(x),
		"category": category, "path": path, "reveal": nilIfEmpty(s.revealTarget(x)), "facts": s.attentionFacts(x),
		"modelNotes": modelNotesData(x, r)}
}

// dataFinding: data/finding?id=<finding>: one finding of the last round, as the attention list has it, with the lines
// its hits point at. An id the last round does not have: known false.
func (s *Service) dataFinding(args map[string]string) O {
	r := s.Store.LastReport()
	out := O{"schema": dataSchema, "known": false, "scanned": scannedData(r), "finding": args["id"], "evidence": nil}
	if r == nil || args["id"] == "" {
		return out
	}
	for _, f := range r.Findings {
		if s.fid(f) != args["id"] {
			continue
		}
		var category any
		for cat, items := range s.dataItems(r, s.state()) {
			for _, d := range items {
				if d.out["finding"] == args["id"] {
					category = cat
				}
			}
		}
		for k, v := range s.findingEntry(f, r, category) {
			out[k] = v
		}
		out["known"], out["evidence"] = true, s.evidenceData(f)
		return out
	}
	return out
}
