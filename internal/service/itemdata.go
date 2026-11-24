package service

// What each outbox item says, as data (top-level ADR 0028, 2026-11-17: a built-in app gives what kind of thing it is,
// what it is about, the numbers, the state, and the actions with their arguments; the sentences, labels and button
// words are luoke-agent's). Each item carries `data` beside its card and texts; while a core that reads `data` and one
// that does not are both in use, the card and texts stay.
//
// The values are codes, names as they are on this Mac (a file's or an app's name is content, not wording), counts and
// bytes. Nothing here is a sentence. docs/data-resources.md 「outbox 的 data」 lists every field.

import (
	"strconv"
	"strings"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// placeCode: the usual folder a path is in, as a code (placeName's names are the Finder's Chinese ones); "" for none.
func (s *Service) placeCode(path string) string {
	shown := s.display(path)
	for _, dir := range []string{"Downloads", "Desktop", "Documents", "Pictures", "Movies", "Music"} {
		if strings.HasPrefix(shown, "~/"+dir+"/") {
			return strings.ToLower(dir)
		}
	}
	return ""
}

// planRef: the plan a card's button applies and the item in it, or nil when there is nothing to apply.
func planRef(p *Plan, key string) any {
	if p == nil {
		return nil
	}
	return O{"id": p.ID, "key": key}
}

// malwareData: a file the virus database or a YARA rule recognised (securityItems).
func (s *Service) malwareData(f core.Finding, r core.Report, id string) O {
	return O{"type": "malware", "finding": s.fid(f), "name": fileName(f.Path), "place": s.placeCode(f.Path),
		"plan": planRef(s.plan([]core.Finding{f}, r, "security", id, false), "i0")}
}

// startupData: something new that starts by itself (persistenceItem). scope: user-agent | login-item | cron | the
// rule's other scopes; submitted: handed to the system by a running app, gone after a restart; stop: the plan that
// stops it (the user's own LaunchAgent only); settings: the Login Items page is where it is switched off.
func (s *Service) startupData(f core.Finding, r core.Report, id string) O {
	scope, submitted := f.Evidence["scope"], f.Evidence["submitted"] == "1"
	d := O{"type": "startup-new", "finding": s.fid(f), "scope": scope, "submitted": submitted, "app": f.Evidence["app"],
		"program": appName(programName(f.Evidence["program"])), "reveal": f.Path != "", "stop": nil,
		"settings": !submitted && scope == "login-item"}
	if !submitted && scope == "user-agent" {
		d["stop"] = planRef(s.plan([]core.Finding{f}, r, "security", id, false), "i0")
	}
	return d
}

// packageData: a known malicious package in use (maliciousPackageItem). more: the finding that stands for the
// packages past the handful listed one by one (count of them); else count is in how many places this one is used.
func (s *Service) packageData(f core.Finding) O {
	count, _ := strconv.Atoi(f.Evidence["count"])
	return O{"type": "malicious-package", "finding": s.fid(f), "package": f.Evidence["package"], "count": count,
		"more": f.Evidence["packages"] != "", "reveal": strings.HasPrefix(f.Path, "/")}
}

// spaceData: little free space (spaceItems). free (what can be written now), total, swap in bytes (total and swap
// null when the rule did not measure them); purgeable: what the system says it could free besides (null: none); caches: what the rebuildable caches hold; plan: the plan that deletes them as suggested, with each
// item's key and suggestion (the button sends them all), or null.
func (s *Service) spaceData(low core.Finding, cacheBytes int64, p *Plan) O {
	d := O{"type": "space-low", "free": nil, "total": nil, "swap": nil, "purgeable": nil, "caches": cacheBytes, "plan": nil}
	if low.Bytes != nil {
		d["free"] = *low.Bytes
	}
	for _, k := range []string{"total", "swap", "purgeable"} {
		if n, err := strconv.ParseInt(low.Evidence[k+"_bytes"], 10, 64); err == nil {
			d[k] = n
		}
	}
	if p != nil {
		choices := O{}
		for _, it := range p.Items {
			choices[it.Key] = A{it.Suggested}
		}
		d["plan"] = O{"id": p.ID, "choices": choices}
	}
	return d
}

// autoDoneData: one automatic clean on the round's card (autoDoneBody). tools: the caches deleted (partial: only
// partly; failed: not at all), bytes: what that freed; moved: what went to the Trash by kind, with up to three names
// (tool: the test tool a known temporary folder is from); restorable: the batch can be put back; offerStop: the
// newest one, which offers to switch automatic cleaning off.
func autoDoneData(d AutoDone, offerStop bool) O {
	moved, count := A{}, 0
	for _, m := range d.Moved {
		names := A{}
		for _, n := range m.Names {
			base := n
			if i := strings.LastIndex(n, " "); i >= 0 {
				base = n[i+1:]
			}
			tool := ""
			if pr, ok := core.TempLeakPrefix(base); ok {
				tool = core.AutoKnownTemp[pr]
			}
			names = append(names, O{"name": base, "tool": tool})
		}
		moved = append(moved, O{"kind": m.Kind, "count": m.Items, "bytes": m.Bytes, "names": names})
		count += m.Items
	}
	return O{"batch": d.Batch, "at": core.ISOTime(d.At.Time), "bytes": d.Bytes,
		"tools": strs(uniq(append(append([]string(nil), d.Tools...), d.Partial...))), "partial": strs(d.Partial),
		"failed": strs(d.Failed), "moved": moved, "unrecorded": strs(d.Unrecorded),
		"restorable": d.Batch != "" && count > len(d.Unrecorded), "offerStop": offerStop}
}

// decideData: what waits for the user on the round's card (decisionsBody). trash and bytes: what the plan clears as
// suggested and what that frees; caches: the rebuildable caches not yet deleted (plan: their plan and keys, for the
// one button), cachesBytes: what that button frees (the caches' part of bytes: the rest of bytes is what is moved to
// the Trash from the scan page); cleaned and freed: those already deleted this round; toLook: everything that waits; rest: that less
// what the urgent cards already ask about; offerAuto: automatic cleaning is off and would have cleaned something;
// skipped: checks that did not run, by reason.
func (s *Service) decideData(r core.Report, st State, f []core.Finding, id string) O {
	v := s.roundView(f, r, id)
	d := O{"trash": len(v.trash), "bytes": v.bytes, "caches": len(v.caches), "cachesBytes": v.cachesBytes, "cleaned": len(v.cleaned), "freed": v.freed,
		"toLook": v.toLook, "rest": s.roundRest(v, f, st), "plan": nil, "offerAuto": len(s.autoButton(f, st)) > 0}
	if v.plan != nil && len(v.caches) > 0 {
		keys := A{}
		for _, it := range v.caches {
			keys = append(keys, it.Key)
		}
		d["plan"] = O{"id": v.plan.ID, "caches": keys}
	}
	fda, db, other := 0, 0, 0
	for _, x := range r.Skipped {
		switch {
		case strings.Contains(x.Reason, "完全磁盘访问"):
			fda++
		case strings.Contains(x.Reason, "病毒库"):
			db++
		default:
			other++
		}
	}
	d["skipped"] = O{"fda": fda, "virusDb": db, "other": other}
	return d
}

// roundData: the round's item (roundItems, roundBody): the automatic cleans it tells (the newest maxToldCleans in
// full; moreCleans: how many older ones), what waits for the user (null when nothing does), and the caches an
// automatic clean of this round could not delete at all.
func (s *Service) roundData(r core.Report, st State, told []AutoDone, f []core.Finding, decide bool, id string) O {
	cleans := A{}
	for i, d := range told {
		if i >= maxToldCleans {
			break
		}
		cleans = append(cleans, autoDoneData(d, i == 0))
	}
	more := len(told) - maxToldCleans
	if more < 0 {
		more = 0
	}
	out := O{"type": "round", "cleans": cleans, "moreCleans": more, "decide": nil, "failed": A{}}
	if decide {
		out["decide"] = s.decideData(r, st, f, id)
	}
	var failed []string
	for _, d := range st.AutoDone {
		if d.Round != nil && d.Round.Equal(r.StartedAt.Time) {
			failed = append(failed, d.Failed...)
		}
	}
	var only []string
	for _, tool := range uniq(failed) {
		inTold := false
		for _, d := range told {
			if contains(d.Failed, tool) {
				inTold = true
			}
		}
		if !inTold {
			only = append(only, tool)
		}
	}
	out["failed"] = strs(only)
	return out
}

// strs: a list of names as JSON gives it: [] rather than null for none.
func strs(s []string) A {
	out := A{}
	for _, x := range s {
		out = append(out, x)
	}
	return out
}
