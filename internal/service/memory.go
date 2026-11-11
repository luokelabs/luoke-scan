package service

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The records this tool writes into the user's memory (luoke-mem#7): what happened, in a sentence and a few fields;
// never a path, a folder's contents or a hash: a file's name only for malware (10-26).

func (s *Service) remember(records []MemoryRecord) {
	if len(records) > 0 && s.Config.Remember != nil {
		s.Config.Remember(records)
	}
}

var categoryLabels = map[string]string{"cache": "缓存", "leftover": "卸载残留", "leak": "临时文件", "stale-project": "很久没动的项目",
	"space": "大文件和重复文件", "persistence": "开机自己运行的", "malware": "报毒的文件",
	"supply-chain": "已知恶意的依赖包"}

// signatureName: what recognised a file, as a name: ASCII letters, digits and ._:- only, at most 100 (else the rule).
func signatureName(sig, rule string) string {
	if sig == "" || len([]rune(sig)) > 100 {
		return rule
	}
	for _, r := range sig {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)
		if !ok {
			return rule
		}
	}
	return sig
}

// cleanedRecords: what the user did with a plan: one scan-cleaned per kind of thing and choice; a malware file on its
// own (scan-malware).
func (s *Service) cleanedRecords(plan string, outcomes []outcome, report *core.Report) []MemoryRecord {
	var out []MemoryRecord
	groups := map[string][]outcome{}
	for _, o := range outcomes {
		if strings.HasPrefix(o.item.Rule, "malware.") {
			continue
		}
		k := o.item.Category + "\x00" + o.item.Rule + "\x00" + o.choice
		groups[k] = append(groups[k], o)
	}
	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		first := g[0].item
		var ok []outcome
		for _, o := range g {
			if o.ok {
				ok = append(ok, o)
			}
		}
		failed := len(g) - len(ok)
		if len(ok) == 0 {
			continue
		}
		var bytes int64
		for _, o := range ok {
			if o.item.Bytes != nil {
				bytes += *o.item.Bytes
			}
		}
		verb := "移到了废纸篓"
		switch g[0].choice {
		case ChoiceClone:
			verb = "换成了克隆"
		case ChoiceRemove:
			verb = "删掉了（会自动重建）"
		case ChoiceScriptsOff:
			verb = "改成了不让依赖在安装时跑脚本"
		}
		label, has := categoryLabels[first.Category]
		if g[0].choice == ChoiceScriptsOff {
			label, has = "包管理器的设置", true
		}
		if !has {
			label = "东西"
		}
		text := fmt.Sprintf("在螺壳扫描里把 %d 项%s%s", len(ok), label, verb)
		if bytes > 0 {
			text += "，" + core.FormatBytes(bytes)
		}
		if failed > 0 {
			text += fmt.Sprintf("，%d 项没做成", failed)
		}
		out = append(out, MemoryRecord{Topic: "scan-cleaned", Speaker: "user", Kind: "receipt", Text: text, Ref: plan, HappenedAt: s.now(),
			Data: map[string]any{"category": first.Category, "rule": first.Rule, "items": len(ok), "bytes": bytes,
				"choice": g[0].choice, "failed": failed}})
	}
	for _, o := range outcomes {
		if strings.HasPrefix(o.item.Rule, "malware.") && o.ok {
			name := ""
			if len(o.item.Targets) > 0 {
				name = filepath.Base(o.item.Targets[0].Path)
			}
			out = append(out, s.malwareRecord(o.item.FindingID, o.item.Rule, name, "trash", plan, report))
		}
	}
	return out
}

// malwareRecord: a malware alert dealt with: the file's name only, what recognised it, what the user did.
func (s *Service) malwareRecord(findingID, rule, fileName, action, ref string, report *core.Report) MemoryRecord {
	var sig string
	if report != nil {
		for _, f := range report.Findings {
			if s.fid(f) == findingID {
				if v, ok := f.Evidence["signature"]; ok {
					sig = v
				} else {
					sig = f.Evidence["rule"]
				}
				break
			}
		}
	}
	signature := signatureName(sig, rule)
	text := "在螺壳扫描里说报毒的文件 " + fileName + "（" + signature + "）不是病毒，以后别提"
	if action == "trash" {
		text = "在螺壳扫描里把一个报毒的文件 " + fileName + "（" + signature + "）移到了废纸篓"
	}
	engine := "yara"
	if rule == "malware.clamav" {
		engine = "clamav"
	}
	return MemoryRecord{Topic: "scan-malware", Speaker: "user", Kind: "receipt", Text: text, Ref: ref, HappenedAt: s.now(),
		Data: map[string]any{"file_name": fileName, "signature": signature, "engine": engine, "action": action}}
}

// ignoredRecord: "以后别提" for one finding (scan_ignore): this one thing, not the whole kind.
func (s *Service) ignoredRecord(f core.Finding, report *core.Report) MemoryRecord {
	if isMalware(f) {
		return s.malwareRecord(s.fid(f), f.Rule, filepath.Base(f.Path), "ignore", "", report)
	}
	return s.ignoredGroup(string(f.Category), f.Rule, f.Evidence["bundle_id"], 1, "")
}

// unignoredRecord: the user took back 「以后别提」 for one finding right after (撤销 on the answer card).
func (s *Service) unignoredRecord(f core.Finding) MemoryRecord {
	what := "这一项" + categoryLabels[string(f.Category)]
	if isMalware(f) {
		what = "报毒的文件 " + filepath.Base(f.Path)
	}
	return MemoryRecord{Topic: "scan-ignored", Speaker: "user", Kind: "statement", Text: "在螺壳扫描里撤回了「" + what + "以后别提」，照样提醒",
		HappenedAt: s.now(), Data: map[string]any{"category": string(f.Category), "rule": f.Rule, "action": "undo"}}
}

// ignoredRecords: "以后别提" chosen in a plan: one record per kind of thing (and app), with how many; malware one by one.
func (s *Service) ignoredRecords(items []PlanItem, plan string, report *core.Report) []MemoryRecord {
	var out []MemoryRecord
	var rest []PlanItem
	for _, it := range items {
		if strings.HasPrefix(it.Rule, "malware.") {
			name := ""
			if len(it.Targets) > 0 {
				name = filepath.Base(it.Targets[0].Path)
			}
			out = append(out, s.malwareRecord(it.FindingID, it.Rule, name, "ignore", plan, report))
		} else {
			rest = append(rest, it)
		}
	}
	apps := map[string]string{}
	if report != nil {
		for _, f := range report.Findings {
			if a, ok := f.Evidence["bundle_id"]; ok {
				apps[s.fid(f)] = a
			}
		}
	}
	groups := map[string][]PlanItem{}
	for _, it := range rest {
		k := it.Category + "\x00" + it.Rule + "\x00" + apps[it.FindingID]
		groups[k] = append(groups[k], it)
	}
	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		out = append(out, s.ignoredGroup(g[0].Category, g[0].Rule, apps[g[0].FindingID], len(g), plan))
	}
	return out
}

// ignoredGroup: app is the removed app's bundle id: its name is not known any more once it is gone.
func (s *Service) ignoredGroup(category, rule, app string, count int, ref string) MemoryRecord {
	data := map[string]any{"category": category, "rule": rule, "items": count}
	what := "这一项"
	if count != 1 {
		what = fmt.Sprintf("这 %d 项", count)
	}
	what += categoryLabels[category]
	text := "在螺壳扫描里说" + what + "以后别提"
	if app != "" {
		data["app"] = app
		text += "（" + app + "）"
	}
	return MemoryRecord{Topic: "scan-ignored", Speaker: "user", Kind: "statement", Text: text, Ref: ref, HappenedAt: s.now(), Data: data}
}

// autoCleanedRecord: what the rules cleaned without a click: by the rules, not the user. ok false when nothing got
// cleaned (a tool's own clean failing every round is not news for the memory).
func (s *Service) autoCleanedRecord(d AutoDone) (MemoryRecord, bool) {
	if len(d.Tools) == 0 && len(d.Partial) == 0 && len(d.Moved) == 0 {
		return MemoryRecord{}, false
	}
	total := d.Bytes
	for _, m := range d.Moved {
		total += m.Bytes
	}
	var parts []string
	if len(d.Tools) > 0 {
		parts = append(parts, strings.Join(d.Tools, "、")+" 的缓存")
	}
	if len(d.Partial) > 0 {
		parts = append(parts, strings.Join(d.Partial, "、")+" 的缓存（一部分）")
	}
	for _, m := range d.Moved {
		parts = append(parts, fmt.Sprintf("%d 项%s", m.Items, kindLabel(m.Kind)))
	}
	text := "螺壳扫描按规则自动清了" + strings.Join(parts, "、")
	if total > 0 {
		text += "，" + core.FormatBytes(total)
	}
	caches := []any{}
	for _, t := range append(append([]string(nil), d.Tools...), d.Partial...) {
		caches = append(caches, map[string]any{"tool": t, "bytes": d.ToolBytes[t]})
	}
	moved := []any{}
	for _, m := range d.Moved {
		moved = append(moved, map[string]any{"kind": m.Kind, "items": m.Items, "bytes": m.Bytes})
	}
	partial := d.Partial
	if partial == nil {
		partial = []string{}
	}
	ref := d.Batch
	if ref == "" {
		ref = "auto-" + d.ID
	}
	return MemoryRecord{Topic: "scan-auto-cleaned", Speaker: "system", Kind: "activity", Text: text, Ref: ref, HappenedAt: d.At.Time,
		Data: map[string]any{"by": "rule", "caches": caches, "partial": partial, "moved": moved, "bytes": total}}, true
}

func (s *Service) autocleanRecord(on bool) MemoryRecord {
	text := "在螺壳扫描里关掉了不用点就清，以后都先问"
	if on {
		text = "在螺壳扫描里打开了不用点就清"
	}
	return MemoryRecord{Topic: "scan-autoclean", Speaker: "user", Kind: "statement", Text: text, HappenedAt: s.now(), Data: map[string]any{"on": on}}
}
