package core

import (
	"fmt"
	"sort"
	"strings"
)

// Keys of what the model said about a finding (evidence that changes nothing the rules decided).
const (
	IdentifyNoteKey = "model_identify"
	ExplainNoteKey  = "model_explain"
	SkillNoteKey    = "model_note"
)

// ReportText is the last round for a person at a terminal: by what may be done, the biggest and most serious first,
// then what could not be checked.
func ReportText(r Report, home string) string {
	groups := []struct {
		v          Verdict
		name, note string
	}{{Safe, "放心删", "会重建的缓存，删了用到时会重新下载"}, {Confirm, "要确认", "多半用不到了，一项项看过再决定"},
		{Info, "仅供参考", "不建议直接删，或者只是让你知道"}}
	var out []string
	secs := int(r.FinishedAt.Sub(r.StartedAt.Time).Seconds())
	if secs < 1 {
		secs = 1
	}
	out = append(out, fmt.Sprintf("螺壳扫描 · %s 查的（用了 %d 秒）", r.StartedAt.Local().Format("2006-01-02 15:04"), secs))
	if len(r.Findings) == 0 && len(r.Skipped) == 0 {
		out = append(out, "", "没查出什么。")
	}
	for _, g := range groups {
		var items []Finding
		for _, f := range r.Findings {
			if f.Verdict == g.v {
				items = append(items, f)
			}
		}
		if len(items) == 0 {
			continue
		}
		sort.SliceStable(items, func(i, j int) bool {
			a, b := items[i], items[j]
			if a.Severity.Rank() != b.Severity.Rank() {
				return a.Severity.Rank() > b.Severity.Rank()
			}
			if bytesOf(a) != bytesOf(b) {
				return bytesOf(a) > bytesOf(b)
			}
			return a.Title < b.Title
		})
		var total int64
		for _, f := range items {
			total += bytesOf(f)
		}
		sum := ""
		if total > 0 && g.v != Info {
			sum = "，共 " + FormatBytes(total)
		}
		out = append(out, "", fmt.Sprintf("%s（%d 项%s）——%s", g.name, len(items), sum, g.note))
		indent := strings.Repeat(" ", 11)
		for _, f := range items {
			size := "·"
			if f.Bytes != nil {
				size = FormatBytes(*f.Bytes)
			}
			if n := len([]rune(size)); n < 9 {
				size += strings.Repeat(" ", 9-n)
			}
			mark := ""
			if f.Severity == High {
				mark = "！"
			}
			out = append(out, "  "+size+mark+f.Title)
			if strings.HasPrefix(f.Path, "/") {
				out = append(out, indent+HomeRelative(f.Path, home))
			} else if f.Path != "" {
				out = append(out, indent+f.Path)
			}
			for _, k := range []string{IdentifyNoteKey, ExplainNoteKey, SkillNoteKey} {
				if m := f.Evidence[k]; m != "" {
					out = append(out, indent+m)
				}
			}
			if how := f.Evidence["how"]; how != "" {
				out = append(out, indent+"怎么办："+how)
			}
		}
	}
	if len(r.Skipped) > 0 {
		out = append(out, "", fmt.Sprintf("没查成（%d 项）", len(r.Skipped)))
		for _, s := range r.Skipped {
			out = append(out, "  "+s.Rule+"："+s.Reason)
		}
	}
	out = append(out, "", "每一条的全部细节：luoke-scan findings")
	return strings.Join(out, "\n") + "\n"
}
