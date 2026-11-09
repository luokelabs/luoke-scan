package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// What the window shows of this tool besides cards (luoke-agent#3): the summary in the sidebar, the state of the
// permissions, and two base pages the window draws from A2UI. Read by relative id (summary, permissions, page/<id>).

var basePages = []struct{ id, title string }{{"overview", "概览"}, {"cleaned", "清理记录"}}

// maxRecordBatches is the most batches the clean-up record page lists (a batch takes 6 components).
const maxRecordBatches = 20

func (s *Service) registerPages() {
	srv := s.Server
	srv.Resource("outbox", "扫描要告诉你的事", func() any { return s.outbox() })
	srv.Resource("summary", "概览", func() any { return s.summary(s.state()) })
	srv.Resource("permissions", "权限的状态", func() any { return s.permissionStates(s.state()) })
	for _, p := range basePages {
		id := p.id
		srv.Resource("page/"+id, p.title, func() any { return A(s.page(id, s.state())) })
	}
}

// summary: {"count", "text"}: what waits for the user (the count by the sidebar) and one sentence on it. The serious
// ones only for reference count too; the rest only for reference does not.
func (s *Service) summary(st State) O {
	r := s.Store.LastReport()
	if r == nil {
		return O{"count": 0, "text": "还没查过这台 Mac"}
	}
	all := s.visible(*r, st)
	var f, safe []core.Finding
	high := 0
	for _, x := range all {
		if x.Verdict != core.Info {
			f = append(f, x)
		}
		if isHighInfo(x) {
			high++
		}
	}
	// As the outbox counts them: one the user acted on or put away is not urgent any more.
	urgent := 0
	var bytes int64
	for _, x := range f {
		if isUrgent(x) {
			if a, ok := st.Acks["security/"+s.fid(x)]; !ok || a.State == "shown" {
				urgent++
			}
		}
		if x.Verdict == core.Safe {
			safe = append(safe, x)
			if x.Bytes != nil {
				bytes += *x.Bytes
			}
		}
	}
	var text string
	switch {
	case urgent > 0:
		text = fmt.Sprintf("有 %d 件要尽快看看", urgent)
		if high > 0 {
			text += fmt.Sprintf("，另外 %d 条需要留意", high)
		}
	case len(f) == 0 && high == 0:
		text = "没有要你处理的"
	default:
		text = roundHeadline(len(safe), bytes, len(f)-len(safe)+high)
	}
	return O{"count": len(f) + high, "text": text}
}

// permissionStates: each permission in the manifest, as it is now. Full Disk Access: asked of macOS right now where
// this can be, else from the last round (denied when a check lacked it, granted only when the check that needs it
// ran, ask otherwise). Automatic cleaning: on unless turned off, or every kind is off. Never guessed.
func (s *Service) permissionStates(st State) O {
	fda := "ask"
	var now *bool
	if s.Config.FullDiskAccess != nil {
		now = s.Config.FullDiskAccess()
	}
	if now != nil {
		fda = "denied"
		if *now {
			fda = "granted"
		}
	} else if r := s.Store.LastReport(); r != nil {
		denied, other := false, false
		for _, x := range r.Skipped {
			if strings.Contains(x.Reason, "完全磁盘访问") {
				denied = true
			}
			if x.Rule == "permission.stale-grant" || x.Reason == core.Interrupted {
				other = true
			}
		}
		if denied {
			fda = "denied"
		} else if !other {
			fda = "granted"
		}
	}
	auto := "off"
	if st.AutocleanOff == nil {
		for _, k := range AutoKinds {
			if _, off := st.AutoOff[string(k)]; !off {
				auto = "on"
			}
		}
	}
	return O{"fda": fda, "auto": auto, "admin": "ask"}
}

// page is a base page's A2UI messages; the surface is the page's id.
func (s *Service) page(id string, st State) []any {
	c := NewCard(id)
	switch id {
	case "overview":
		s.overviewPage(c, st)
	case "cleaned":
		s.cleanedPage(c)
	default:
		c.Text("没有这一页")
	}
	return c.Messages()
}

func (s *Service) overviewPage(c *Card, st State) {
	c.Heading("扫描")
	r := s.Store.LastReport()
	if r == nil {
		c.Text("还没查过这台 Mac。")
		c.Buttons([]Button{{Label: "现在查一下", Event: "scan_now", Primary: true}})
		return
	}
	count := map[core.Verdict]int{}
	for _, x := range s.visible(*r, st) {
		count[x.Verdict]++
	}
	text, _ := s.summary(st)["text"].(string)
	c.Text(text)
	c.Text(fmt.Sprintf("上一轮 %s：放心删 %d、要确认 %d、仅供参考 %d", localTime(r.StartedAt.Time), count[core.Safe], count[core.Confirm], count[core.Info]), true)
	if v, ok := r.Versions["clamav_db_version"]; ok {
		d, ok := r.Versions["clamav_db_date"]
		if !ok {
			d = "日期不明"
		}
		c.Text("病毒库 daily "+v+"（"+d+"）", true)
	}
	if len(r.Skipped) > 0 {
		c.Text(fmt.Sprintf("有 %d 项没查成，下一轮再查", len(r.Skipped)), true)
	}
	var on []string
	for _, k := range AutoKinds {
		if _, off := st.AutoOff[string(k)]; !off {
			on = append(on, k.Label())
		}
	}
	if st.AutocleanOff != nil || len(on) == 0 {
		c.Text("自动清：关", true)
	} else {
		c.Text("自动清："+strings.Join(on, "、"), true)
	}
	if !s.IsScanning() {
		c.Buttons([]Button{{Label: "现在查一下", Event: "scan_now"}})
	}
}

// canPutBack: what 「放回」 on a whole batch would bring back: still in the Trash, not moved with the password, not
// malware, not what starts by itself.
func canPutBack(es []Cleaned) []Cleaned {
	var out []Cleaned
	for _, e := range es {
		if e.Restored == nil && e.Trashed != nil && (e.Admin == nil || !*e.Admin) && core.Exists(*e.Trashed) &&
			!strings.HasPrefix(e.Rule, "malware.") && !strings.HasPrefix(e.Rule, "persistence.") {
			out = append(out, e)
		}
	}
	return out
}

// localTime: "10月27日 20:05", this Mac's time zone: for people, not the ISO form.
func localTime(t time.Time) string {
	l := t.Local()
	return fmt.Sprintf("%d月%d日 %02d:%02d", int(l.Month()), l.Day(), l.Hour(), l.Minute())
}

// cleanedPage: the latest clean-ups, a batch each: when, what, how much, and 「放回」 while anything of it is still in
// the Trash.
func (s *Service) cleanedPage(c *Card) {
	c.Heading("清理记录")
	all := s.Cleaned()
	if len(all) == 0 {
		c.Text("还没清理过。")
		return
	}
	var order []string
	batches := map[string][]Cleaned{}
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		if _, has := batches[e.Batch]; !has {
			order = append(order, e.Batch)
		}
		batches[e.Batch] = append(batches[e.Batch], e)
	}
	if len(order) > maxRecordBatches {
		c.Text(fmt.Sprintf("这里列最近 %d 次，更早的 %d 次没列", maxRecordBatches, len(order)-maxRecordBatches), true)
	}
	for i, b := range order {
		if i >= maxRecordBatches {
			break
		}
		es := batches[b]
		var bytes int64
		latest := es[0].At.Time
		var titles []string
		for j, e := range es {
			if e.Bytes != nil {
				bytes += *e.Bytes
			}
			if e.At.After(latest) {
				latest = e.At.Time
			}
			if j < 3 {
				titles = append(titles, e.Title)
			}
		}
		names := strings.Join(titles, "、")
		if len(es) > 3 {
			names += fmt.Sprintf(" 等 %d 项", len(es))
		}
		c.Divider()
		who := "你清的"
		if strings.HasPrefix(b, "auto-") {
			who = "自动清"
		}
		line := who + "：" + names
		if bytes > 0 {
			line += "（" + core.FormatBytes(bytes) + "）"
		}
		c.Text(line)
		back := canPutBack(es)
		var trashed []Cleaned
		allBack := true
		for _, e := range es {
			if e.Trashed != nil {
				trashed = append(trashed, e)
				if e.Restored == nil {
					allBack = false
				}
			}
		}
		when := localTime(latest)
		if len(trashed) > 0 && allBack {
			when += "，已放回"
		}
		c.Text(when, true)
		if len(back) > 0 {
			c.Buttons([]Button{{Label: "放回", Event: "scan_restore", Context: O{"id": b}}})
		}
	}
}
