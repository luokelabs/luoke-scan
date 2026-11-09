package service

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The outbox (tool protocol §3): what the tool still wants the user to hear, as state rather than messages. Five
// kinds (luoke-agent#2): security (urgent: malware, and new things that start by themselves without anyone vouching
// for them), space (normal), needs-access (low, naming the permission), and the round as one item: auto-done (normal)
// when it cleaned something without a click, else findings (low) when something waits for the user, or something only
// for reference is serious enough to be heard of anyway (luoke-scan#51).

const (
	loginItemsGrantName = "登录项"
	explainNoteKey      = "model_explain"
	identifyNoteKey     = "model_identify"
	skillReviewNoteKey  = "model_note"
	// maxToldCleans: automatic cleans drawn in full on one card; older ones are a line.
	maxToldCleans = 2
	// maxListed is the most findings one list on the round's card shows.
	maxListed = 10
	// listedCost: components a listed finding takes at most (its title, what to do, a row of two buttons).
	listedCost = 7
)

// outbox: the report before the state: a round writes what it cleaned to the state before it saves its report, so
// the new report never comes with a state from before it.
func (s *Service) outbox() any {
	r := s.Store.LastReport()
	return s.outboxOf(s.state(), r)
}

func (s *Service) outboxOf(st State, r *core.Report) O {
	items := A{}
	if r != nil {
		for _, group := range [][]O{s.securityItems(*r, st), s.spaceItems(*r, st), s.roundItems(*r, st), s.accessItems(*r)} {
			for _, it := range group {
				id, _ := it["id"].(string)
				if a, ok := st.Acks[id]; ok && a.State != "shown" {
					continue // answered or dismissed: done with it
				}
				items = append(items, it)
			}
		}
	}
	return O{"items": items}
}

func (s *Service) item(id, kind, urgency string, created time.Time, whyNow, title, summary string, card []any, expires *time.Time, permission string) O {
	o := O{"id": id, "kind": kind, "urgency": urgency, "deadline": nil, "expires": nil,
		"created": core.ISOTime(created), "why_now": whyNow, "title": Clip(title), "summary": Clip(summary), "card": A(card)}
	if expires != nil {
		o["expires"] = core.ISOTime(*expires)
	}
	if permission != "" {
		o["permission"] = permission // needs-access: the id in the manifest's permissions
	}
	return o
}

// securityItems: one urgent item per file the virus database or a YARA rule recognised, and per new thing that
// starts by itself without anyone vouching for it. Once dismissed it is not urgent again.
func (s *Service) securityItems(r core.Report, st State) []O {
	var out []O
	for _, f := range s.visible(r, st) {
		if !isUrgent(f) {
			continue
		}
		id := "security/" + s.fid(f)
		if a, ok := st.Acks[id]; ok && a.State != "shown" {
			continue
		}
		if f.Rule == "persistence.new" {
			out = append(out, s.persistenceItem(f, id, r))
			continue
		}
		if isMaliciousPackage(f) {
			out = append(out, s.maliciousPackageItem(f, id, r))
			continue
		}
		basis := "规则 " + f.Rule
		if rule, ok := f.Evidence["rule"]; ok {
			basis = "规则 " + rule
		}
		if sig, ok := f.Evidence["signature"]; ok {
			basis = "病毒库认出是 " + sig + "（" + f.Evidence["database"] + "）"
		}
		c := NewCard("security-" + core.ShortHash(s.fid(f)))
		c.Heading(f.Title)
		c.Text(s.display(f.Path), true)
		c.Text(strings.Join(append([]string{"依据：" + basis}, modelLines(f)...), "\n"), true)
		var buttons []Button
		if p := s.plan([]core.Finding{f}, r, "security", id, false); p != nil {
			buttons = append(buttons, Button{Label: "移到废纸篓", Event: "scan_apply",
				Context: O{"plan_id": p.ID, "choices": O{"i0": A{ChoiceTrash}}}, Primary: true})
		}
		buttons = append(buttons, Button{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(f)}},
			Button{Label: "不是病毒，以后别提", Event: "scan_ignore", Context: O{"finding_id": s.fid(f)}})
		c.Buttons(buttons)
		out = append(out, s.item(id, "security", "urgent", r.FinishedAt.Time, "这一轮刚认出来；没打开过就别打开", f.Title,
			s.display(f.Path)+"："+basis+"。建议移到废纸篓。", c.Messages(), nil, ""))
	}
	return out
}

// persistenceItem: something new that starts by itself. The user's own LaunchAgent can go from the card (stopped,
// plist to the Trash); a login item is switched off in System Settings; the system's jobs need a password.
func (s *Service) persistenceItem(f core.Finding, id string, r core.Report) O {
	scope, why := f.Evidence["scope"], f.Evidence["why"]
	c := NewCard("security-" + core.ShortHash(s.fid(f)))
	c.Heading(f.Title)
	mine := "是我装的"
	var advice string
	switch scope {
	case "user-agent":
		advice = "如果是你自己装的，点「是我装的」就好；不认识的话可以停掉它，配置会移到废纸篓，随时能放回。"
	case "login-item":
		advice = "如果是你自己装的，点「是我装的」就好；不认识的话，在 系统设置 → 通用 → 登录项与扩展 里关掉。"
	case "cron":
		mine = "是我加的"
		advice = "如果是你自己加的，点「是我加的」就好；不认识的话，在终端里运行 crontab -e 删掉这一行。"
	default:
		advice = "如果是你自己装的，点「是我装的」就好；不认识的话，在访达里找到它移到废纸篓（会要你的密码）。"
	}
	var body string
	if program, ok := f.Evidence["program"]; ok {
		body = "它会运行 " + program + "。"
	}
	if why != "" {
		body += why + "。"
	}
	c.Text(body + advice)
	if f.Path != "" {
		c.Text("配置文件："+s.display(f.Path), true)
	}
	buttons := []Button{{Label: mine, Event: "scan_ignore", Context: O{"finding_id": s.fid(f)}, Primary: true}}
	if f.Path != "" {
		buttons = append(buttons, Button{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(f)}})
	}
	switch scope {
	case "user-agent":
		if p := s.plan([]core.Finding{f}, r, "security", id, false); p != nil {
			buttons = append(buttons, Button{Label: "停掉它", Event: "scan_apply",
				Context: O{"plan_id": p.ID, "choices": O{"i0": A{ChoiceTrash}}}})
		}
	case "login-item":
		buttons = append(buttons, Button{Label: "打开「登录项」设置", Event: "scan_open_settings", Context: O{"grant": loginItemsGrantName}})
	}
	c.Buttons(buttons)
	return s.item(id, "security", "urgent", r.FinishedAt.Time, "这一轮新加的、会自己启动的程序（"+why+"）", f.Title,
		f.Title+"。"+body+advice, c.Messages(), nil, "")
}

// maliciousPackageItem: a project or a global install uses a known malicious package. What to do is written out (take
// the dependency out, move to a version not on the list, change the keys and tokens); the card offers to show the
// lockfile in Finder, never to delete anything of the project's. The rule gives one finding per package (every place
// it is used listed in it) and a handful at most, the rest as one more: so a package in thirty projects is one card.
func (s *Service) maliciousPackageItem(f core.Finding, id string, r core.Report) O {
	c := NewCard("security-" + core.ShortHash(s.fid(f)))
	c.Heading(f.Title)
	how := f.Evidence["how"]
	c.Text(how + "。")
	lines := []string{"依据：" + f.Evidence["list"] + "，" + f.Evidence["ids"]}
	if f.Evidence["ids"] == "" {
		lines[0] = "依据：" + f.Evidence["list"]
	}
	switch {
	case f.Evidence["packages"] != "":
		lines = append(lines, "包："+f.Evidence["packages"])
	case f.Evidence["places"] != "":
		lines = append(lines, "位置（"+f.Evidence["count"]+" 处）："+f.Evidence["places"])
	case f.Evidence["lockfile"] != "":
		lines = append(lines, "位置："+f.Evidence["lockfile"])
	default:
		lines = append(lines, "位置："+f.Evidence["where"])
	}
	c.Text(strings.Join(append(lines, modelLines(f)...), "\n"), true)
	var buttons []Button
	if strings.HasPrefix(f.Path, "/") {
		buttons = append(buttons, Button{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(f)}, Primary: true})
	}
	buttons = append(buttons, Button{Label: "处理好了，以后别提", Event: "scan_ignore", Context: O{"finding_id": s.fid(f)}})
	c.Buttons(buttons)
	return s.item(id, "security", "urgent", r.FinishedAt.Time, "这一轮和恶意包名单比对出来的；装过就当令牌和钥匙已经泄露", f.Title,
		f.Title+"。"+how+"。", c.Messages(), nil, "")
}

// spaceItems: low free space, with what can be freed right away (rebuildable caches) offered on the same card.
func (s *Service) spaceItems(r core.Report, st State) []O {
	vis := s.visible(r, st)
	var low *core.Finding
	for i := range vis {
		if vis[i].Rule == "space.low" {
			low = &vis[i]
			break
		}
	}
	if low == nil {
		return nil
	}
	id := "space/low/" + core.ISODay(r.StartedAt.Time)
	var caches []core.Finding
	var bytes int64
	for _, f := range vis {
		if f.Category == core.CatCache && f.Verdict == core.Safe {
			caches = append(caches, f)
			if f.Bytes != nil {
				bytes += *f.Bytes
			}
		}
	}
	c := NewCard("space-" + core.ShortHash(id))
	total := "?"
	if t, ok := low.Evidence["total"]; ok {
		total = t
	}
	summary := low.Title + "（共 " + total
	if swap, ok := low.Evidence["swap"]; ok {
		summary += "，交换文件占 " + swap
	}
	summary += "）。"
	if p := s.plan(caches, r, "space", id, false); p != nil {
		summary += "会重建的工具缓存能马上腾出 " + core.FormatBytes(bytes) + "。"
		s.planBody(c, *p, low.Title, "下面这些是会重建的工具缓存，删了用到时会重新下载。", caches)
	} else {
		c.Heading(low.Title)
		c.Text(summary, true)
	}
	return []O{s.item(id, "space", "normal", r.FinishedAt.Time, "空间快不够了，满了会影响别的程序", low.Title, summary, c.Messages(), nil, "")}
}

// roundItems: the round as one item (luoke-agent#2, 10-27). auto-done when there is something on top (every
// automatic clean is told; one the agent has not said yet when the next round starts is carried into that round's
// item); else findings when something waits for the user or is serious; else nothing. Its id is the round's alone.
func (s *Service) roundItems(r core.Report, st State) []O {
	id := roundID(r)
	// Answered or dismissed under the id the version before this one gave the round.
	if a, ok := st.Acks["findings/"+core.ISOTime(r.StartedAt.Time)]; ok && a.State != "shown" {
		return nil
	}
	told, f := carried(r.StartedAt.Time, st), s.visible(r, st)
	decide := belowCleans(f)
	if len(told) == 0 && !decide {
		return nil
	}
	c := NewCard(roundSurface(id))
	title, summary := s.roundBody(c, r, st, told, f, decide, id)
	if len(told) > 0 {
		newest := told[0]
		thisRound := newest.Round != nil && newest.Round.Equal(r.StartedAt.Time)
		why := "不用点就清的几类，前一轮清了"
		if thisRound {
			why = "不用点就清的几类，这一轮清了"
		}
		created := maxTime(newest.At.Time, r.FinishedAt.Time)
		expires := maxTime(newest.At.Add(7*24*time.Hour), r.StartedAt.Add(3*24*time.Hour))
		return []O{s.item(id, "auto-done", "normal", created, why, title, summary, c.Messages(), &expires, "")}
	}
	expires := r.StartedAt.Add(3 * 24 * time.Hour)
	return []O{s.item(id, "findings", "low", r.FinishedAt.Time, "扫描刚查完一轮", title, summary, c.Messages(), &expires, "")}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// isHighInfo: only for reference, but serious (FileVault off, a keyboard watcher nobody vouches for…): no plan can
// carry it, yet the user hears of it with the round (luoke-scan#51).
func isHighInfo(f core.Finding) bool { return f.Verdict == core.Info && f.Severity == core.High }

// belowCleans: the round's card has something below the cleans: a decision, or something serious only for reference.
func belowCleans(f []core.Finding) bool {
	for _, x := range f {
		if x.Verdict != core.Info || isHighInfo(x) {
			return true
		}
	}
	return false
}

func roundID(r core.Report) string  { return "round/" + core.ISOTime(r.StartedAt.Time) }
func roundSurface(id string) string { return "round-" + core.ShortHash(id) }

// carried: the automatic cleans the item of the round started at start tells, newest first: the round's own, and
// earlier ones (a week at most) the agent had not said when it started. Only what cleaned something.
func carried(start time.Time, st State) []AutoDone {
	var out []AutoDone
	for _, d := range st.AutoDone {
		if d.Round == nil || (len(d.Tools) == 0 && len(d.Partial) == 0 && len(d.Moved) == 0) {
			continue
		}
		if d.Round.Equal(start) {
			out = append(out, d)
			continue
		}
		if !d.Round.Before(start) || start.Sub(d.At.Time) >= 7*24*time.Hour {
			continue
		}
		if d.Told == nil || !d.Told.Before(start) { // said during this round: still on its item until the next
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At.Time) })
	return out
}

// roundBody is the round's card below its heading: what was cleaned, then what waits for the user; its title and summary.
func (s *Service) roundBody(c *Card, r core.Report, st State, told []AutoDone, f []core.Finding, decide bool, id string) (string, string) {
	var titles []string
	summary := ""
	if len(told) > 0 {
		t, sm := s.toldBody(c, told)
		titles = append(titles, t)
		summary += sm
	}
	if decide {
		if len(told) > 0 {
			c.Divider()
		}
		t, sm := s.decisionsBody(c, r, st, f, id)
		titles = append(titles, t)
		summary += sm
	}
	// A clean of this round that only failed: said here, not as something done.
	var failed []string
	for _, d := range st.AutoDone {
		if d.Round != nil && d.Round.Equal(r.StartedAt.Time) {
			failed = append(failed, d.Failed...)
		}
	}
	var lines []string
	for _, tool := range uniq(failed) {
		inTold := false
		for _, d := range told {
			if contains(d.Failed, tool) {
				inTold = true
			}
		}
		if !inTold {
			lines = append(lines, tool)
		}
	}
	if len(lines) > 0 {
		line := strings.Join(lines, "、") + " 的缓存没清成（它自己的清理命令出错了），下次再试。"
		c.Text(line, true)
		summary += line
	}
	return strings.Join(titles, "；"), summary
}

// toldBody is the top of the round's card: the newest automatic cleans in full, older ones as a line.
func (s *Service) toldBody(c *Card, told []AutoDone) (string, string) {
	var titles []string
	summary := ""
	for i, d := range told {
		if i >= maxToldCleans {
			break
		}
		if i > 0 {
			c.Divider()
		}
		t, sm := s.autoDoneBody(c, d, i == 0)
		titles = append(titles, t)
		summary += sm
	}
	if len(told) > maxToldCleans {
		line := fmt.Sprintf("更早还有 %d 次自动清，记在清理记录里。", len(told)-maxToldCleans)
		c.Text(line, true)
		summary += line
	}
	return strings.Join(titles, "；"), summary
}

// roundRedraw: for a tool answering a click on the round's card ([放回], [以后别自动清], [以后自动清]): the card as it
// is now, to draw under the answer, and whether something on it still waits for the user. nil when the click came
// from another card, or the round's item is done with.
func (s *Service) roundRedraw(meta O) *redraw {
	ua, _ := meta[UserAction].(map[string]any)
	sid, _ := ua["surfaceId"].(string)
	r := s.Store.LastReport()
	if sid == "" || r == nil {
		return nil
	}
	st, id := s.state(), roundID(*r)
	if a, ok := st.Acks[id]; sid != roundSurface(id) || (ok && a.State != "shown") {
		return nil
	}
	told, f := carried(r.StartedAt.Time, st), s.visible(*r, st)
	below := belowCleans(f)
	if len(told) == 0 && !below {
		return nil
	}
	waits := false
	for _, x := range f {
		if x.Verdict != core.Info { // the serious ones only for reference are read, not decided
			waits = true
		}
	}
	report := *r
	return &redraw{body: func(c *Card) {
		c.Divider()
		s.roundBody(c, report, st, told, f, below, id)
	}, waits: waits}
}

// roundTop: for the answer to the plan on the round's card: the cleans on top of it again, so their [放回] stays.
func (s *Service) roundTop(plan Plan) func(*Card) {
	r := s.Store.LastReport()
	if r == nil || plan.OutboxID != roundID(*r) {
		return nil
	}
	told := carried(r.StartedAt.Time, s.state())
	if len(told) == 0 {
		return nil
	}
	return func(c *Card) {
		s.toldBody(c, told)
		c.Divider()
	}
}

// decisionsBody is what waits for the user, with the clean-up plan; its title and summary. Every finding the title
// counts is on the card (in a plan, among the grants to take back, or listed with what to do); so are the serious ones
// only for reference.
func (s *Service) decisionsBody(c *Card, r core.Report, st State, f []core.Finding, id string) (string, string) {
	count := map[core.Verdict]int{}
	for _, x := range f {
		count[x.Verdict]++
	}
	p, admin := s.plans(f, r, "findings", id)
	// The title says what the card's button does as preselected: these go, the rest wait for the user.
	var trash []PlanItem
	if p != nil {
		for _, it := range p.Items {
			if Clears(it.Suggested) {
				trash = append(trash, it)
			}
		}
	}
	var bytes int64
	for _, it := range trash {
		if it.Bytes != nil {
			bytes += *it.Bytes
		}
	}
	toLook := len(f) - count[core.Info] - len(trash)
	var grants []core.Finding
	for _, x := range f {
		if x.Rule == "permission.stale-grant" && len(grants) < 5 {
			grants = append(grants, x)
		}
	}
	// What the title counts that is neither in a plan nor among the grants: what no plan can carry.
	onCard := map[string]bool{}
	for _, pl := range []*Plan{p, admin} {
		if pl != nil {
			for _, it := range pl.Items {
				onCard[it.FindingID] = true
			}
		}
	}
	for _, g := range grants {
		onCard[s.fid(g)] = true
	}
	var own, high []core.Finding
	for _, x := range f {
		if x.Verdict != core.Info && !onCard[s.fid(x)] {
			own = append(own, x)
		}
		if isHighInfo(x) {
			high = append(high, x)
		}
	}
	own = bySeverity(own)
	title := roundHeadline(len(trash), bytes, toLook+len(high))
	summary := fmt.Sprintf("放心删 %d 条、要确认 %d 条、仅供参考 %d 条", count[core.Safe], count[core.Confirm], count[core.Info])
	if len(high) > 0 {
		summary += fmt.Sprintf("（其中需要留意的 %d 条）", len(high))
	}
	summary += "。"
	if len(r.Skipped) > 0 {
		summary += fmt.Sprintf("有 %d 项没查成。", len(r.Skipped))
	}
	// 以后自动清 sits next to 按这个处理 when there is a plan, else on its own row.
	var auto []Button
	if st.AutocleanOff != nil {
		for _, x := range f {
			if x.Category == core.CatCache && x.Verdict == core.Safe {
				auto = []Button{{Label: "以后自动清", Event: "scan_autoclean", Context: O{"on": true}}}
				break
			}
		}
	}
	if p != nil {
		s.planBody(c, *p, title, "会自动重建的缓存直接删掉，别的放心删的移到废纸篓，要你确认的先不动。", f, auto...)
		auto = nil
	} else {
		c.Heading(title)
	}
	if admin != nil {
		s.adminBody(c, *admin)
	}
	if len(auto) > 0 {
		c.Buttons(auto)
	}
	if len(grants) > 0 {
		c.Divider()
		c.Text("这几个应用已经删了，权限还留着，可以在系统设置里移除：", true)
		for _, g := range grants {
			c.Text(g.Title)
			if gs, ok := g.Evidence["grants"]; ok {
				first := strings.Split(gs, "、")[0]
				c.Buttons([]Button{{Label: "打开「" + first + "」设置", Event: "scan_open_settings", Context: O{"grant": first}}})
			}
		}
	}
	unlisted := s.listBody(c, own, "这几样螺壳不替你动，你可以自己看看：") + s.listBody(c, high, "这几条值得留意，有空看一下：")
	if unlisted > 0 {
		c.Text(fmt.Sprintf("还有 %d 条这里放不下，问我就列给你。", unlisted), true)
	}
	if info := count[core.Info] - len(high); info > 0 {
		c.Text(fmt.Sprintf("另有 %d 条仅供参考，问我就列给你。", info), true)
	}
	return title, summary
}

// roundHeadline: what a round found, in one line: how much can go right away, and how many things are worth a look.
func roundHeadline(safe int, bytes int64, toLook int) string {
	var title string
	switch {
	case safe > 0 && bytes > 0:
		title = "能清出 " + core.FormatBytes(bytes)
	case safe > 0:
		title = fmt.Sprintf("能放心删的 %d 项", safe)
	}
	switch {
	case toLook > 0 && title != "":
		title += fmt.Sprintf("，另外有 %d 件事值得看一眼", toLook)
	case toLook > 0:
		title = fmt.Sprintf("有 %d 件事值得看一眼", toLook)
	}
	return title
}

// bySeverity: higher severity first, else as the report has them.
func bySeverity(f []core.Finding) []core.Finding {
	out := append([]core.Finding(nil), f...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}

// listBody: findings no plan carries, one by one with what to do. No button deletes anything. As many as the card
// holds (room is left for the lines after it); how many were not listed.
func (s *Service) listBody(c *Card, fs []core.Finding, note string) int {
	room := CardMaxComponents - 3 // what did not fit, what is only for reference, a failed clean
	if len(fs) == 0 || c.Count()+2+listedCost > room {
		return len(fs)
	}
	c.Divider()
	c.Text(note, true)
	listed := 0
	for i, f := range fs {
		if i >= maxListed || c.Count()+listedCost > room {
			break
		}
		c.Text(withSize(f.Title, f.Bytes))
		if line, ok := listedDetail(f); ok {
			c.Text(line, true)
		}
		if b := s.listButtons(f); len(b) > 0 {
			c.Buttons(b)
		}
		listed++
	}
	return len(fs) - listed
}

// listedDetail: the line under a listed finding: whose folder it is and the plain words, when the model said; what
// to do; else why; the note on a skill. One caption.
func listedDetail(f core.Finding) (string, bool) {
	_, explained := f.Evidence[explainNoteKey]
	var rule string
	if how, ok := f.Evidence["how"]; ok {
		rule = "怎么办：" + how
	} else if !explained {
		if why, ok := f.Evidence["why"]; ok {
			rule = why
		} else {
			rule = f.Evidence["hint"]
		}
	}
	var lines []string
	for _, l := range []string{f.Evidence[identifyNoteKey], f.Evidence[explainNoteKey], rule, f.Evidence[skillReviewNoteKey]} {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return "", false
	}
	return strings.Join(lines, "\n"), true
}

// listButtons: its page in System Settings where it has one, and the Finder where there is something to show.
func (s *Service) listButtons(f core.Finding) []Button {
	var b []Button
	switch {
	case f.Rule == "permission.stale-grant" && f.Evidence["grants"] != "":
		g := strings.Split(f.Evidence["grants"], "、")[0]
		b = append(b, Button{Label: "打开「" + g + "」设置", Event: "scan_open_settings", Context: O{"grant": g}})
	case f.Rule == "keyboard.unvouched":
		b = append(b, Button{Label: "打开「输入监控」设置", Event: "scan_open_settings", Context: O{"grant": "输入监控"}})
	case f.Rule == "persistence.new" && f.Evidence["scope"] == "login-item":
		b = append(b, Button{Label: "打开「登录项」设置", Event: "scan_open_settings", Context: O{"grant": loginItemsGrantName}})
	}
	if strings.HasPrefix(f.Path, "/") && f.Rule != "process.deleted-binary" && f.Rule != "permission.stale-grant" {
		b = append(b, Button{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(f)}})
	}
	return b
}

// accessItems: checks that could not run for lack of a permission only the user can give, also one not allowed for this
// app: it is needed again, and the card is how the user is asked.
func (s *Service) accessItems(r core.Report) []O {
	need := false
	for _, x := range r.Skipped {
		if strings.Contains(x.Reason, "完全磁盘访问") {
			need = true
		}
	}
	if !need {
		return nil
	}
	id := "needs-access/full-disk-access"
	summary := "给「螺壳」打开「完全磁盘访问」就能查，删掉的应用留下的数据和权限也会一起查。"
	c := NewCard("access-" + core.ShortHash(id))
	c.Heading("下载、文稿、桌面还没查")
	c.Text(summary, true)
	c.Buttons([]Button{{Label: "打开设置", Event: "scan_open_settings", Context: O{"grant": "完全磁盘访问"}, Primary: true}})
	return []O{s.item(id, "needs-access", "low", r.FinishedAt.Time, "这一轮有一项因为它没查成", "下载、文稿、桌面还没查", summary, c.Messages(), nil, "fda")}
}

func kindLabel(k string) string { return core.AutoKind(k).Label() }

// autoDoneBody: what was cleaned without a click; its title and summary. Caches were deleted; the rest went to the
// Trash and come back with 「放回」 (the whole batch). offerStop: with [以后别自动清].
func (s *Service) autoDoneBody(c *Card, d AutoDone, offerStop bool) (string, string) {
	cleaned := uniq(append(append([]string(nil), d.Tools...), d.Partial...))
	summary := ""
	if len(cleaned) > 0 {
		summary = "清了 " + core.FormatBytes(d.Bytes) + " 的工具缓存（" + strings.Join(cleaned, "、") + "），用到时会重新下载。"
	}
	if len(d.Moved) > 0 {
		var parts []string
		for _, m := range d.Moved {
			parts = append(parts, fmt.Sprintf("%s %d 项（%s）", kindLabel(m.Kind), m.Items, core.FormatBytes(m.Bytes)))
		}
		summary += "移到废纸篓：" + strings.Join(parts, "、") + "。"
	}
	if len(d.Partial) > 0 {
		summary += "其中 " + strings.Join(d.Partial, "、") + " 的只清掉了一部分（有文件删不掉），下次再试。"
	}
	if len(d.Failed) > 0 {
		summary += strings.Join(d.Failed, "、") + " 的缓存没清成（它自己的清理命令出错了），下次再试。"
	}
	// What went to the Trash is not freed until the Trash is emptied: said apart from the caches.
	count, size := 0, int64(0)
	for _, m := range d.Moved {
		count += m.Items
		size += m.Bytes
	}
	var title string
	switch {
	case len(d.Moved) == 0 && d.Bytes == 0:
		title = "自动清缓存没清成"
	case len(d.Moved) == 0:
		title = "自动清了 " + core.FormatBytes(d.Bytes) + " 的工具缓存"
	default:
		title = fmt.Sprintf("自动移到废纸篓 %d 项（%s）", count, core.FormatBytes(size))
		if len(cleaned) > 0 {
			title += "，清了 " + core.FormatBytes(d.Bytes) + " 的工具缓存"
		}
	}
	c.Heading(title)
	c.Text(summary)
	for _, m := range d.Moved {
		more := ""
		if m.Items > len(m.Names) {
			more = fmt.Sprintf(" 等 %d 项", m.Items)
		}
		c.Text(kindLabel(m.Kind)+"："+strings.Join(m.Names, "、")+more, true)
	}
	if len(d.Unrecorded) > 0 {
		c.Text("这几项没记进清理记录，要放回得在访达里打开废纸篓："+strings.Join(d.Unrecorded, "、"), true)
	}
	var buttons []Button
	if d.Batch != "" && count > len(d.Unrecorded) {
		buttons = append(buttons, Button{Label: "放回", Event: "scan_restore", Context: O{"id": d.Batch}})
	}
	if offerStop {
		buttons = append(buttons, Button{Label: "以后别自动清", Event: "scan_autoclean", Context: O{"on": false}})
	}
	if len(buttons) > 0 {
		c.Buttons(buttons)
	}
	return title, summary
}
