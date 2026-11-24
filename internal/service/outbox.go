package service

import (
	"fmt"
	"path/filepath"
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
)

// outbox: the report before the state: a round writes what it cleaned to the state before it saves its report, so
// the new report never comes with a state from before it. features: the forms the agent core draws (Features); the
// round's card uses them, the others are drawn as version 1 of the catalog has them.
func (s *Service) outbox(features map[string]bool) any {
	r := s.Store.LastReport()
	return s.outboxOf(s.state(), r, features)
}

func (s *Service) outboxOf(st State, r *core.Report, features ...map[string]bool) O {
	var fs map[string]bool
	if len(features) > 0 {
		fs = features[0]
	}
	items := A{}
	if r != nil {
		for _, group := range [][]O{s.securityItems(*r, st), s.spaceItems(*r, st), s.roundItems(*r, st, fs), s.accessItems(*r)} {
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
		if s.urgentDone(f, r) { // moved, or found gone, with a click this round (wherever): the card goes too
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
		// 大白话：是什么、怎么办；规则名、病毒名、路径留在报告里（负责人 11-06）
		title, advice := s.plain(f)
		c := NewCard("security-" + core.ShortHash(s.fid(f)))
		c.Heading(title)
		c.Text(advice)
		c.Buttons(s.malwareButtons(f, r, id))
		it := s.item(id, "security", "urgent", r.FinishedAt.Time, "这一轮刚认出来；建议先不要打开", title,
			title+"。"+advice, c.Messages(), nil, "")
		it["data"] = s.malwareData(f, r, id)
		out = append(out, it)
	}
	return out
}

// persistenceItem: something new that starts by itself. The user's own LaunchAgent can go from the card (stopped,
// plist to the Trash); a login item is switched off in System Settings; the system's jobs need a password.
func (s *Service) persistenceItem(f core.Finding, id string, r core.Report) O {
	scope, why := f.Evidence["scope"], f.Evidence["why"]
	c := NewCard("security-" + core.ShortHash(s.fid(f)))
	// Named as Login Items names it: the app it belongs to; the program's own name only when that says more.
	app, program := f.Evidence["app"], appName(programName(f.Evidence["program"]))
	submitted := f.Evidence["submitted"] == "1"
	title := "新装了一个会跟着电脑一起启动的程序"
	if submitted {
		title = "有个程序在后台运行"
		if app != "" {
			title = "「" + app + "」在后台起了一个程序"
		}
		if program != "" && program != app {
			title += "「" + program + "」"
		}
	} else if app != "" {
		title += "「" + app + "」"
	} else if program != "" {
		title += "「" + program + "」"
	}
	c.Heading(title)
	mine := "是我装的"
	body := "它会跟着电脑一起启动，这一轮刚出现。"
	var advice string
	switch {
	case submitted:
		body = "它是开着的程序交给系统运行的，这一轮刚出现；重启以后不会再自己起来，所以不在「登录项」里。"
		if app != "" {
			body = "它是「" + app + "」开着时交给系统运行的，这一轮刚出现；重启以后不会再自己起来，所以不在「登录项」里。"
		}
		advice = "如果是你装的应用起的，点「是我装的」就好；不认识的话，点「在访达里显示」看看它是哪个程序。"
	case scope == "user-agent":
		advice = "如果是你自己装的，点「是我装的」就好；不认识的话可以停掉它，配置会移到废纸篓，随时能放回。"
	case scope == "login-item":
		advice = "如果是你自己装的，点「是我装的」就好；不认识的话，在 系统设置 → 通用 → 登录项与扩展 里关掉。"
	case scope == "cron":
		mine = "是我加的"
		advice = "如果是你自己加的，点「是我加的」就好；不认识的话，点「在访达里显示」看看它运行的是哪个程序，把那个程序移到废纸篓。"
	default:
		advice = "如果是你自己装的，点「是我装的」就好；不认识的话，在访达里找到它移到废纸篓（会要你的密码）。"
	}
	c.Text(body + advice)
	buttons := []Button{{Label: mine, Event: "scan_ignore", Context: O{"finding_id": s.fid(f)}, Primary: true}}
	if f.Path != "" {
		buttons = append(buttons, Button{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(f)}})
	}
	switch {
	case submitted: // not in Login Items, and not the user's LaunchAgent to stop
	case scope == "user-agent":
		if p := s.plan([]core.Finding{f}, r, "security", id, false); p != nil {
			buttons = append(buttons, Button{Label: "停掉它", Event: "scan_apply",
				Context: O{"plan_id": p.ID, "choices": O{"i0": A{ChoiceTrash}}}})
		}
	case scope == "login-item":
		buttons = append(buttons, Button{Label: "打开「登录项」设置", Event: "scan_open_settings", Context: O{"grant": loginItemsGrantName}})
	}
	c.Buttons(buttons)
	about := "这一轮新加的、会自己启动的程序（" + why + "）"
	if submitted {
		about = "这一轮新加的、在后台运行的程序（" + why + "）"
	}
	it := s.item(id, "security", "urgent", r.FinishedAt.Time, about, title,
		title+"。"+body+advice, c.Messages(), nil, "")
	it["data"] = s.startupData(f, r, id)
	return it
}

// maliciousPackageItem: a project or a global install uses a known malicious package. What to do is written out (take
// the dependency out, move to a version not on the list, change the keys and tokens); the card offers to show the
// lockfile in Finder, never to delete anything of the project's. The rule gives one finding per package (every place
// it is used listed in it) and a handful at most, the rest as one more: so a package in thirty projects is one card.
func (s *Service) maliciousPackageItem(f core.Finding, id string, r core.Report) O {
	// 大白话（负责人 11-06）：名单、编号、位置和「怎么办」的命令都在报告里
	title, advice := s.plain(f)
	c := NewCard("security-" + core.ShortHash(s.fid(f)))
	c.Heading(title)
	c.Text(advice)
	var buttons []Button
	if strings.HasPrefix(f.Path, "/") {
		buttons = append(buttons, Button{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(f)}, Primary: true})
	}
	buttons = append(buttons, Button{Label: "处理好了，以后别提", Event: "scan_ignore", Context: O{"finding_id": s.fid(f)}})
	c.Buttons(buttons)
	it := s.item(id, "security", "urgent", r.FinishedAt.Time, "这一轮和恶意包名单比对出来的；装过就当令牌和钥匙已经泄露", title,
		title+"。"+advice, c.Messages(), nil, "")
	it["data"] = s.packageData(f)
	return it
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
	p := s.plan(caches, r, "space", id, false)
	if p != nil {
		line := "会自己重建的工具缓存能马上腾出 " + core.FormatBytes(bytes) + "，删了不影响使用。"
		summary += line
		c.Heading(low.Title)
		c.Text(line)
		s.cleanButton(c, *p, "腾出 "+core.FormatBytes(bytes))
	} else {
		c.Heading(low.Title)
		c.Text(summary, true)
	}
	it := s.item(id, "space", "normal", r.FinishedAt.Time, "空间快不够了，满了会影响别的程序", low.Title, summary, c.Messages(), nil, "")
	it["data"] = s.spaceData(*low, bytes, p)
	return []O{it}
}

// roundItems: the round as one item (luoke-agent#2, 10-27). auto-done when there is something on top (every
// automatic clean is told; one the agent has not said yet when the next round starts is carried into that round's
// item); else findings when something waits for the user or is serious; else nothing. Its id is the round's alone.
func (s *Service) roundItems(r core.Report, st State, features map[string]bool) []O {
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
	c := NewCard(roundSurface(id)).Use(features)
	title, summary := s.roundBody(c, r, st, told, f, decide, id)
	data := s.roundData(r, st, told, f, decide, id)
	if len(told) > 0 {
		newest := told[0]
		thisRound := newest.Round != nil && newest.Round.Equal(r.StartedAt.Time)
		why := "不用点就清的几类，前一轮清了"
		if thisRound {
			why = "不用点就清的几类，这一轮清了"
		}
		created := maxTime(newest.At.Time, r.FinishedAt.Time)
		expires := maxTime(newest.At.Add(7*24*time.Hour), r.StartedAt.Add(3*24*time.Hour))
		it := s.item(id, "auto-done", "normal", created, why, title, summary, c.Messages(), &expires, "")
		it["data"] = data
		return []O{it}
	}
	expires := r.StartedAt.Add(3 * 24 * time.Hour)
	it := s.item(id, "findings", "low", r.FinishedAt.Time, "扫描刚查完一轮", title, summary, c.Messages(), &expires, "")
	it["data"] = data
	return []O{it}
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
		line := strings.Join(lines, "、") + " 的缓存没清成（里面的文件删不掉），下次再试。"
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

// roundRedraw: for a tool answering a click on the round's card ([放回], [关掉自动清理], [打开自动清理]): the card as it
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
	report, features := *r, Features(meta)
	// drawn as the outbox draws the round's card for this core; an answer above it stays as it was
	card := func(c *Card) {
		was := c.features
		c.Use(features)
		s.roundBody(c, report, st, told, f, below, id)
		c.Use(was)
	}
	return &redraw{body: func(c *Card) {
		c.Divider()
		card(c)
	}, card: card, waits: waits, rest: s.roundRest(s.roundView(f, report, id), f, st),
		data: s.roundData(report, st, told, f, below, id)}
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

// roundView: a round's findings sorted for its card and the scan page: the plan (what 「清理」 does as suggested,
// and the choices on the page), the items that need the password, and what waits for the user that no plan carries.
type roundView struct {
	plan, admin *Plan
	trash       []PlanItem     // what the plan clears as suggested
	bytes       int64          // what that frees
	look        []core.Finding // what waits for the user outside the plans (serious ones only for reference too)
	toLook      int            // how many things wait for the user: what the scan page lists but the rebuildable caches (luoke-scan#129)
	caches      []PlanItem     // the rebuildable caches: deleted with their own button, nothing to choose
	cachesBytes int64          // what that one button frees: of bytes, the caches' part (luoke-scan#205)
	cleaned     []PlanItem     // the rebuildable caches the user already had deleted this round (cachesCleaned)
	freed       int64          // what deleting those freed
	high        int
	count       map[core.Verdict]int
	// done: the other items already gone with a click this round (itemsCleaned), from 「今天」's cards or the scan page,
	// or found already gone by one (deleted outside this tool): not offered again, not counted in what can be freed nor
	// in what waits for the user
	done []PlanItem
}

func (s *Service) roundView(f []core.Finding, r core.Report, id string) roundView {
	v := roundView{count: map[core.Verdict]int{}}
	for _, x := range f {
		v.count[x.Verdict]++
	}
	v.plan, v.admin = s.plans(f, r, "findings", id)
	if v.plan != nil {
		gone := s.cachesCleaned(*v.plan, r)
		moved := s.itemsCleaned(*v.plan, r)
		for _, it := range v.plan.Items {
			if it.Suggested == ChoiceRemove {
				if b, ok := gone[it.Key]; ok {
					v.cleaned = append(v.cleaned, it)
					v.freed += b
					continue
				}
			}
			if moved[it.Key] {
				v.done = append(v.done, it)
				continue
			}
			if Clears(it.Suggested) {
				v.trash = append(v.trash, it)
				if it.Bytes != nil {
					v.bytes += *it.Bytes
				}
			}
			if it.Suggested == ChoiceRemove {
				v.caches = append(v.caches, it)
				if it.Bytes != nil {
					v.cachesBytes += *it.Bytes
				}
			}
		}
	}
	inPlan := map[string]bool{}
	for _, pl := range []*Plan{v.plan, v.admin} {
		if pl != nil {
			for _, it := range pl.Items {
				inPlan[it.FindingID] = true
			}
		}
	}
	for _, x := range f {
		if isHighInfo(x) {
			v.high++
		}
		// Once: what the plan lists (with its own 「移到废纸篓」) is not listed again under 「要你看看」 (AI plugins, models)
		if (x.Verdict != core.Info || isHighInfo(x)) && !inPlan[s.fid(x)] {
			v.look = append(v.look, x)
		}
	}
	v.look = bySeverity(v.look)
	// What waits is what the scan page lists: every item of the plans but the rebuildable caches (nothing to choose) and
	// what already went this round, and what no plan carries (「要你看看」). Counted from those lists, not from the
	// findings' verdicts: a plan also carries items of findings that are only for reference (AI plugins, chat templates),
	// and the page lists them under 「可以清掉」 like the rest, so its numbers add up.
	v.toLook = len(v.look)
	if v.plan != nil {
		for _, it := range v.plan.Items {
			// A setting's state that scan_apply can change when asked (the install-scripts rule) is only for reference:
			// in the plan so that it can be applied, not something that waits for the user.
			if it.Suggested != ChoiceRemove && !hasItem(v.done, it.Key) && it.Rule != core.InstallScriptsRuleID {
				v.toLook++
			}
		}
	}
	if v.admin != nil {
		v.toLook += len(v.admin.Items)
	}
	return v
}

// isDone: the finding's item already went with a click this round (roundView.done).
func (v roundView) isDone(fid string) bool {
	for _, it := range v.done {
		if it.FindingID == fid {
			return true
		}
	}
	return false
}

// cachesCleaned: the rebuildable caches of the round's plan the user already had deleted with a click this round
// (「清理 N 项缓存」 on the round's card, 「清理」 on the scan page), from the clean-up record: deleted for good (not in
// the Trash), not by automatic cleaning, since the round started, the same rule and folder. By item key, with what
// that freed. They are not offered again until the next round finds them. The plan's id is not compared: the plan of
// the same round can change (something on the page put away with 以后别提).
func (s *Service) cachesCleaned(p Plan, r core.Report) map[string]int64 {
	out := map[string]int64{}
	var caches []PlanItem
	for _, it := range p.Items {
		if it.Suggested == ChoiceRemove {
			caches = append(caches, it)
		}
	}
	if len(caches) == 0 {
		return out
	}
	for _, e := range s.Cleaned() {
		if e.Auto != nil || e.Trashed != nil || e.Wrote != nil || e.At.Before(r.StartedAt.Time) || !strings.HasPrefix(e.Batch, "p-") {
			continue
		}
		for _, it := range caches {
			for _, t := range it.Targets {
				if e.Rule == it.Rule && e.Original == t.Path {
					b := int64(0)
					if e.Bytes != nil {
						b = *e.Bytes
					}
					out[it.Key] += b
				}
			}
		}
	}
	return out
}

// itemsCleaned: the items of the round's plan that already went with a click this round, wherever the user clicked
// (an urgent card or the round's card in 「今天」, the scan page). By item key. The round's report still lists them until
// the next round looks again; offered again they would only come back 「找不到，已跳过」. Either way:
//   - every place the item would move or change has a record in the clean-up record since the round started, by a plan
//     (not automatic cleaning), the same rule, not put back; matched by where it was (as written, or its folders' links
//     resolved as the record has it) or by what it was (device and inode, when the plan has them);
//   - or a click found it already gone (State.Gone, deleted outside this tool) since the round started, and nothing of
//     it was put back since.
func (s *Service) itemsCleaned(p Plan, r core.Report) map[string]bool {
	type ident struct {
		dev int64
		ino uint64
	}
	at, by := map[string]bool{}, map[ident]string{}
	back := map[string]time.Time{} // rule and where it was → when it was last put back
	for _, e := range s.Cleaned() {
		if e.Restored != nil {
			if k := e.Rule + "\x00" + e.Original; e.Restored.After(back[k]) {
				back[k] = e.Restored.Time
			}
		}
		if e.Auto != nil || e.Restored != nil || e.At.Before(r.StartedAt.Time) || !strings.HasPrefix(e.Batch, "p-") {
			continue
		}
		at[e.Rule+"\x00"+e.Original] = true
		if e.Inode != 0 {
			by[ident{e.Device, e.Inode}] = e.Rule
		}
	}
	gone := s.state().Gone
	out := map[string]bool{}
	if len(at) == 0 && len(gone) == 0 {
		return out
	}
	for _, it := range p.Items {
		all := len(it.Targets) > 0
		var putBack time.Time
		for _, t := range it.Targets {
			canonical := core.Canonical(filepath.Dir(t.Path)) + "/" + filepath.Base(t.Path)
			rule, known := by[ident{t.Device, t.Inode}]
			all = all && (at[it.Rule+"\x00"+t.Path] || at[it.Rule+"\x00"+canonical] || t.Inode != 0 && known && rule == it.Rule)
			for _, k := range []string{it.Rule + "\x00" + t.Path, it.Rule + "\x00" + canonical} {
				if back[k].After(putBack) {
					putBack = back[k]
				}
			}
		}
		g, wasGone := gone[it.FindingID]
		if all || wasGone && !g.Before(r.StartedAt.Time) && !putBack.After(g.Time) {
			out[it.Key] = true
		}
	}
	return out
}

// urgentDone: an urgent finding's item already went this round (itemsCleaned on its own plan, the one its card and the
// scan page's row click): moved by a click, or a click found it gone.
func (s *Service) urgentDone(f core.Finding, r core.Report) bool {
	p := s.plan([]core.Finding{f}, r, "security", "security/"+s.fid(f), false)
	return p != nil && len(p.Items) == 1 && s.itemsCleaned(*p, r)[p.Items[0].Key]
}

// roundRest: how many things the round's card sends to the scan page (「另外 N 项」, 「去扫描页看 N 项」): what waits
// for the user but what the urgent cards in 「今天」 already ask about.
func (s *Service) roundRest(v roundView, f []core.Finding, st State) int {
	urgent := 0
	for _, x := range f {
		if isUrgent(x) && !v.isDone(s.fid(x)) { // done: toLook already leaves it out
			if a, ok := st.Acks["security/"+s.fid(x)]; !ok || a.State == "shown" {
				urgent++
			}
		}
	}
	return v.toLook - urgent
}

// decisionsBody is the round's card for the user (负责人 11-06：一句结论、一个按钮; luoke-scan#129): how much can be
// freed, that the rebuildable caches need no choosing and how many other things wait in the scan page, and a button
// that deletes just the caches. The items, their choices and what to do with each are on the page (page/overview);
// paths, ids, rule names and 「仅供参考」 are only in the report. Its title and summary.
func (s *Service) decisionsBody(c *Card, r core.Report, st State, f []core.Finding, id string) (string, string) {
	v := s.roundView(f, r, id)
	rest := s.roundRest(v, f, st) // 「今天」上面已经有急事卡的不再算进「另外 N 项」
	title := roundHeadline(len(v.trash), v.bytes, 0)
	if title == "" {
		title = fmt.Sprintf("%d 项等你处理", v.toLook)
	}
	c.Heading(title)
	// Where the core opens the tool's own pages (§4 openPage), what waits on the scan page is a button that goes there
	// (「去扫描页看 N 项」) instead of a line that names it. The summary says it either way: it is read without the card.
	openPage := c.Has("openPage")
	var parts, drawn []string
	if len(v.cleaned) > 0 { // after 「清理 N 项缓存」 the card stays while the rest waits: it says the caches went
		p := fmt.Sprintf("已删掉会重建的缓存 %d 项", len(v.cleaned))
		if v.freed > 0 {
			p += "（腾出 " + core.FormatBytes(v.freed) + "）"
		}
		parts = append(parts, p)
		drawn = append(drawn, p)
	}
	if len(v.caches) > 0 {
		parts = append(parts, fmt.Sprintf("会重建的缓存 %d 项，不用你选", len(v.caches)))
		drawn = append(drawn, parts[len(parts)-1])
	}
	if rest > 0 {
		parts = append(parts, fmt.Sprintf("另外 %d 项在「螺壳扫描」里等你看", rest))
		if !openPage {
			drawn = append(drawn, parts[len(parts)-1])
		}
	}
	line := ""
	if len(parts) > 0 {
		line = strings.Join(parts, "；") + "。"
	}
	if len(drawn) > 0 {
		c.Text(strings.Join(drawn, "；")+"。", true)
	}
	var buttons []Button
	if v.plan != nil && len(v.caches) > 0 {
		only := O{}
		for _, it := range v.plan.Items {
			c.Defaults(it.Key, ChoiceKeep)
		}
		for _, it := range v.caches {
			only[it.Key] = A{ChoiceRemove}
		}
		buttons = append(buttons, Button{Label: fmt.Sprintf("清理 %d 项缓存", len(v.caches)), Event: "scan_apply",
			Context: O{"plan_id": v.plan.ID, "choices": only}, Primary: true})
	}
	if rest > 0 && openPage {
		buttons = append(buttons, Button{Label: fmt.Sprintf("去扫描页看 %d 项", rest), Event: "agent.open_page",
			Context: O{"page": "overview"}, Primary: len(buttons) == 0})
	}
	if buttons = append(buttons, s.autoButton(f, st)...); len(buttons) > 0 {
		c.Buttons(buttons)
	}
	summary := line
	for _, l := range skippedLines(r) {
		summary += l.text + "。"
	}
	return roundHeadline(len(v.trash), v.bytes, rest), summary
}

// cleanButton: one button that applies the plan as suggested. The choices are in the card's data model, not drawn.
func (s *Service) cleanButton(c *Card, p Plan, label string, extra ...Button) {
	for _, it := range p.Items {
		c.Defaults(it.Key, it.Suggested)
	}
	c.Buttons(append([]Button{{Label: label, Event: "scan_apply", Context: O{"plan_id": p.ID, "choices": ChoicesPath}, Primary: true}}, extra...))
}

// autoButton: 「打开自动清理」 while automatic cleaning is off and there are rebuildable caches to clean.
func (s *Service) autoButton(f []core.Finding, st State) []Button {
	if st.AutocleanOff == nil {
		return nil
	}
	for _, x := range f {
		if x.Category == core.CatCache && x.Verdict == core.Safe {
			return []Button{{Label: "打开自动清理", Event: "scan_autoclean", Context: O{"on": true}}}
		}
	}
	return nil
}

// skipped: what a round could not check, by reason, in the user's words: what lacks Full Disk Access waits for the
// user (not for the next round, luoke-scan#114); the virus database not yet downloaded comes by itself.
type skipped struct {
	text  string
	grant string // the System Settings page that fixes it, or ""
}

func skippedLines(r core.Report) []skipped {
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
	var out []skipped
	if fda > 0 {
		out = append(out, skipped{fmt.Sprintf("有 %d 项要打开「完全磁盘访问」才能查", fda), "完全磁盘访问"})
	}
	if db > 0 {
		out = append(out, skipped{"病毒库还在准备，准备好了再查", ""})
	}
	if other > 0 {
		out = append(out, skipped{fmt.Sprintf("有 %d 项这次没查成，下一轮再试", other), ""})
	}
	return out
}

// roundHeadline: what a round found, in one line: how much can go right away, and how many things are worth a look.
func roundHeadline(safe int, bytes int64, toLook int) string {
	var title string
	switch {
	case safe > 0 && bytes > 0:
		title = "能清出 " + core.FormatBytes(bytes) // 算的是建议清的那些（缓存，和扫描页上默认移到废纸篓的）
	case safe > 0:
		title = fmt.Sprintf("能放心删的 %d 项", safe)
	}
	switch {
	case toLook > 0 && title != "":
		title += fmt.Sprintf("，另外 %d 项等你处理", toLook)
	case toLook > 0:
		title = fmt.Sprintf("%d 项等你处理", toLook) // 和「12 项等你处理，其中 2 项要尽快」同一个写法
	}
	return title
}

// bySeverity: higher severity first, else as the report has them.
func bySeverity(f []core.Finding) []core.Finding {
	out := append([]core.Finding(nil), f...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}

// listButtons: its page in System Settings where it has one, and the Finder where there is something to show.
func (s *Service) listButtons(f core.Finding) []Button {
	var b []Button
	switch {
	case f.Rule == "permission.stale-grant" && f.Evidence["grants"] != "":
		// One page each: the app is in each of these lists, and each needs its own 「−」
		for _, g := range strings.Split(f.Evidence["grants"], "、") {
			b = append(b, Button{Label: "打开「" + g + "」", Event: "scan_open_settings", Context: O{"grant": g}})
		}
	case f.Rule == "posture.filevault":
		b = append(b, Button{Label: "打开 FileVault 设置", Event: "scan_open_settings", Context: O{"grant": "FileVault"}})
	case f.Rule == "keyboard.unvouched":
		b = append(b, Button{Label: "打开「输入监控」设置", Event: "scan_open_settings", Context: O{"grant": "输入监控"}})
	case isVitals(f):
		b = append(b, vitalsButton(f))
	case f.Category == core.CatPersistence && !strings.HasPrefix(f.Rule, "browser.") && f.Evidence["scope"] != "cron",
		strings.HasPrefix(f.Rule, "startup."):
		// 系统设置的「登录项与扩展」里列着开机启动的程序和后台项目，开关在那里（luoke-scan#129：给一件能做的事，不让用户去找别人）
		b = append(b, Button{Label: "在登录项里管理", Event: "scan_open_settings", Context: O{"grant": loginItemsGrantName}})
	}
	if strings.HasPrefix(f.Path, "/") && f.Rule != "process.deleted-binary" && f.Rule != "permission.stale-grant" && !isVitals(f) {
		b = append(b, Button{Label: "在访达里显示", Event: "scan_reveal", Context: O{"finding_id": s.fid(f)}})
	}
	return b
}

// malwareButtons: what a file the virus database or YARA recognised gets, on its urgent card and on the scan page:
// 「移到废纸篓」 (the user's own click; plans never trash it by default) and 「不是病毒」. No 「在访达里显示」: it takes
// a non-technical user right next to the file, where a curious double-click opens it (design review 11-07).
func (s *Service) malwareButtons(f core.Finding, r core.Report, id string) []Button {
	var b []Button
	if p := s.plan([]core.Finding{f}, r, "security", id, false); p != nil {
		b = append(b, Button{Label: "移到废纸篓", Event: "scan_apply",
			Context: O{"plan_id": p.ID, "choices": O{"i0": A{ChoiceTrash}}}, Primary: true, Icon: "trash"})
	}
	return append(b, Button{Label: "不是病毒", Event: "scan_ignore", Context: O{"finding_id": s.fid(f)}})
}

// accessItems: checks that could not run for lack of a permission only the user can give, also one not allowed for this
// app: it is needed again, and the card is how the user is asked.
func (s *Service) accessItems(r core.Report) []O {
	if s.Config.FullDiskAccess != nil { // allowed since that round: the card goes now, not a round later (luoke-scan#101)
		if now := s.Config.FullDiskAccess(); now != nil && *now {
			return nil
		}
	}
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
	it := s.item(id, "needs-access", "low", r.FinishedAt.Time, "这一轮有一项因为它没查成", "下载、文稿、桌面还没查", summary, c.Messages(), nil, "fda")
	it["data"] = O{"type": "needs-access", "permission": "fda"}
	return []O{it}
}

func kindLabel(k string) string { return core.AutoKind(k).Label() }

// autoDoneBody: what was cleaned without a click; its title and summary. Caches were deleted; the rest went to the
// Trash and come back with 「放回」 (the whole batch). offerStop: with [关掉自动清理].
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
		summary += strings.Join(d.Failed, "、") + " 的缓存没清成（里面的文件删不掉），下次再试。"
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
		var names []string
		for _, n := range m.Names {
			if t := friendlyName(n); !contains(names, t) {
				names = append(names, t)
			}
		}
		c.Text(kindLabel(m.Kind)+"："+andMore(strings.Join(names, "、"), len(names), m.Items), true)
	}
	if len(d.Unrecorded) > 0 {
		c.Text("这几项没记进清理记录，要放回得在访达里打开废纸篓："+strings.Join(d.Unrecorded, "、"), true)
	}
	var buttons []Button
	if d.Batch != "" && count > len(d.Unrecorded) {
		buttons = append(buttons, Button{Label: "放回", Event: "scan_restore", Context: O{"id": d.Batch}})
	}
	if offerStop {
		buttons = append(buttons, Button{Label: "关掉自动清理", Event: "scan_autoclean", Context: O{"on": false}})
	}
	if len(buttons) > 0 {
		c.Buttons(buttons)
	}
	return title, summary
}
