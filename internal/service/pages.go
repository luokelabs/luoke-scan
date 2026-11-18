package service

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// What the window shows of this tool besides cards (luoke-agent#3): the summary in the sidebar, the state of the
// permissions, and two base pages the window draws from A2UI. Read by relative id (summary, permissions, page/<id>).

var basePages = []struct{ id, title string }{{"overview", "概览"}, {"mac", "状态"}, {"cleaned", "清理记录"}}

// maxRecordBatches is the most batches the clean-up record page lists (a batch takes 6 components).
const maxRecordBatches = 20

func (s *Service) registerPages() {
	srv := s.Server
	srv.ResourceMeta("outbox", "扫描要告诉你的事", func(meta O) any { return s.outbox(Features(meta)) })
	srv.Resource("summary", "概览", func() any { return s.summaryNow(s.state()) })
	srv.Resource("permissions", "权限的状态", func() any { return s.permissionStates(s.state()) })
	for _, p := range basePages {
		id := p.id
		srv.ResourceMeta("page/"+id, p.title, func(meta O) any { return A(s.page(id, s.state(), Features(meta))) })
	}
	s.registerData()
}

// summary: {"count", "text"}: what waits for the user (the count by the sidebar) and one sentence on it. The serious
// ones only for reference count too; the rest only for reference does not.
func (s *Service) summary(st State) O {
	r := s.Store.LastReport()
	if r == nil {
		return O{"count": 0, "text": "还没查过这台 Mac"}
	}
	all := s.visible(*r, st)
	var f []core.Finding
	high := 0
	for _, x := range all {
		if x.Verdict != core.Info {
			f = append(f, x)
		}
		if isHighInfo(x) {
			high++
		}
	}
	// The round's card and the scan page count from roundView (what the plan clears, what waits on the page): so does
	// this, or the sidebar says one size and number and the card another.
	v := s.roundView(all, *r, roundID(*r))
	// As the outbox counts them: one the user acted on or put away is not urgent any more, nor one already gone
	urgent := 0
	for _, x := range f {
		if isUrgent(x) && !v.isDone(s.fid(x)) {
			if a, ok := st.Acks["security/"+s.fid(x)]; !ok || a.State == "shown" {
				urgent++
			}
		}
	}
	count := len(f) + high
	for _, x := range all {
		if v.isDone(s.fid(x)) && (x.Verdict != core.Info || isHighInfo(x)) {
			count-- // already went with a click this round, as the page no longer lists it
		}
	}
	var text string
	switch {
	case urgent > 0:
		// 和扫描页统计的「等你处理」同一个数、同一个量词：总数在前，急的是其中几样（「要你看看」只指那一段）
		text = fmt.Sprintf("%d 项等你处理，其中 %d 项要尽快", v.toLook, urgent)
	case len(f) == 0 && high == 0:
		text = "没有要你处理的"
	default:
		// what this round found may all have gone with clicks since (roundView.done): nothing left is said as none found
		if text = roundHeadline(len(v.trash), v.bytes, v.toLook); text == "" {
			text = "没有要你处理的"
		}
	}
	return O{"count": count, "text": text}
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

// page is a base page's A2UI messages; the surface is the page's id. features: the forms the agent core draws
// (Features); none, the page as version 1 of the catalog has it.
func (s *Service) page(id string, st State, features ...map[string]bool) []any {
	c := NewCard(id)
	if len(features) > 0 {
		c.Use(features[0])
	}
	if id == "overview" {
		c.Page() // the scan page as in the design (luoke-scan#129): a card per part where the core draws pages that way
	}
	switch id {
	case "overview":
		s.overviewPage(c, st)
	case "mac":
		s.macPage(c, st)
	case "cleaned":
		s.cleanedPage(c)
	default:
		c.Text("没有这一页")
	}
	return c.Messages()
}

// What the overview page shows before 「还有 N 类」 / 「还有 N 项」 (the rest follow it, folded where the core draws
// that). How the card's 200 components are shared is worked out in overviewPage from what each part takes.
const (
	pageLookFirst   = 5
	pageDecideFirst = 8
)

// overviewPage: the scan page for someone who does not know computers (负责人 11-06; luoke-scan#114, #129): three
// numbers; what has to go soon (viruses); what can go, the rebuildable caches in one line with their own button and every
// other item with a choice and a line that says what it is; then what waits for the user in plain words (similar things
// in one line, each with something to do); what could not be checked and why. Counted in 项 (things) and 类 (lines of
// similar things). No paths, ids, rule names, signatures, commands, nor what is only for reference.
func (s *Service) overviewPage(c *Card, st State) {
	r := s.Store.LastReport()
	if r == nil {
		c.Heading("扫描")
		c.Text("还没查过这台 Mac。")
		if !s.scanningRow(c, nil) {
			c.Buttons([]Button{{Label: "现在查一下", Event: "scan_now", Primary: true}})
		}
		return
	}
	// The first line as in the design (luoke-scan#129): the title, when it last looked and 「现在查一下」 (not while a
	// round runs), the numbers under it.
	var again []Button
	if !s.IsScanning() {
		again = []Button{{Label: "现在查一下", Event: "scan_now"}}
	}
	c.PageHead("扫描", "上次查 "+localTime(r.StartedAt.Time), again)
	s.scanningRow(c, r) // 正在查的这一轮：一行带进度条（luoke-scan#101）
	f := s.visible(*r, st)
	id := roundID(*r)
	v := s.roundView(f, *r, id)
	var week int64
	for _, e := range s.Cleaned() {
		if e.Bytes != nil && s.now().Sub(e.At.Time) < 7*24*time.Hour && e.Restored == nil {
			week += *e.Bytes
		}
	}
	bytesOr := func(b int64, none string) string {
		if b <= 0 {
			return none
		}
		return core.FormatBytes(b)
	}
	glance := func() {
		c.Stats([]Stat{{"这周清掉", bytesOr(week, "还没清过")}, {"能清出", bytesOr(v.bytes, "没有")}, {"等你处理", fmt.Sprintf("%d 项", v.toLook)}})
	}
	// The numbers go to a wide window's side column when something below waits for the user, so that follows the
	// first line in the main column; with nothing below they stay in the main column, which would be empty.
	waits := (v.plan != nil && len(v.plan.Items) > len(v.cleaned)+len(v.done)) || v.admin != nil || len(groupLook(v.look)) > 0 || len(skippedLines(*r)) > 0
	for _, x := range f {
		waits = waits || isMalware(x) && !v.isDone(s.fid(x))
	}
	if waits {
		c.Aside(glance)
	} else {
		glance()
	}

	about := map[string]core.Finding{}
	for _, x := range f {
		about[s.fid(x)] = x
	}
	// 要尽快处理的（病毒）放在最上面，按钮和「今天」的急事卡一样；清理方案里不再给它画选择框（design review 11-07：
	// 排在缓存中间、预选「先不动」，像是可以随手清的东西）。这一轮已经点过移走的（在「今天」的急事卡上、在这一页）不再列
	nUrgent := 0
	for _, x := range f {
		if isMalware(x) && !v.isDone(s.fid(x)) {
			nUrgent++
		}
	}
	urgent := map[string]bool{}
	if nUrgent > 0 {
		c.Part(func() {
			c.Divider()
			c.SectionCount("triangle-alert", "要尽快处理", nUrgent)
			c.List(func() {
				for _, x := range f {
					if isMalware(x) && !v.isDone(s.fid(x)) {
						urgent[s.fid(x)] = true
						title, advice := s.plain(x)
						icon, _ := ruleIcon(x.Rule)
						// what to do with it now, read whole (not cut to one line)
						// 和「今天」的急事卡同一份方案、同一件（security/…）：哪边点了，那张卡都算答了
						c.ItemButtons(icon, title, []ItemLine{{Text: advice, Whole: true}}, s.malwareButtons(x, *r, "security/"+s.fid(x)))
					}
				}
			})
		})
	}
	// A deleted program still running and its startup item: by the program's file name (or the label's last part, as
	// before), to what the list above calls the item.
	startsByItself := map[string]string{}
	for _, x := range f {
		if x.Category == core.CatPersistence {
			nm := s.shortName(x)
			for _, k := range []string{nm, appName(filepath.Base(x.Evidence["program"])), appName(x.Evidence["label"])} {
				if k != "" && k != "." && startsByItself[k] == "" {
					startsByItself[k] = nm
				}
			}
		}
	}
	// What follows 「要你看看」 (what could not be checked, the side column's settings), drawn on a card of its own first:
	// the list leaves exactly that much of the card's 200 for it, not a guess.
	tail := func(c *Card) {
		if lines := skippedLines(*r); len(lines) > 0 {
			c.Part(func() {
				c.Divider()
				for _, l := range lines {
					c.Text(l.text, true)
					if l.grant != "" {
						c.Buttons([]Button{{Label: "打开设置", Event: "scan_open_settings", Context: O{"grant": l.grant}}})
					}
				}
			})
		}
		// Settings and the virus database's date: the side column too.
		c.Aside(func() { c.Part(func() { s.autocleanSection(c, f, st, r) }) })
	}
	// 「要你看看」: one line per kind (its icon, title, names, what to do and a button), the kinds past pageLookFirst
	// folded; after: what follows it. Drawn on the page, and on a card of its own to know what it takes.
	look := func(c *Card, after int) {
		groups := groupLook(v.look)
		if len(groups) == 0 {
			return
		}
		if c.Sectioned() {
			after += 3 // what wraps the lines once they are drawn: the part, the list, the list in the fold
		}
		c.Part(func() { s.lookPart(c, v, groups, startsByItself, after) })
	}
	// The card's 200: what each part after 「可以清掉」 takes, drawn on a card of its own (the password items, 「要你看看」
	// whole, what was not checked and the side column), and what 「可以清掉」 takes at the least (each item its choice
	// alone). Both fit: 「要你看看」 keeps all it takes and 「可以清掉」 draws its rows as fully as the rest allows. They
	// do not: 「可以清掉」 keeps every item it can (the button does what is chosen, so nothing it would clean is off the
	// page) and 「要你看看」 has what is left, at least its title and one line naming its kinds.
	alone := func(draw func(*Card)) int {
		d := c.Blank()
		draw(d)
		return d.Count() - 1
	}
	// 「可以清掉」 and the password items, each a part of the page where it is drawn a card per part; partN: the part's
	// own Column, added once what is in it is drawn
	partN := 0
	if c.Sectioned() {
		partN = 1
	}
	clean := func(c *Card, after int) {
		if after != cleanFewest {
			after += partN
		}
		c.Part(func() {
			s.cleanSection(c, *v.plan, about, urgent, after, append(append([]PlanItem{}, v.cleaned...), v.done...))
		})
	}
	admin := func(c *Card) { c.Part(func() { s.adminBody(c, *v.admin, f) }) }
	tailN := alone(tail)
	adminN := 0
	if v.admin != nil {
		adminN = alone(admin)
	}
	lookN := alone(func(d *Card) { look(d, tailN) })
	// 可以清掉的排在「要你看看」前面（后者多半只能看，挡住了马上能做的事）
	if v.plan != nil {
		least := alone(func(d *Card) { clean(d, cleanFewest) })
		lookFor := lookN
		if room := c.Max() - c.Count() - tailN - adminN; least+lookN > room {
			lookLeast := alone(func(d *Card) { look(d, d.Max()) }) // no line fits: the title, the kinds named
			lookFor = max(lookLeast, room-least)
		}
		clean(c, tailN+adminN+lookFor)
	}
	if v.admin != nil {
		admin(c)
	}
	look(c, tailN)
	tail(c)
}

// lookPart: 「要你看看」 on the scan page (luoke-scan#129): its title, then one line per kind (its icon, title, names,
// what to do and a button), the kinds past pageLookFirst folded in 「还有 N 类，共 M 项」. Where the page is drawn a card
// per part, as in the design: the lines in a List, the names as chips, a line's one button with its icon and words.
// after: what the page keeps free after it.
func (s *Service) lookPart(c *Card, v roundView, groups []lookGroup, startsByItself map[string]string, after int) {
	c.Divider()
	c.SectionCount("eye", "要你看看", len(v.look))
	count := func(gs []lookGroup) int {
		n := 0
		for _, g := range gs {
			n += len(g.findings)
		}
		return n
	}
	line := func(c *Card, g lookGroup) { c.Item(func() { s.lookLine(c, g, startsByItself) }) }
	// One line per kind while the page has room for it, for one more line and what follows. 「可以清掉」 leaves
	// 「要你看看」 what it takes whole whenever both fit (below); only a page with more kinds than that names the
	// kinds past the room in one line (their title each), so every kind is on the page however many there are.
	lines := func(gs []lookGroup, after int) {
		c.List(func() {
			for i, g := range gs {
				if !c.Fits(after+1, func(d *Card) { line(d, g) }) {
					var titles []string
					for _, h := range gs[i:] {
						t, _, _ := s.plainGroup(h)
						titles = append(titles, t)
					}
					c.Text(strings.Join(titles, "\n"), true)
					return
				}
				line(c, g)
			}
		})
	}
	if len(groups) > pageLookFirst+1 { // 只多一类就直接列：一句「还有 1 类」占的地方一样大
		lines(groups[:pageLookFirst], after+2) // the fold and its one line after these
		rest := groups[pageLookFirst:]
		c.Collapsed(fmt.Sprintf("还有 %d 类，共 %d 项", len(rest), count(rest)), func() { lines(rest, after+1) })
	} else {
		lines(groups, after)
	}
}

// lookLine: one kind under 「要你看看」: its icon, title, names, what to do and its buttons (or each one in the Finder,
// folded when more than three).
func (s *Service) lookLine(c *Card, g lookGroup, startsByItself map[string]string) {
	title, advice, names := s.plainGroup(g)
	// A known malicious package: what to do at once (change the passwords, leave the project alone), read whole
	// like the steps below; other kinds' advice one line where the core cuts texts.
	whole := isMaliciousPackage(g.findings[0])
	if item := startsByItself[appName(filepath.Base(g.findings[0].Path))]; len(g.findings) == 1 && g.findings[0].Rule == "process.deleted-binary" && item != "" {
		// 同一轮里有它的开机启动项：照实说。清理只把启动项移走，不结束在运行的它，所以写上重启；两句各占一行，内层引号用『』。
		// 第二句是要用户照着做的步骤，不截成一行
		advice = "它会跟着开机启动，重启后还会再运行。\n要停掉它：把上面「会跟着电脑一起启动的『" + item + "』」改成「移到废纸篓」，清理后重启一下电脑。"
		whole = true
	}
	if !whole {
		advice = lookAdvice(g, advice) // one short line, as in the design
	}
	var buttons, each []Button
	if len(g.findings) == 1 {
		buttons = s.listButtons(g.findings[0])
	} else if g.findings[0].Rule == "permission.stale-grant" {
		seen := map[string]bool{} // each settings page the apps are in, once
		for _, f := range g.findings {
			for _, b := range s.listButtons(f) {
				if !seen[b.Label] {
					seen[b.Label] = true
					buttons = append(buttons, b)
				}
			}
		}
	} else if b := s.listButtons(g.findings[0]); len(b) > 0 && b[0].Event == "scan_open_settings" {
		buttons = b[:1] // the same settings page for all of them
	} else {
		each = s.revealEach(g.findings) // AI plugins, apps from nowhere: each one in the Finder, as a line of one has
	}
	if c.Sectioned() && c.Has("lucide") {
		// one button on the right, as in the design: where it is switched off (登录项, 输入监控), not also the Finder
		if len(buttons) == 2 && buttons[0].Event == "scan_open_settings" && buttons[1].Event == "scan_reveal" {
			buttons = buttons[:1]
		}
		if len(buttons) == 1 {
			buttons[0] = lookButton(buttons[0], g.findings[0])
		}
	}
	chips, more := s.groupChips(g, names)
	icon, _ := ruleIcon(g.findings[0].Rule)
	c.ItemButtons(icon, title, []ItemLine{{Text: names, Chips: chips, More: more}, {Text: advice, Whole: whole}}, buttons)
	switch {
	case len(each) > 3: // folded where the core folds: the line stays one line
		what := fmt.Sprintf("在访达里逐个看（%d 个）", len(each))
		if len(each) < len(g.findings) {
			what = fmt.Sprintf("在访达里逐个看（前 %d 个，一共 %d 个）", len(each), len(g.findings))
		}
		c.Collapsed(what, func() { c.Buttons(each) })
	case len(each) > 0:
		c.Buttons(each)
	}
}

// lookButton: a line's one button as in the design (luoke-scan#129), its icon and words: 「在访达里看」, the settings
// page with the gear, 「去设置移除」 for the apps deleted but still allowed.
func lookButton(b Button, f core.Finding) Button {
	switch b.Event {
	case "scan_reveal":
		b.Label, b.Icon = "在访达里看", "folder-open"
	case "scan_open_settings":
		b.Icon = "settings"
		if f.Rule == "permission.stale-grant" {
			b.Label = "去设置移除"
		}
	}
	return b
}

// groupChips: a kind's names as chips (luoke-scan#129 design): the first three, and whether there are more. None for
// a kind whose line lists no names.
func (s *Service) groupChips(g lookGroup, names string) ([]string, bool) {
	if names == "" || len(g.findings) < 2 {
		return nil, false
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range g.findings {
		if nm := s.shortName(f); nm != "" && !seen[nm] {
			seen[nm] = true
			out = append(out, nm)
		}
	}
	if len(out) > 3 {
		return out[:3], true
	}
	return out, false
}

// cleanSection: 「可以清掉」 on the scan page (luoke-scan#129). First the rebuildable caches as one line, their tools
// named, with a button that deletes just them (nothing to choose: their tools rebuild them). Then every other item,
// the biggest first, with its choice (suggested preselected) and a line that tells what it is, and one button that does
// what is chosen. All of them drawn: nothing goes that the page does not show. The caches' choices in the data model are
// 「先不动」, so the bottom button never deletes them behind the user's back. gone: what already went with a click this
// round (roundView.cleaned, roundView.done): not offered again, nor counted in the button, its choice 「先不动」. after:
// the components the page keeps free after it (the rows are drawn as fully as that allows); cleanFewest: every row its
// choice alone, to know what it takes at the least.
func (s *Service) cleanSection(c *Card, p Plan, about map[string]core.Finding, urgent map[string]bool, after int, gone []PlanItem) {
	var caches, decide, live []PlanItem
	for _, it := range p.Items {
		if !hasItem(gone, it.Key) {
			live = append(live, it)
		}
		switch {
		case urgent[it.FindingID]:
			c.Defaults(it.Key, it.Suggested) // 在上面单独处理
		case hasItem(gone, it.Key):
			c.Defaults(it.Key, ChoiceKeep)
		case it.Suggested == ChoiceRemove:
			caches = append(caches, it)
		default:
			decide = append(decide, it)
		}
	}
	if len(caches)+len(decide) == 0 {
		return
	}
	sort.SliceStable(decide, func(i, j int) bool { return itemBytes(decide[i]) > itemBytes(decide[j]) })
	c.Divider()
	c.SectionCount("trash-2", "可以清掉", len(caches)+len(decide))
	if len(caches) > 0 {
		var tools []string
		var bytes int64
		only := O{}
		for _, it := range caches {
			name := it.Title
			if kc, ok := knownCacheByRule(it.Rule); ok {
				name = kc.Tool
			} else if f, ok := about[it.FindingID]; ok {
				name, _ = s.plain(f)
			}
			if !contains(tools, name) {
				tools = append(tools, name)
			}
			bytes += itemBytes(it)
			only[it.Key] = A{ChoiceRemove}
			c.Defaults(it.Key, ChoiceKeep)
		}
		title := fmt.Sprintf("会自动重建的缓存 %d 项", len(caches))
		if bytes > 0 {
			title += sizeNote(&bytes)
		}
		c.ItemButtons("refresh-cw", title, []ItemLine{{Text: strings.Join(tools, "、")}},
			[]Button{{Label: "清理", Event: "scan_apply", Context: O{"plan_id": p.ID, "choices": only}, Primary: len(decide) == 0}})
	}
	// One row per item, but one per kind for a kind with more than planGroupFrom items (planGroups: 41 installers are
	// one row, its choice for all of them), the biggest first.
	groups := planGroups(live)
	inGroup := map[string]bool{}
	for _, g := range groups {
		for _, m := range g.items {
			inGroup[m.Key] = true
		}
	}
	var entries []planEntry
	for _, g := range groups {
		entries = append(entries, s.groupEntry(g, about))
	}
	for _, it := range decide {
		if !inGroup[it.Key] {
			entries = append(entries, s.itemEntry(it, about))
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].bytes > entries[j].bytes })
	// A row as an item row (its icon, title, size and line, the choice on the right), its choice with the line under it,
	// or its choice alone (the line kept where it tells the risk: an AI plugin, a model's template)
	row := func(c *Card, e planEntry, how rowStyle) {
		switch {
		case how == rowFull:
			c.ItemChoice(e.icon, e.title, e.size, e.detail, e.key, e.options, e.selected)
		case how == rowShort || len(e.reveal) > 0:
			c.ItemChoiceShort(e.title, e.size, e.detail, e.key, e.options, e.selected)
		default:
			c.ItemChoiceShort(e.title, e.size, "", e.key, e.options, e.selected)
		}
		switch {
		case len(e.reveal) > 3: // folded as under 「要你看看」
			c.Collapsed(fmt.Sprintf("在访达里逐个看（%d 个）", len(e.reveal)), func() { c.Buttons(e.reveal) })
		case len(e.reveal) > 0:
			c.Buttons(e.reveal)
		}
	}
	shown := len(entries)
	if shown > pageDecideFirst+1 { // 只多一项就直接列
		shown = pageDecideFirst
	}
	// The rows, the first shown as one style and the folded rest as another; n: how many entries are drawn, the ones
	// past it left as they are (先不动) and said to be, so the button never does anything to what the page does not show.
	rows := func(c *Card, first, rest rowStyle, n int) {
		for _, e := range entries[:min(n, shown)] {
			row(c, e, first)
		}
		if n > shown {
			folded, k := entries[shown:n], 0
			for _, e := range folded {
				k += e.n
			}
			c.Collapsed(fmt.Sprintf("还有 %d 项", k), func() {
				for _, e := range folded {
					row(c, e, rest)
				}
			})
		}
		if left := entries[n:]; len(left) > 0 {
			k := 0
			for _, e := range left {
				c.Defaults(e.key, ChoiceKeep)
				k += e.n
			}
			c.Text(fmt.Sprintf("还有 %d 项这一页放不下，这次先不动。", k), true)
		}
		s.applyChosenButton(c, p, decide, groups)
	}
	if after == cleanFewest {
		rows(c, rowBare, rowBare, len(entries))
		return
	}
	// The fullest that leaves after free, the shown rows first; every entry its choice alone when nothing else fits;
	// fewer entries only when not even that does.
	styles := [][2]rowStyle{{rowFull, rowFull}, {rowFull, rowShort}, {rowFull, rowBare}, {rowShort, rowShort},
		{rowShort, rowBare}, {rowBare, rowBare}}
	for _, st := range styles {
		if c.Fits(after, func(d *Card) { rows(d, st[0], st[1], len(entries)) }) {
			rows(c, st[0], st[1], len(entries))
			return
		}
	}
	n := len(entries)
	for n > 0 && !c.Fits(after, func(d *Card) { rows(d, rowBare, rowBare, n) }) {
		n--
	}
	rows(c, rowBare, rowBare, n)
}

// rowStyle: how a row of 「可以清掉」 is drawn: an item row (nine components), its choice with a line under it (two), its
// choice alone (one).
type rowStyle int

const (
	rowFull rowStyle = iota
	rowShort
	rowBare
)

// cleanFewest, as cleanSection's after: draw it in the fewest components that still show every item.
const cleanFewest = -1

// applyChosenButton: 「可以清掉」's one button, under its rows: it does what is chosen.
func (s *Service) applyChosenButton(c *Card, p Plan, decide []PlanItem, groups []planGroup) {
	if len(decide) > 0 {
		// 只出现一次的主要动作写字，不给图标：以后这一行多一个按钮也不会变成对勾
		b := Button{Label: "按上面的选择清理", Event: "scan_apply", Context: O{"plan_id": p.ID, "choices": ChoicesPath}, Primary: true}
		// {n} counts rows; a row that stands for several items counts as many where the core weighs rows (§4
		// countWeights: 41 installers in one row are 41). Where it does not, a page with such a row keeps the words: it
		// would say 1 for 41.
		if count, label := cleanCount(decide); count != nil && c.Has("countLabel") && c.Has("countAlso") &&
			(len(groups) == 0 || c.Has("countWeights")) {
			if len(groups) > 0 {
				weights := O{}
				for _, g := range groups {
					weights[g.key] = len(g.items)
				}
				count["weights"] = weights
			}
			b.Label, b.Count = label, count
		}
		c.Buttons([]Button{b})
	}
}

// planEntry: one row of 「可以清掉」: an item, or a kind of them under one choice (planGroups).
type planEntry struct {
	key, icon, title, size, detail, selected string
	options                                  []Option
	bytes                                    int64
	n                                        int // the items it stands for
	// reveal: 「在访达里显示」 for what it would move, where the user should see it before choosing (an AI plugin, a
	// model's template: luoke-scan#152), drawn under the row
	reveal []Button
}

// itemEntry: an item's row: what it is (an app's or a file's name, its size as a tag) and the line under it.
func (s *Service) itemEntry(it PlanItem, about map[string]core.Finding) planEntry {
	title, detail := s.itemTitle(it, about), ""
	if f, ok := about[it.FindingID]; ok {
		title, detail = s.planLines(f)
		if f.Bytes == nil && it.Bytes != nil {
			title = withSize(title, it.Bytes)
		}
	}
	size := ""
	if b := itemBytes(it); b > 0 && strings.HasSuffix(title, sizeNote(it.Bytes)) {
		title, size = strings.TrimSuffix(title, sizeNote(it.Bytes)), core.FormatBytes(b) // 有标签时大小画成标签
	}
	icon, _ := ruleIcon(it.Rule)
	e := planEntry{key: it.Key, icon: icon, title: title, size: size, detail: detail, selected: it.Suggested,
		options: labeled(it.Options), bytes: itemBytes(it), n: 1}
	if f, ok := about[it.FindingID]; ok && trashableSkill(f) {
		e.reveal = s.revealEach([]core.Finding{f})
	}
	return e
}

// groupEntry: a kind's row: what they are, how many and their size together, their names, and one choice for all.
func (s *Service) groupEntry(g planGroup, about map[string]core.Finding) planEntry {
	var fs []core.Finding
	var total int64
	for _, it := range g.items {
		total += itemBytes(it)
		if f, ok := about[it.FindingID]; ok {
			fs = append(fs, f)
		}
	}
	title, names := fmt.Sprintf("%s，一共 %d 项", g.items[0].Title, len(g.items)), ""
	if len(fs) == len(g.items) {
		var t string
		t, _, names = s.plainGroup(lookGroup{key: groupKey(fs[0]), findings: fs})
		title = strings.Replace(t, plainSize(&total), "", 1)
	}
	detail := "这 " + strconv.Itoa(len(g.items)) + " 项一起处理"
	if names != "" {
		detail = names + "，" + detail
	}
	var reveal []Button
	if len(fs) > 0 && trashableSkill(fs[0]) {
		// AI plugins, models: what the risk is (the reason to delete them) and each one in the Finder (luoke-scan#152)
		_, advice, _ := s.plainGroup(lookGroup{key: groupKey(fs[0]), findings: fs})
		detail += "\n" + advice
		reveal = s.revealEach(fs)
	}
	size := ""
	if total > 0 {
		size = core.FormatBytes(total)
	}
	icon, _ := ruleIcon(g.items[0].Rule)
	return planEntry{key: g.key, icon: icon, title: title, size: size, detail: detail, selected: g.items[0].Suggested,
		options: labeled(g.options), bytes: total, n: len(g.items), reveal: reveal}
}

// cleanCount: what 「可以清掉」's button counts where the core draws counted labels (§4 countLabel, countAlso;
// luoke-scan#129), and its words. {n} is how many of the items are chosen for the Trash; at 0 the core does not draw the
// button (it greyed it before 11-11: a 「移到废纸篓 0 项」 under rows all 「先不动」); any other choice that does something
// (以后别提, 换成克隆, 改成不跑…: also) draws it as 「按上面的选择处理」, so those can go on their own. Where none of the
// items can go to the Trash (「移到废纸篓 0 项」 would name what none of them does) it keeps 「按上面的选择清理」 and counts
// those other choices: drawn while one of them is picked, as the other. nil when none of the items can be acted on.
func cleanCount(decide []PlanItem) (O, string) {
	trash := false
	var also []string
	for _, it := range decide {
		for _, o := range it.Options {
			switch {
			case o == ChoiceTrash:
				trash = true
			case o != ChoiceKeep && !contains(also, o):
				also = append(also, o)
			}
		}
	}
	sort.Strings(also)
	values := func(xs []string) A {
		out := A{}
		for _, o := range xs {
			out = append(out, o)
		}
		return out
	}
	if !trash {
		if len(also) == 0 {
			return nil, ""
		}
		count := O{"path": ChoicesPath["path"], "value": also[0]}
		if len(also) > 1 {
			count["also"], count["alsoLabel"] = values(also[1:]), "按上面的选择清理"
		}
		return count, "按上面的选择清理"
	}
	count := O{"path": ChoicesPath["path"], "value": ChoiceTrash}
	if len(also) > 0 {
		count["also"], count["alsoLabel"] = values(also), "按上面的选择处理"
	}
	return count, "移到废纸篓 {n} 项"
}

// hasItem: one of the items has this key.
func hasItem(items []PlanItem, key string) bool {
	for _, it := range items {
		if it.Key == key {
			return true
		}
	}
	return false
}

// revealMost: the most 「在访达里显示」 buttons a line of several gets (two components each).
const revealMost = 8

// revealEach: for a line of several things the user is told to find in the Finder (AI plugins, apps from nowhere),
// one 「在访达里显示「名字」」 each, as the line of one of them has; the first revealMost of them.
func (s *Service) revealEach(fs []core.Finding) []Button {
	var out []Button
	for _, f := range fs {
		if len(out) == revealMost {
			break
		}
		for _, b := range s.listButtons(f) {
			if b.Event == "scan_reveal" {
				b.Label = "在访达里显示「" + s.shortName(f) + "」"
				if f.Evidence["template"] != "" {
					b.Label += "的模板" // the template file is what it selects
				}
				out = append(out, b)
			}
		}
	}
	return out
}

// itemBytes: an item's size, 0 when it has none.
func itemBytes(it PlanItem) int64 {
	if it.Bytes == nil {
		return 0
	}
	return *it.Bytes
}

// autocleanSection: whether automatic cleaning is on, what it cleans and the button that changes it; the virus
// database's date.
func (s *Service) autocleanSection(c *Card, f []core.Finding, st State, r *core.Report) {
	c.Divider()
	var on []string
	for _, k := range AutoKinds {
		if _, off := st.AutoOff[string(k)]; !off {
			on = append(on, k.Label())
		}
	}
	// 一个开关，开和关同一个样子：「自动清理」和开关一行，清什么一行（开之前说清会清什么，设计评审 11-07）
	if st.AutocleanOff != nil || len(on) == 0 {
		c.Switch("自动清理", "打开自动清理", false, "scan_autoclean", O{"on": true})
		c.Text(AutocleanWhat, true)
	} else {
		c.Switch("自动清理", "关掉自动清理", true, "scan_autoclean", O{"on": false})
		c.Text("每天那一轮不用你点就清："+strings.Join(on, "、")+"。移到废纸篓的都能放回，要你定的照样先问你。", true)
	}
	if d, ok := r.Versions["clamav_db_date"]; ok {
		c.Text("病毒库更新于 "+monthDay(d), true) // 和「上一轮 10月20日」同一种写法
	}
}

// AutocleanWhat: what 「打开自动清理」 turns on, in the user's words (README「打开以后，四类不用点就清」).
const AutocleanWhat = "打开后，每天那一轮不用你点就清：会重建的缓存、装好了的应用的安装包、下载文件夹里的重复文件、测试工具留下的临时文件夹。移到废纸篓的都能放回，要你定的照样先问你。"

// canPutBack: what 「放回」 on a whole batch would bring back: still in the Trash (or a config 改成不跑 made where there
// was none, still as written), not moved with the password, not malware, not what starts by itself.
func canPutBack(es []Cleaned) []Cleaned {
	var out []Cleaned
	for _, e := range es {
		if e.Restored == nil && (e.Admin == nil || !*e.Admin) && ((e.Trashed != nil && core.Exists(*e.Trashed)) || newConfigThere(e)) &&
			!strings.HasPrefix(e.Rule, "malware.") && !strings.HasPrefix(e.Rule, "persistence.") {
			out = append(out, e)
		}
	}
	return out
}

// localTime: "10月27日 20:05", this Mac's time zone: for people, not the ISO form.
// monthDay: 2026-10-20 as 10月20日; anything else as it is.
func monthDay(d string) string {
	t, err := time.Parse("2006-01-02", d)
	if err != nil {
		return d
	}
	return fmt.Sprintf("%d月%d日", int(t.Month()), t.Day())
}

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
		for _, e := range es {
			if e.Bytes != nil {
				bytes += *e.Bytes
			}
			if e.At.After(latest) {
				latest = e.At.Time
			}
			if t := friendlyName(e.Title); len(titles) < 3 && !contains(titles, t) {
				titles = append(titles, t)
			}
		}
		names := andMore(strings.Join(titles, "、"), len(titles), len(es))
		c.Divider()
		who := "你清的"
		if strings.HasPrefix(b, "auto-") {
			who = "自动清理的"
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
			if e.Trashed != nil || newConfig(e) {
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
			put := fmt.Sprintf("「放回」把还在废纸篓里的 %d 项放回原来的位置", len(back))
			if len(trashed) < len(es) {
				put += "；删掉的缓存不用放回，用到时会重建"
			}
			c.Text(put+"。", true)
			c.Buttons([]Button{{Label: "放回", Event: "scan_restore", Context: O{"id": b}}})
		}
	}
}

// friendlyName: a throwaway folder of a known tool (「临时文件夹 puppeteer_dev_chrome_profile-P00020」, or the bare name) as
// 「Puppeteer 留下的临时文件夹」;
// anything else as it is.
func friendlyName(name string) string {
	base := name // 记录里的标题带着类别：「临时文件夹 puppeteer_dev_chrome_profile-P00020」
	if i := strings.LastIndex(name, " "); i >= 0 {
		base = name[i+1:]
	}
	if pr, ok := core.TempLeakPrefix(base); ok {
		if tool, known := core.AutoKnownTemp[pr]; known {
			return tool + " 留下的临时文件夹"
		}
	}
	return name
}

// andMore: 「a、b 等 24 项」 when there are more than the names shown; no space before 等 after a Chinese name
// (「Puppeteer 留下的临时文件夹等 24 项」), one after a Latin one (「report.pdf 等 24 项」).
func andMore(names string, shown, total int) string {
	if total <= shown {
		return names
	}
	sep := " "
	if r := []rune(names); len(r) > 0 && r[len(r)-1] >= 0x4E00 && r[len(r)-1] <= 0x9FFF {
		sep = ""
	}
	return names + sep + fmt.Sprintf("等 %d 项", total)
}
