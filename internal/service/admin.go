package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The service's side of what needs the password: which targets count as the system's, the plan carried out through
// the step with administrator rights (螺壳's main body shows the dialog: Config.Elevate), and what an earlier step moved
// but nobody wrote down.

// AdminLine is one line the step with administrator rights answers per target (JSON, one per line).
type AdminLine struct {
	Bytes   *int64  `json:"bytes,omitempty"`
	Device  *int64  `json:"device,omitempty"`
	Error   *string `json:"error,omitempty"`
	Gone    *bool   `json:"gone,omitempty"` // not there any more: counted as done
	Inode   *uint64 `json:"inode,omitempty"`
	Key     string  `json:"key"`
	Path    string  `json:"path"`
	Trashed *string `json:"trashed,omitempty"`
}

// adminPending is what was about to go with the password, written down before the dialog: when this process is ended
// meanwhile, what root moved is found in the Trash again by what it is and recorded.
type adminPending struct {
	At    core.Time          `json:"at"`
	Items []adminPendingItem `json:"items"`
	Plan  string             `json:"plan"`
}

type adminPendingItem struct {
	Device int64  `json:"device"`
	Inode  uint64 `json:"inode"`
	Key    string `json:"key"`
	Path   string `json:"path"`
	Rule   string `json:"rule"`
	Title  string `json:"title"`
}

// systemPlaces are the folders of the system's Library an app's own data can be left in.
var systemPlaces = []string{"Application Support", "Caches", "Logs"}

// insideSystem: an app's data in the system's Library (a direct child of one of its places), or one of an Intel
// Homebrew's folders in /usr/local.
func (s *Service) insideSystem(path string) bool {
	parent, name := core.Canonical(filepath.Dir(path)), filepath.Base(path)
	if name == "" || name == "." || name == ".." || name == "/" {
		return false
	}
	if contains(core.IntelHomebrewFolders, name) && parent == core.Canonical(s.installRule().UsrLocal) {
		return true
	}
	lib := s.Config.Context.SystemLibrary
	if lib == "" {
		return false
	}
	for _, p := range systemPlaces {
		if core.Canonical(filepath.Join(lib, p)) == parent {
			return true
		}
	}
	return false
}

// stillLeftOver: an app's data in the system's Library still counts as left over, judged in full: the round's rule
// (its settings), the installed components and launchd jobs, and Launch Services.
func (s *Service) stillLeftOver(id string) bool {
	ctx := s.Config.Context
	if ctx.SystemLibrary == "" {
		return false
	}
	var rule *core.LeftoverRule
	for _, r := range s.Config.Rules {
		if x, ok := r.(*core.LeftoverRule); ok {
			rule = x
			break
		}
	}
	if rule == nil {
		rule = core.NewLeftoverRule(nil, nil).(*core.LeftoverRule)
	}
	if core.NewInstalledApps(ctx.AppDirs, rule.LaunchServices).Covers(id) {
		return false
	}
	components := core.InstalledComponents(ctx.SystemLibrary, ctx.Receipts, ctx.Home)
	programs, ok := core.LaunchdPaths(ctx.SystemLibrary, ctx.Home, false)
	if !ok {
		return false
	}
	return rule.SystemLeftovers(id, ctx.SystemLibrary, ctx.AppDirs, components, programs, s.now()) != nil
}

// homebrewStillGoes: the Intel Homebrew may still go, judged in full as the round does (its launchd jobs, running
// programs, nothing written lately).
func (s *Service) homebrewStillGoes() bool {
	rule := s.installRule()
	if rule.AppleSilicon == nil || !rule.AppleSilicon() {
		return false
	}
	library := s.Config.Context.SystemLibrary
	if library == "" {
		library = filepath.Join(s.Config.Context.Home, "Library")
	}
	programs, ok := core.LaunchdPaths(library, s.Config.Context.Home, false)
	if !ok || rule.Crontab == nil {
		return false
	}
	cron, ok := rule.Crontab()
	if !ok {
		return false
	}
	var running []string
	if rule.Running != nil {
		running = rule.Running()
	}
	_, _, goes := s.homebrew().Removable(append(programs, strings.Split(cron, "\n")...), running, uint32(os.Getuid()), s.now())
	return goes
}

func (s *Service) pendingPath(plan string) string {
	return filepath.Join(s.plansDir(), plan+".admin-pending")
}

// reconcileAdmin records what an earlier password step moved but nobody wrote down; drops what is done with. A plan
// another process is applying right now is left to it; holding is the one this process holds already.
func (s *Service) reconcileAdmin(holding ...string) {
	held := ""
	if len(holding) > 0 {
		held = holding[0]
	}
	s.reconcileAdminNotes(held, false)
}

// reconcileAdminNotes records what the root step moved, from each note it left; keep leaves the held plan's note
// for the next time (the step may still be running).
func (s *Service) reconcileAdminNotes(held string, keep bool) {
	for _, f := range core.Children(s.plansDir()) {
		if filepath.Ext(f) != ".admin-pending" {
			continue
		}
		d, err := os.ReadFile(f)
		var p adminPending
		if err != nil || json.Unmarshal(d, &p) != nil {
			os.Remove(f)
			continue
		}
		mine := p.Plan == held
		if !mine && !s.begin(p.Plan) {
			continue
		}
		func() {
			if !mine {
				defer s.end(p.Plan)
			}
			// Under the lock: the process that held it may have recorded everything and removed the note meanwhile.
			again, err := os.ReadFile(f)
			if err != nil || string(again) != string(d) {
				return
			}
			recorded := map[string]bool{}
			for _, e := range s.Cleaned() {
				recorded[fmt.Sprintf("%d:%d", e.Device, e.Inode)] = true
			}
			var lines []cleanLine
			for _, it := range p.Items {
				k := fmt.Sprintf("%d:%d", it.Device, it.Inode)
				if recorded[k] {
					continue
				}
				recorded[k] = true
				if _, _, _, there := identity(it.Path); there {
					continue
				}
				trashed := s.findInTrash(it.Device, it.Inode)
				if trashed == "" {
					continue
				}
				yes := true
				e := Cleaned{ID: "c-" + core.ShortHash(p.Plan, it.Path, core.ISOTime(p.At.Time), randomID()), Batch: p.Plan, At: p.At,
					Rule: it.Rule, Title: it.Title, Original: it.Path, Trashed: strPtr(trashed), Device: it.Device, Inode: it.Inode, Admin: &yes}
				lines = append(lines, cleanLine{Op: "trashed", Entry: &e})
			}
			if len(lines) > 0 {
				s.cleanLog().append(lines, s.now())
			}
			if !(keep && mine) {
				os.Remove(f)
			}
		}()
	}
}

// pendingSibling is the other plan offered on the same card, while it is not done yet.
func (s *Service) pendingSibling(plan Plan) *Plan {
	if plan.Sibling == "" {
		return nil
	}
	if _, done := s.state().DonePlans[plan.Sibling]; done {
		return nil
	}
	if p, ok := LoadPlan(s.plansDir(), plan.Sibling); ok {
		return &p
	}
	return nil
}

// notNowReason: why picked items were not handed to the password step.
func notNowReason(items []PlanItem) string {
	for _, it := range items {
		if it.Rule != homebrewRule {
			return "现在不算卸载残留了"
		}
	}
	return "现在不能删了（有程序或开机任务在用它，或者最近还在用）"
}

// finish: a plan carried out to the end. The card it was on is answered once its other plan, if any, is too.
func (s *Service) finish(plan Plan) {
	at := core.Time{Time: s.now()}
	s.mutate(func(st *State) {
		if st.DonePlans == nil {
			st.DonePlans = map[string]core.Time{}
		}
		st.DonePlans[plan.ID] = at
		siblingDone := true
		if plan.Sibling != "" {
			_, siblingDone = st.DonePlans[plan.Sibling]
		}
		if siblingDone && plan.OutboxID != "" {
			st.Acks[plan.OutboxID] = Ack{State: "answered", At: at}
		}
	})
}

// applyAdmin is scan_apply on the plan that needs the password: one dialog for all of it, then the step with
// administrator rights. Cancelled: nothing happened, and the card keeps this plan's controls (and the other plan's).
// undecided: some items were not decided on (a terminal named only some): the plan stays open for them.
func (s *Service) applyAdmin(plan Plan, picks map[string]string, meta O, undecided bool) (ToolOutput, error) {
	s.reconcileAdmin(plan.ID)
	var picked []PlanItem
	for _, it := range plan.Items {
		if picks[it.Key] == ChoiceTrash {
			picked = append(picked, it)
		}
	}
	// Judged again here: an app registered anywhere still has its data. Only these ids go to root, as arguments this
	// process makes, not as the plan file says.
	verified := map[string]bool{}
	brewPicked := false
	for _, it := range picked {
		if it.BundleID != "" && s.stillLeftOver(it.BundleID) {
			verified[it.BundleID] = true
		}
		if it.Rule == homebrewRule {
			brewPicked = true
		}
	}
	brew := brewPicked && s.homebrewStillGoes()
	var chosen, notNow []PlanItem
	for _, it := range picked {
		if (it.BundleID != "" && verified[it.BundleID]) || (it.Rule == homebrewRule && brew) {
			chosen = append(chosen, it)
		} else {
			notNow = append(notNow, it)
		}
	}
	var ignored []string
	var ignoredItems []PlanItem
	for _, it := range plan.Items {
		if picks[it.Key] == ChoiceIgnore {
			ignored = append(ignored, it.FindingID)
			ignoredItems = append(ignoredItems, it)
		}
	}
	newly := s.markIgnored(ignored)
	var fresh []PlanItem
	for _, it := range ignoredItems {
		if newly[it.FindingID] {
			fresh = append(fresh, it)
		}
	}
	s.remember(s.ignoredRecords(fresh, plan.ID, s.Store.LastReport()))
	other := s.pendingSibling(plan)
	top := s.roundTop(plan)
	card := func(lines func(*Card), again bool) []any {
		return s.answerCard(meta, again || other != nil, func(c *Card) {
			if top != nil {
				top(c)
			}
			lines(c)
			if again {
				s.adminBody(c, plan)
			}
			if other != nil {
				c.Divider()
				s.planBody(c, *other, "不要密码的这几项", "", nil)
			}
		})
	}
	if len(chosen) == 0 {
		// Kept, or not mentioned again: decided, so done. Picked but no longer left over: said so.
		text := "没有改动什么。"
		if len(ignored) > 0 {
			text = fmt.Sprintf("以后不再提 %d 项。", len(ignored))
		}
		if len(notNow) > 0 {
			text = fmt.Sprintf("%d 项", len(notNow)) + notNowReason(notNow) + "，没动。"
		}
		if !undecided {
			s.finish(plan)
		}
		return ToolOutput{Text: text, Card: card(func(c *Card) { c.Text(text) }, undecided), Done: Bool(!undecided && other == nil)}, nil
	}
	var bytes int64
	apps := 0
	for _, it := range chosen {
		if it.Bytes != nil {
			bytes += *it.Bytes
		}
		if it.Rule != homebrewRule {
			apps++
		}
	}
	var what []string
	if apps > 0 {
		what = append(what, fmt.Sprintf("系统目录里 %d 个应用留下的东西", apps))
	}
	if brew && apps < len(chosen) {
		what = append(what, "/usr/local 里旧的 Intel 版 Homebrew")
	}
	prompt := "螺壳扫描要把" + strings.Join(what, "和")
	if bytes > 0 {
		prompt += "（" + core.FormatBytes(bytes) + "）"
	}
	prompt += "移到废纸篓。"
	at := core.Time{Time: s.now()}
	pending := adminPending{Plan: plan.ID, At: at}
	var keys []string
	hasBrew := false
	for _, it := range chosen {
		keys = append(keys, it.Key)
		if it.Rule == homebrewRule {
			hasBrew = true
		}
		for _, t := range it.Targets {
			pending.Items = append(pending.Items, adminPendingItem{Key: it.Key, Title: it.Title, Rule: it.Rule, Path: t.Path, Device: t.Device, Inode: t.Inode})
		}
	}
	os.MkdirAll(s.plansDir(), 0o700)
	if d, err := core.EncodeJSON(pending); err == nil {
		core.WriteAtomic(s.pendingPath(plan.ID), d, 0o600)
	}
	var ids []string
	for id := range verified {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	args := []string{"--plan", plan.ID, "--user", strconv.Itoa(os.Getuid()), "--keys", strings.Join(keys, ","), "--apps", strings.Join(ids, ",")}
	if hasBrew {
		args = append(args, "--homebrew")
	}
	res := s.Config.Elevate(args, prompt)
	switch res.Kind {
	case "cancelled":
		os.Remove(s.pendingPath(plan.ID))
		text := "没有删，需要时再点。"
		return ToolOutput{Text: text, Card: card(func(c *Card) { c.Text(text) }, true), Done: Bool(false)}, nil
	case "done":
	default:
		if res.Uncertain {
			// The main app stopped waiting; the root step may still be moving things. What has moved so far goes in the
			// record now, and the note stays, so that the next round (or a restore) records the rest.
			s.reconcileAdminNotes(plan.ID, true)
			return ToolOutput{}, Fail("failed", "不知道删成了没有（"+res.Why+"）：挪走的会记进清理记录，下一轮再看一遍")
		}
		s.reconcileAdmin(plan.ID) // whatever got moved before it failed is in the record now
		return ToolOutput{}, Fail("failed", "没删成："+res.Why)
	}
	var lines []AdminLine
	for _, l := range strings.Split(res.Output, "\n") {
		var x AdminLine
		if json.Unmarshal([]byte(l), &x) == nil && (x.Key != "" || x.Path != "") {
			lines = append(lines, x)
		}
	}
	var moved, gone, left []AdminLine
	answered := map[string]bool{}
	for _, l := range lines {
		answered[l.Key] = true
		switch {
		case l.Trashed != nil:
			moved = append(moved, l)
		case l.Gone != nil && *l.Gone:
			gone = append(gone, l)
		default:
			left = append(left, l)
		}
	}
	// Chosen, but the step said nothing of it: not moved.
	var unanswered []PlanItem
	for _, c := range chosen {
		if !answered[c.Key] {
			unanswered = append(unanswered, c)
		}
	}
	byKey := map[string]PlanItem{}
	for _, it := range plan.Items {
		if _, has := byKey[it.Key]; !has {
			byKey[it.Key] = it
		}
	}
	known := map[string]bool{}
	for _, e := range s.Cleaned() {
		known[fmt.Sprintf("%d:%d", e.Device, e.Inode)] = true
	}
	var entries []cleanLine
	movedKeys := map[string]bool{}
	var freed int64
	for _, l := range moved {
		movedKeys[l.Key] = true
		if l.Bytes != nil {
			freed += *l.Bytes
		}
		var dev int64
		var ino uint64
		if l.Device != nil {
			dev = *l.Device
		}
		if l.Inode != nil {
			ino = *l.Inode
		}
		if known[fmt.Sprintf("%d:%d", dev, ino)] {
			continue
		}
		yes := true
		e := Cleaned{ID: "c-" + core.ShortHash(plan.ID, l.Path, core.ISOTime(at.Time), randomID()), Batch: plan.ID, At: at,
			Rule: byKey[l.Key].Rule, Title: filepath.Base(l.Path), Original: l.Path, Trashed: l.Trashed, Device: dev, Inode: ino,
			Bytes: l.Bytes, Admin: &yes}
		entries = append(entries, cleanLine{Op: "trashed", Entry: &e})
	}
	if len(entries) > 0 {
		s.cleanLog().append(entries, at.Time)
	}
	os.Remove(s.pendingPath(plan.ID))
	var outcomes []outcome
	for _, it := range chosen {
		outcomes = append(outcomes, outcome{it, ChoiceTrash, movedKeys[it.Key]})
	}
	s.remember(s.cleanedRecords(plan.ID, outcomes, nil))
	var parts []string
	if len(moved) > 0 {
		p := fmt.Sprintf("移到废纸篓 %d 项", len(moved))
		if freed > 0 {
			p += "（" + core.FormatBytes(freed) + "）"
		}
		parts = append(parts, p)
	}
	if len(gone) > 0 {
		parts = append(parts, fmt.Sprintf("%d 项已经不在了", len(gone)))
	}
	if n := len(left) + len(notNow) + len(unanswered); n > 0 {
		parts = append(parts, fmt.Sprintf("%d 项没动", n))
	}
	text := "没有改动什么。"
	if len(parts) > 0 {
		text = strings.Join(parts, "，") + "。"
	}
	complete := len(left) == 0 && len(notNow) == 0 && len(unanswered) == 0
	done := complete && !undecided
	if done {
		s.finish(plan)
	}
	result := card(func(c *Card) {
		c.Text(text)
		for _, l := range left {
			title := s.display(l.Path)
			if it, ok := byKey[l.Key]; ok {
				title = it.Title
			}
			why := "没动"
			if l.Error != nil {
				why = *l.Error
			}
			c.Text(title+"："+s.display(l.Path)+"："+why, true)
		}
		for _, it := range notNow {
			c.Text(it.Title+"："+notNowReason([]PlanItem{it}), true)
		}
		for _, it := range unanswered {
			c.Text(it.Title+"：没动（删除那一步没说它怎么样了）", true)
		}
		if len(moved) > 0 {
			c.Text("要放回，在访达里把它们从废纸篓拖回原来的位置（会要密码）：", true)
			for _, l := range moved {
				c.Text(s.display(l.Path), true)
			}
		}
	}, !done)
	return ToolOutput{Text: text, Card: result, Done: Bool(done && other == nil)}, nil
}

// MARK: from a terminal (luoke-scan system)

// SystemItem is one item of what needs the password, as a terminal lists it.
type SystemItem struct {
	Key, Title string
	Bytes      *int64
	Paths      []string
	Gone       bool // nothing of it left where it was (moved by an earlier run)
}

// SystemLeftovers is the plan of what needs the password on the round's card, the very one: carried out in a
// terminal, it is done on the card too, and the other way round.
type SystemLeftovers struct {
	Plan    string
	Scanned core.Time
	Items   []SystemItem
	Done    bool
}

// SystemLeftovers: nil when the last round found none, or there is no round yet.
func (s *Service) SystemLeftovers() *SystemLeftovers {
	r := s.Store.LastReport()
	if r == nil {
		return nil
	}
	st := s.state()
	_, a := s.plans(s.visible(*r, st), *r, "findings", roundID(*r))
	if a == nil {
		return nil
	}
	out := &SystemLeftovers{Plan: a.ID, Scanned: r.StartedAt}
	_, out.Done = st.DonePlans[a.ID]
	for _, it := range a.Items {
		item := SystemItem{Key: it.Key, Title: it.Title, Bytes: it.Bytes, Gone: true}
		for _, t := range it.Targets {
			item.Paths = append(item.Paths, t.Path)
			if core.Exists(t.Path) {
				item.Gone = false
			}
		}
		out.Items = append(out.Items, item)
	}
	return out
}

// TrashSystemLeftovers moves the items keys names to the Trash, as a click on 「移到废纸篓（要输入密码）」 does; the
// others stay for later, and the plan is done once nothing of it is left undecided. What to print, and whether
// everything named is gone from where it was.
func (s *Service) TrashSystemLeftovers(keys []string) ([]string, bool) {
	found := s.SystemLeftovers()
	if found == nil {
		return []string{"上一轮没查到要密码才能删的东西。"}, false
	}
	if found.Done {
		return []string{"这些已经处理过了。"}, true
	}
	for _, k := range keys {
		ok := false
		for _, it := range found.Items {
			if it.Key == k {
				ok = true
			}
		}
		if !ok {
			return []string{"没有这一项：" + k}, false
		}
	}
	plan, ok := LoadPlan(s.plansDir(), found.Plan)
	if !ok {
		return []string{"这份方案找不到了，重新查一下再来。"}, false
	}
	if !s.begin(plan.ID) {
		return []string{"这份方案正在处理，等一下再看。"}, false
	}
	defer s.end(plan.ID)
	if _, done := s.state().DonePlans[plan.ID]; done {
		return []string{"这些已经处理过了。"}, true // from the card, meanwhile
	}
	named, gone := map[string]bool{}, map[string]bool{}
	for _, k := range keys {
		named[k] = true
	}
	for _, it := range found.Items {
		if it.Gone {
			gone[it.Key] = true
		}
	}
	picks := map[string]string{}
	for _, it := range plan.Items {
		picks[it.Key] = ChoiceKeep
		if named[it.Key] && !gone[it.Key] {
			picks[it.Key] = ChoiceTrash
		}
	}
	undecided := false
	for _, it := range found.Items {
		if !named[it.Key] && !gone[it.Key] {
			undecided = true
		}
	}
	out, err := s.applyAdmin(plan, picks, O{}, undecided)
	if err != nil {
		if f, ok := err.(*ToolFailure); ok {
			return []string{f.Message}, false
		}
		return []string{err.Error()}, false
	}
	lines := CardLines(out.Card, out.Text)
	if len(lines) == 0 {
		lines = []string{out.Text}
	}
	all := true
	for _, it := range plan.Items {
		if named[it.Key] {
			for _, t := range it.Targets {
				if core.Exists(t.Path) {
					all = false
				}
			}
		}
	}
	return lines, all
}
