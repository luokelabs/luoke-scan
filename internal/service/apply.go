package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// Plans and carrying them out. Only what a plan lists, only the choices it offers, only after a click, and every
// target checked again (same file, not a link, unchanged, inside the home or temp folder).

const (
	// planGroupFrom: a kind with more items than this is one row on the page and the plan's card, its one choice for
	// all of them (planGroups): the plan takes everything that can be cleaned, however many (luoke-scan#129: no cap
	// that drops 41 installers into 「要你看看」), and a card still holds at most 200 components.
	planGroupFrom = 3
	// applyBudget: after this much of a scan_apply no more items are started (the rest stay, 「再点一次」), so the answer
	// comes within requestLimit even when one item (a big cache) takes a while.
	applyBudget = requestLimit - 60*time.Second
	// checkBudget is how long one scan_apply may spend looking for changes in its targets: walking a folder for changes,
	// it looks at the clock every 500 entries and, once past it, stops and leaves that target (and the rest) where they
	// are. The other checks of a target (same file, not a link, where it should be) take no time worth limiting.
	checkBudget = 120 * time.Second
	// requestLimit: 螺壳's main body ends a request (one luoke-scan mcp process) that has not answered in 300 s, with
	// SIGKILL (docs/host-interface.md §2; luoke-scan#122). scan_apply answers within this of its start: the checks and the
	// password dialog share it, and the dialog is not shown with less than dialogLeast left.
	requestLimit = 285 * time.Second
	dialogLeast  = 60 * time.Second
)

func isMalware(f core.Finding) bool {
	return f.Rule == "malware.clamav" || strings.HasPrefix(f.Rule, "malware.yara.")
}

// isUrgent (luoke-agent#2): malware, a known malicious package in use, and something new that starts by itself with
// nobody vouching for it. isUrgent: a file the virus database or YARA recognised, or a new thing that starts by itself with a serious sign
// (the rule makes those High); a new job that is only unsigned or a script goes on the round's card.
func isUrgent(f core.Finding) bool {
	return isMalware(f) || isMaliciousPackage(f) || (f.Rule == "persistence.new" && f.Severity == core.High)
}

// isMaliciousPackage: a project or a global install uses a package on the list of known malicious packages. Urgent,
// but nothing to delete from the card: the project is the user's own.
func isMaliciousPackage(f core.Finding) bool { return f.Rule == "supplychain.malicious" }

// plannable: a finding is something to delete, decided from the finding alone (no file system access).
func (s *Service) plannable(f core.Finding) bool {
	if trashableSkill(f) {
		return true // in the plan, a high-risk one to the Trash by default (baseSuggestion); not just a button to the Finder (luoke-scan#152)
	}
	if f.Rule == core.InstallScriptsRuleID {
		// A package manager's user config that one appended line changes (scripts-off): only for reference, and still
		// something scan_apply can do when asked.
		return f.Evidence["append"] != ""
	}
	if f.Verdict == core.Info {
		return false
	}
	switch f.Category {
	case core.CatCache, core.CatLeftover:
		return true
	case core.CatLeak:
		_, has := f.Evidence["prefix"]
		return s.Config.Context.Tmp != "" && has
	case core.CatStaleProject:
		return f.Rule == "stale.project" || f.Rule == "stale.artifacts"
	case core.CatSpace:
		return f.Rule == "stale.large-file" || f.Rule == "space.duplicates"
	case core.CatPersistence:
		// A job of this user's: its plist goes to the Trash (and it is stopped first). The system's need a password.
		return f.Rule == "persistence.launchagent-missing" || (f.Rule == "persistence.new" && f.Evidence["scope"] == "user-agent")
	case core.CatMalware:
		return isMalware(f)
	}
	return false
}

// trashableSkill: an AI plugin the user put in their own skills folder, or a local model whose chat template has
// words added: a folder of its own, safe to move to the Trash and put back. Not a plugin a marketplace installed (its
// manager puts it back; it is uninstalled in the tool), not a project's (the project is the user's), not an Ollama
// model (its files are shared between models).
func trashableSkill(f core.Finding) bool {
	if f.Path == "" || !strings.HasPrefix(f.Path, "/") {
		return false
	}
	switch {
	case strings.HasPrefix(f.Rule, "skill.") && f.Rule != "skill.partial":
		return f.Evidence["scope"] == string(core.ScopePersonal) && !pluginSkill(f)
	case f.Rule == "model.chat-template":
		return f.Evidence["tool"] != "Ollama"
	}
	return false
}

// pluginSkill: a skill that came with a plugin from a marketplace (Claude Code's plugins folder).
func pluginSkill(f core.Finding) bool { return f.Evidence["agent"] == "Claude Code 插件" }

// installRule is the round's install rule, with this service's settings (where /usr/local is: tests point it at a
// fake folder).
func (s *Service) installRule() *core.InstallLeftoverRule {
	for _, r := range s.Config.Rules {
		if x, ok := r.(*core.InstallLeftoverRule); ok {
			return x
		}
	}
	return &core.InstallLeftoverRule{UsrLocal: "/usr/local"}
}

// homebrew is the Intel Homebrew judgement for this home.
func (s *Service) homebrew() core.IntelHomebrew {
	b := s.installRule().Homebrew(s.Config.Context.Home, s.Config.Context.SystemLibrary)
	if s.Config.TrashFolders != nil && len(s.Config.TrashFolders) > 0 {
		b.Trash = s.Config.TrashFolders[0]
	}
	return b
}

// targetPaths is what deleting a finding would move.
func (s *Service) targetPaths(f core.Finding) []string {
	if !s.plannable(f) {
		return nil
	}
	switch f.Rule {
	case homebrewRule:
		// Its folders (the password step judges them again); the links to them stay.
		var out []string
		for _, name := range core.IntelHomebrewFolders {
			p := filepath.Join(s.installRule().UsrLocal, name)
			if _, _, _, ok := identity(p); ok {
				out = append(out, p)
			}
		}
		return out
	case homebrewLinksRule:
		brew := s.homebrew()
		state := filepath.Join(brew.UsrLocal, core.IntelHomebrewState)
		links, _ := brew.DanglingLinks()
		out := append([]string(nil), links...)
		if _, _, link, ok := identity(state); ok && !link {
			out = append(out, state)
		}
		return out
	}
	switch {
	case f.Category == core.CatLeak:
		prefix, has := f.Evidence["prefix"]
		tmp := s.Config.Context.Tmp
		if tmp == "" || !has {
			return nil
		}
		since := s.now().Add(-core.TempLeakQuiet)
		var out []string
		for _, c := range core.Children(tmp) {
			if p, ok := core.TempLeakPrefix(filepath.Base(c)); ok && p == prefix && !core.Changed(c, since, s.now()) {
				out = append(out, c)
			}
		}
		sort.Strings(out)
		return out
	case (f.Category == core.CatSpace && f.Rule == "space.duplicates") || (f.Category == core.CatStaleProject && f.Rule == "stale.artifacts") ||
		(f.Category == core.CatCache && f.Rule == "cache.electron"):
		var out []string
		for _, t := range strings.Split(f.Evidence["targets"], "\n") {
			if t != "" {
				out = append(out, t)
			}
		}
		return out
	case f.Category == core.CatLeftover:
		// An app's data is in several places; anything else (an old installer) is the file itself.
		id, has := f.Evidence["bundle_id"]
		if !has {
			return []string{f.Path}
		}
		ctx := &s.Config.Context
		out := core.LeftoverPlaces(id, ctx.Home, ctx.MayLook)
		if ctx.SystemLibrary != "" {
			out = append(out, core.LeftoverSystemPlaces(id, ctx.SystemLibrary)...)
		}
		return out
	}
	return []string{f.Path}
}

// roots are the folders a target must be strictly inside.
func (s *Service) roots() []string {
	out := []string{core.Canonical(s.Config.Context.Home)}
	if s.Config.Context.Tmp != "" {
		out = append(out, core.Canonical(s.Config.Context.Tmp))
	}
	return out
}

func (s *Service) inside(path string) bool {
	p := core.Canonical(filepath.Dir(path)) + "/" + filepath.Base(path)
	roots := s.roots()
	for _, r := range append(append([]string(nil), roots...), canonicalAll(s.Config.Context.ProjectRoots)...) {
		if p == r {
			return false
		}
	}
	for _, r := range roots {
		if strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func canonicalAll(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = core.Canonical(p)
	}
	return out
}

// insideHomebrewLinks: inside one of the folders of /usr/local Homebrew links into (bin, lib, share…), not one of
// those folders itself: where links to an Intel Homebrew that is gone may be deleted.
func (s *Service) insideHomebrewLinks(path string) bool {
	name, parent := filepath.Base(path), core.Canonical(filepath.Dir(path))
	if name == "" || name == "." || name == ".." || name == "/" {
		return false
	}
	for _, f := range core.IntelHomebrewLinkFolders {
		base := core.Canonical(filepath.Join(s.installRule().UsrLocal, f))
		if parent == base || strings.HasPrefix(parent, base+"/") {
			return true
		}
	}
	return false
}

// planItem is one item of a plan. admin: the targets in the system's Library (the plan that needs the password),
// else those in the home or temp folder.
func (s *Service) planItem(f core.Finding, key string, admin bool) *PlanItem {
	if f.Rule == core.InstallScriptsRuleID {
		if admin {
			return nil
		}
		return s.scriptsOffItem(f, key)
	}
	links := f.Rule == homebrewLinksRule // links themselves, deleted rather than moved
	var targets []Target
	for _, p := range s.targetPaths(f) {
		if !s.Config.Context.MayLook(p) { // never so much as a stat where this round may not look
			continue
		}
		var in bool
		switch {
		case admin:
			in = s.insideSystem(p)
		case links:
			in = s.insideHomebrewLinks(p)
		default:
			in = s.inside(p)
		}
		dev, ino, link, ok := identity(p)
		if !in || !ok || (!links && link) {
			continue
		}
		targets = append(targets, Target{Path: p, Device: dev, Inode: ino})
	}
	if len(targets) == 0 {
		return nil
	}
	// A rebuildable cache is deleted, not moved to the Trash: nothing is lost (its tool rebuilds it) and the space is
	// free at once (11-05, as automatic cleaning).
	cache := strings.HasPrefix(f.Rule, "cache.rebuildable.")
	suggested := baseSuggestion(f)
	options := []string{ChoiceTrash, ChoiceKeep, ChoiceIgnore}
	switch {
	case f.Rule == "space.duplicates":
		options = []string{ChoiceTrash, ChoiceClone, ChoiceKeep, ChoiceIgnore}
	case links:
		options = []string{ChoiceDelete, ChoiceKeep, ChoiceIgnore}
	case cache:
		options = []string{ChoiceRemove, ChoiceKeep, ChoiceIgnore}
	}
	it := PlanItem{Key: key, FindingID: s.fid(f), Rule: f.Rule, Category: string(f.Category), Title: f.Title, Bytes: f.Bytes,
		Targets: targets, Suggested: suggested, Options: options, Label: f.Evidence["label"]}
	if f.Rule == "space.duplicates" {
		it.Original = f.Path
	}
	if f.Rule == "leftover.app-data" {
		it.BundleID = f.Evidence["bundle_id"]
	}
	return &it
}

// plan: the same findings in the same report give the same plan (the id comes from the findings alone, so reading
// the outbox every minute finds the saved plan without looking at the disk again). admin: the plan of what is in the
// system's Library, carried out after the user's password; its items' keys are a0, a1… so both can share a card.
func (s *Service) plan(findings []core.Finding, report core.Report, scope, outboxID string, admin bool) *Plan {
	var candidates []core.Finding
	for _, f := range findings {
		var ok bool
		if admin {
			ok = (f.Rule == "leftover.app-data" || f.Rule == homebrewRule) && f.Verdict != core.Info && f.Evidence["system"] == "1"
		} else {
			ok = s.plannable(f) && f.Rule != homebrewRule
		}
		if ok {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sc := scope
	if admin {
		sc += "/admin"
	}
	parts := []string{sc, core.ISOTime(report.StartedAt.Time)}
	for _, f := range candidates {
		parts = append(parts, s.fid(f))
	}
	id := "p-" + core.ShortHash(parts...)
	if p, ok := LoadPlan(s.plansDir(), id); ok {
		if p.Tool != ToolVersion {
			s.suggestAgain(&p, candidates, admin, scope)
		}
		return &p
	}
	// Nothing could be planned for these: not looked at again. Kept on disk too, since every request may be a
	// process of its own.
	empty := filepath.Join(s.plansDir(), id+".empty")
	if _, known := s.noPlan.Load(id); known || core.Exists(empty) {
		return nil
	}
	// What automatic cleaning would take without asking (the four kinds, by its own stricter rules: an installer of an
	// app installed at that version, two weeks in Downloads; a copy in Downloads; a test tool's idle temp folder) is
	// suggested too, even where the rule itself says 「要确认」 (负责人 11-09 on luoke-scan#129: what the rules already
	// call safe goes by default; the user still clicks, and it comes back from the Trash). Not a kind the user turned
	// off or put something back from (the picker's Off).
	auto := s.autoSuggest(candidates, admin, scope)
	var items []PlanItem
	for i, f := range candidates {
		key := "i" + strconv.Itoa(i)
		if admin {
			key = "a" + strconv.Itoa(i)
		}
		if it := s.planItem(f, key, admin); it != nil {
			withAuto(it, auto)
			items = append(items, *it)
		}
	}
	if len(items) == 0 {
		s.noPlan.Store(id, true)
		os.MkdirAll(s.plansDir(), 0o700)
		os.WriteFile(empty, nil, 0o600)
		return nil
	}
	scanned := report.StartedAt
	p := Plan{ID: id, Created: core.Time{Time: s.now()}, Scanned: &scanned, OutboxID: outboxID, Items: items, Admin: admin,
		Tool: ToolVersion}
	p.Save(s.plansDir())
	return &p
}

// planGroup: items of one kind the page and the plan's card draw as one row with one choice: key is what that choice
// is sent as, options what every one of them offers.
type planGroup struct {
	key     string
	items   []PlanItem
	options []string
}

// planGroups: the kinds (one rule, one preselected choice) with more than planGroupFrom items, among what the user
// chooses for one by one (not the rebuildable caches, which have their own button, nor a virus, which has its own
// buttons); each keyed g-<its first item's key>, its items in the plan's order. Worked out from the plan alone, the
// same for the page that draws them and for scan_apply that hands their choice to each item.
func planGroups(items []PlanItem) []planGroup {
	var order []string
	by := map[string][]PlanItem{}
	for _, it := range items {
		if it.Suggested == ChoiceRemove || it.Rule == "malware.clamav" || strings.HasPrefix(it.Rule, "malware.yara.") {
			continue
		}
		k := it.Rule + "\x00" + it.Suggested
		if by[k] == nil {
			order = append(order, k)
		}
		by[k] = append(by[k], it)
	}
	var out []planGroup
	for _, k := range order {
		members := by[k]
		if len(members) <= planGroupFrom {
			continue
		}
		var options []string
		for _, o := range members[0].Options {
			all := true
			for _, m := range members[1:] {
				all = all && contains(m.Options, o)
			}
			if all {
				options = append(options, o)
			}
		}
		out = append(out, planGroup{key: "g-" + members[0].Key, items: members, options: options})
	}
	return out
}

// baseSuggestion: what an item is preselected to by its rule's verdict: safe ones go (a rebuildable cache deleted, the
// rest to the Trash), the others stay until the user picks (改成不跑 too).
func baseSuggestion(f core.Finding) string {
	if trashableSkill(f) && f.Severity == core.High {
		return ChoiceTrash // a high-risk AI plugin or model: to the Trash by default, back from it (luoke-scan#152); the rest 先不动
	}
	switch {
	case f.Rule == core.InstallScriptsRuleID || f.Verdict != core.Safe:
		return ChoiceKeep
	case strings.HasPrefix(f.Rule, "cache.rebuildable."):
		return ChoiceRemove
	}
	return ChoiceTrash
}

// autoSuggest: what automatic cleaning would take of these, by finding id; only for the round's plan.
func (s *Service) autoSuggest(candidates []core.Finding, admin bool, scope string) map[string]core.AutoHow {
	auto := map[string]core.AutoHow{}
	if !admin && scope == "findings" {
		for _, x := range s.autoPicker().Pick(candidates) {
			auto[x.FindingID] = x.How
		}
	}
	return auto
}

// withAuto: an item automatic cleaning would take is preselected to go too, where its rule leaves it to the user.
func withAuto(it *PlanItem, auto map[string]core.AutoHow) {
	how, ok := auto[it.FindingID]
	if !ok || it.Suggested != ChoiceKeep {
		return
	}
	switch {
	case how == core.HowTrash && contains(it.Options, ChoiceTrash):
		it.Suggested = ChoiceTrash
	case (how == core.HowRemove || how == core.HowTool) && contains(it.Options, ChoiceRemove):
		it.Suggested = ChoiceRemove
	}
}

// suggestAgain: a plan an older version of this tool saved (luoke-scan#129: 14:37's plan kept every installer at
// 「先不动」 after the update that preselects them) takes this version's defaults, from the same round's findings: the
// same items and targets as the round found them (nothing is looked at on disk again), each preselected as this version
// would. The plan records no choice of the user's (those live on the card, and the page sends its defaults on every
// read), so there is nothing of theirs to keep. Saved, so it happens once.
func (s *Service) suggestAgain(p *Plan, candidates []core.Finding, admin bool, scope string) {
	byID := map[string]core.Finding{}
	for _, f := range candidates {
		byID[s.fid(f)] = f
	}
	auto := s.autoSuggest(candidates, admin, scope)
	for i := range p.Items {
		it := &p.Items[i]
		f, ok := byID[it.FindingID]
		if !ok {
			continue
		}
		it.Suggested = baseSuggestion(f)
		withAuto(it, auto)
	}
	p.Tool = ToolVersion
	p.Save(s.plansDir())
}

// plans: the plan offered on a card and the one beside it that needs the password, each knowing the other
// (luoke-agent#2: two plans, two buttons, so what needs no password is not held up by the dialog).
func (s *Service) plans(findings []core.Finding, report core.Report, scope, outboxID string) (*Plan, *Plan) {
	p := s.plan(findings, report, scope, outboxID, false)
	a := s.plan(findings, report, scope, outboxID, true)
	if p != nil && a != nil && (p.Sibling != a.ID || a.Sibling != p.ID) {
		p.Sibling, a.Sibling = a.ID, p.ID
		p.Save(s.plansDir())
		a.Save(s.plansDir())
	}
	return p, a
}

func (s *Service) planTool(args O, st State) (ToolOutput, error) {
	r := s.Store.LastReport()
	if r == nil {
		return ToolOutput{}, Fail("not_ready", "还没查过，先查一轮。")
	}
	scope := "all"
	if v, has := args["scope"]; has {
		str, ok := v.(string)
		if !ok || (str != "all" && str != "cache") {
			return ToolOutput{}, Fail("invalid", "scope 只能是 all 或 cache")
		}
		scope = str
	}
	var f []core.Finding
	for _, x := range s.visible(*r, st) {
		if scope == "all" || x.Category == core.CatCache {
			f = append(f, x)
		}
	}
	p, a := s.plans(f, *r, scope, "")
	if p == nil && a == nil {
		return ToolOutput{Text: "现在没有可以清理的。"}, nil
	}
	first := p
	if first == nil {
		first = a
	}
	c := NewCard("plan-" + first.ID)
	if p != nil {
		s.planBody(c, *p, "这几项可以这样处理", "", f)
	} else {
		c.Heading("这几项可以这样处理")
	}
	if a != nil {
		s.adminBody(c, *a, f)
	}
	var texts []string
	if p != nil {
		texts = append(texts, planSummary(*p))
	}
	if a != nil {
		texts = append(texts, fmt.Sprintf("另有 %d 项在系统目录里，要输入 Mac 的密码", len(a.Items)))
	}
	return ToolOutput{Text: strings.Join(texts, "；"), Card: c.Messages()}, nil
}

func planSummary(p Plan) string {
	var bytes int64
	n := 0
	for _, it := range p.Items {
		if Clears(it.Suggested) {
			n++
			if it.Bytes != nil {
				bytes += *it.Bytes
			}
		}
	}
	out := fmt.Sprintf("%d 项可以处理", len(p.Items))
	if n > 0 {
		out += fmt.Sprintf("，建议清掉的 %d 项能腾出 %s", n, core.FormatBytes(bytes))
	}
	return out + "；要确认的默认先不动，你选了才动。"
}

func sizeNote(b *int64) string {
	if b == nil {
		return ""
	}
	return "（" + core.FormatBytes(*b) + "）"
}

// withSize: a title with its size after it, unless the title already says it.
func withSize(title string, b *int64) string {
	if b == nil || *b <= 0 || strings.Contains(title, core.FormatBytes(*b)) {
		return title
	}
	return title + sizeNote(b)
}

func labeled(options []string) []Option {
	out := make([]Option, len(options))
	for i, o := range options {
		out[i] = Option{Value: o, Label: ChoiceLabels[o], Icon: choiceIcons[o]}
	}
	return out
}

// planBody is one picker per item (suggested choice preselected), then the button that runs the plan. findings: the
// ones the items are for, so what the model said about one is under it (modelLines). extra: buttons that go in the same
// row as 按上面的选择清理, side by side (打开自动清理).
func (s *Service) planBody(c *Card, p Plan, title, note string, findings []core.Finding, extra ...Button) {
	c.Heading(title)
	if note != "" {
		c.Text(note, true)
	}
	about := map[string]core.Finding{}
	for _, f := range findings {
		about[s.fid(f)] = f
	}
	// A kind with many items is one choice for all of them, at its first item's place (planGroups), as on the page
	group := map[string]planGroup{}
	for _, g := range planGroups(p.Items) {
		for _, it := range g.items {
			group[it.Key] = g
		}
	}
	for _, it := range p.Items {
		g, grouped := group[it.Key]
		switch {
		case !grouped:
			c.Choice(it.Key, s.itemTitle(it, about), labeled(it.Options), it.Suggested)
		case g.items[0].Key == it.Key:
			e := s.groupEntry(g, about)
			if e.size != "" {
				e.title += "（" + e.size + "）"
			}
			c.Choice(g.key, e.title, e.options, e.selected)
		}
	}
	c.Buttons(append([]Button{{Label: "按上面的选择清理", Event: "scan_apply", Context: O{"plan_id": p.ID, "choices": ChoicesPath}, Primary: true}}, extra...))
}

// itemTitle: a plan item for the user: the finding's plain title (no path, id or rule), with its size.
func (s *Service) itemTitle(it PlanItem, about map[string]core.Finding) string {
	if f, ok := about[it.FindingID]; ok {
		if t, _ := s.plain(f); t != "" {
			for _, o := range it.Options { // 选择框已经写着「删掉（会自动重建）」：标题里不再说一遍
				if o == ChoiceRemove {
					t = strings.TrimSuffix(t, "，删了会自动重建")
				}
			}
			if f.Bytes == nil && it.Bytes != nil {
				return withSize(t, it.Bytes)
			}
			return t
		}
	}
	return withSize(it.Title, it.Bytes)
}

// adminBody is the items that need the password, under their own heading and button on the same card. findings:
// the ones the items are for, so their titles are the plain ones too (none: the last round's, so a plan shown again
// after an answer reads the same as the first time).
func (s *Service) adminBody(c *Card, a Plan, findings []core.Finding) {
	if findings == nil {
		if r := s.Store.LastReport(); r != nil {
			findings = r.Findings
		}
	}
	c.Divider()
	c.Text("这几项删除时会请你输入 Mac 的密码", true)
	about := map[string]core.Finding{}
	for _, f := range findings {
		about[s.fid(f)] = f
	}
	for _, it := range a.Items {
		c.Choice(it.Key, s.itemTitle(it, about), labeled(it.Options), it.Suggested, "admin_choices")
	}
	c.Buttons([]Button{{Label: "移到废纸篓（要输入密码）", Event: "scan_apply", Context: O{"plan_id": a.ID, "choices": AdminChoicesPath}}})
}

// touched: anything under path was written between since and now (a file dated in the future does not count:
// unpacked files can carry future dates). ok false when deadline passed first. .git is not walked.
func touched(path string, since, now, deadline time.Time) (bool, bool) {
	recent := func(d time.Time) bool { return !d.Before(since) && !d.After(now) }
	if top, ok := core.Item(path); ok && recent(top.Modified) {
		return true, true
	}
	n := 0
	late := false
	unchanged := core.Tree(path, func(e core.Entry) bool { return !e.InGit }, func(e core.Entry) bool {
		if !e.InGit && recent(e.Modified) {
			return false
		}
		n++
		if n%500 == 0 && time.Now().After(deadline) {
			late = true
			return false
		}
		return true
	})
	if unchanged {
		return false, true
	}
	if late {
		return false, false
	}
	return true, true
}

// removeCache: a rebuildable cache the user chose to delete, checked again as any target, then as automatic cleaning
// checks one (only at its known place, no link on the way to it, its tool not running); deleted following no link,
// and written down as deleted. What it freed, and why not, if not.
func (s *Service) removeCache(it PlanItem, plan Plan, deadline time.Time) (int64, []string) {
	c, ok := knownCacheByRule(it.Rule)
	if !ok {
		return 0, []string{"不是会重建的缓存"}
	}
	at := filepath.Join(s.Config.Context.Home, c.Path)
	var freed int64
	var why []string
	for _, t := range it.Targets {
		if r := s.refuse(t, it, plan, deadline); r != "" {
			if r != absent {
				why = append(why, r)
			}
			continue
		}
		realHome, ok1 := realPath(s.Config.Context.Home)
		real, ok2 := realPath(at)
		if t.Path != at || !ok1 || !ok2 || real != realHome+"/"+c.Path {
			why = append(why, "路上有链接，或者不在它该在的位置")
			continue
		}
		if users := core.CacheUsers[c.ID]; anyRunning(users, s.Config.Running()) {
			why = append(why, c.Tool+" 正在跑，等它停了再删")
			continue
		}
		before := core.AllocatedSize(at)
		err := s.Config.Remove(real)
		left := int64(0)
		if core.Exists(at) {
			left = core.AllocatedSize(at)
		}
		gone := before - left
		if gone < 0 {
			gone = 0
		}
		if gone > 0 {
			s.recordRemoved(at, plan.ID, it.Rule, it.Title, core.Size(gone), "")
		}
		freed += gone
		if err != nil {
			why = append(why, removeWhy(err, left))
		}
	}
	return freed, why
}

// plainErr: why something could not be moved, in a few words and without its path (an *os.PathError says the whole
// /Users/… path, and the result is shown to the user).
func plainErr(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		if msg := err.Error(); msg != "" && !strings.Contains(msg, "/") {
			return msg // already a reason in words (notWritten)
		}
		return "出错了"
	}
	switch errno {
	case syscall.EACCES, syscall.EPERM:
		return "没有权限"
	case syscall.ENOENT:
		return "找不到"
	case syscall.EBUSY, syscall.ETXTBSY:
		return "正在使用"
	case syscall.ENOSPC:
		return "空间不够"
	case syscall.EXDEV:
		return "不在同一个磁盘上"
	}
	return "出错了"
}

// removeWhy: what a cache's removal left and why: 「312 个文件已锁定，剩 8.1 GB」.
func removeWhy(err error, left int64) string {
	reason := "没删成"
	if l, ok := err.(*core.RemoveLeft); ok {
		reason = l.Plain()
	}
	if left > 0 {
		return reason + "，剩 " + core.FormatBytes(left)
	}
	return reason
}

func knownCacheByRule(rule string) (core.RebuildableCache, bool) {
	for _, c := range core.KnownCaches {
		if "cache.rebuildable."+c.ID == rule {
			return c, true
		}
	}
	return core.RebuildableCache{}, false
}

func anyRunning(users []string, running map[string]bool) bool {
	for _, u := range users {
		if running[u] {
			return true
		}
	}
	return false
}

// refuse is why a target must not be moved now, or "" when it may.
func (s *Service) refuse(t Target, item PlanItem, plan Plan, deadline time.Time) string {
	dev, ino, link, ok := identity(t.Path)
	if !ok {
		return absent
	}
	if link {
		return "现在是一个链接"
	}
	if dev != t.Device || ino != t.Inode {
		return "已经换成了别的东西"
	}
	if !s.inside(t.Path) {
		return "不在你的家目录或临时目录里"
	}
	// In the home or temp folder, in a folder only an administrator may change.
	if syscall.Access(filepath.Dir(t.Path), 2 /* W_OK */) != nil {
		return "放它的文件夹要管理员权限才能改，要删得在访达里删（会要密码）"
	}
	if _, mounted := core.MountInside(t.Path); mounted {
		return "里面挂着另一个磁盘，先推出它"
	}
	// A rebuildable cache changes whenever its tool runs, and the tool makes it again: being written to is no reason to
	// keep it. Anything else written to since the round that judged it gets looked at again.
	if !strings.HasPrefix(item.Rule, "cache.rebuildable.") {
		since := plan.Created.Time
		if plan.Scanned != nil && plan.Scanned.Before(since) {
			since = plan.Scanned.Time
		}
		changed, inTime := touched(t.Path, since, s.now(), deadline)
		if !inTime {
			return "太大了，这次来不及核对完"
		}
		if changed {
			return "查过以后又改过"
		}
	}
	// Still output its tool makes again: its tool's file next to it, nothing in it tracked, no repository in it.
	if item.Rule == "stale.artifacts" {
		if _, ok := core.StaleArtifactKind(t.Path); !ok {
			return "不再像能重新生成的了（项目文件不在了，或者 git 里有它的文件）"
		}
	}
	// A commit, branch or stash made since only shows in .git, which the check above leaves out: ask git again.
	if item.Rule == "stale.project" {
		w, ok := core.StaleWouldLose(t.Path)
		if !ok {
			return "已经不是 git 仓库了"
		}
		if len(w.Lose) > 0 {
			return "查过以后有了只在这台 Mac 上的工作（" + w.Lose[0] + "）"
		}
	}
	return ""
}

// deleteHomebrewLinks: links to an Intel Homebrew that is gone for good, deleted (they hold nothing), and its state
// folder, to the Trash. Nothing when its folders are back, or still in the Trash. Each only if still the one the plan
// saw, in a folder Homebrew links into (as the folder actually opened says), and, for a link, still pointing into
// Homebrew's folders at nothing (read in that folder). The links are written down as one entry: nothing to put back.
func (s *Service) deleteHomebrewLinks(it PlanItem, plan Plan) (ok, absentN, removed int, why []string) {
	brew := s.homebrew()
	if it.Rule != homebrewLinksRule {
		return 0, 0, 0, []string{"不能直接删"}
	}
	if !brew.Gone() {
		return 0, 0, 0, []string{"旧的 Homebrew 还在（或还在废纸篓里，放回就要用这些链接）"}
	}
	state := filepath.Join(brew.UsrLocal, core.IntelHomebrewState)
	for _, t := range it.Targets {
		dev, ino, link, there := identity(t.Path)
		if !there {
			absentN++
			continue
		}
		if dev != t.Device || ino != t.Inode {
			why = append(why, "已经换成了别的东西")
			continue
		}
		if !s.insideHomebrewLinks(t.Path) {
			why = append(why, "不在 /usr/local 里 Homebrew 放链接的地方")
			continue
		}
		if !link {
			if _, mounted := core.MountInside(t.Path); t.Path != state || mounted {
				why = append(why, "不是链接")
				continue
			}
			if _, _, err := s.trashAndRecord(t.Path, plan.ID, it.Rule, "Homebrew 的状态文件夹", nil, "", nil); err != nil {
				why = append(why, "没能移进废纸篓（"+plainErr(err)+"）")
			} else {
				ok++
			}
			continue
		}
		parent, has := realPath(filepath.Dir(t.Path))
		if !has {
			parent = filepath.Dir(t.Path)
		}
		dfd := core.OpenNoFollow(parent)
		if dfd < 0 {
			why = append(why, "所在的文件夹打不开，或路上有链接")
			continue
		}
		func() {
			defer syscall.Close(dfd)
			// Where the folder opened really is: a folder swapped for a link after the check above is not followed.
			opened, err := core.FDPath(dfd)
			name := filepath.Base(t.Path)
			if err != nil || !s.insideHomebrewLinks(opened+"/"+name) {
				why = append(why, "不在 /usr/local 里 Homebrew 放链接的地方")
				return
			}
			var st syscall.Stat_t
			if core.Fstatat(dfd, name, &st, core.AtSymlinkNoFollow) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFLNK || st.Ino != t.Inode {
				why = append(why, "已经换成了别的东西")
				return
			}
			if !brew.IsDanglingAt(dfd, name, opened) {
				why = append(why, "指向的东西又在了")
				return
			}
			if err := core.Unlinkat(dfd, name, 0); err != nil {
				why = append(why, "没删掉（"+errText(err)+"）")
				return
			}
			ok++
			removed++
		}()
	}
	if removed > 0 {
		s.recordRemoved(brew.UsrLocal, plan.ID, it.Rule, fmt.Sprintf("%d 个指向旧 Homebrew 的失效链接", removed), nil, "")
	}
	return ok, absentN, removed, why
}

type titled struct {
	title string
	bytes *int64
}

type outcome struct {
	item   PlanItem
	choice string
	ok     bool
}

func sumBytes(xs []titled) int64 {
	var n int64
	for _, x := range xs {
		if x.bytes != nil {
			n += *x.bytes
		}
	}
	return n
}

func (s *Service) apply(args, meta O) (ToolOutput, error) {
	// 1. The plan and the user's choices, checked against what the plan offered.
	pid, _ := args["plan_id"].(string)
	plan, ok := LoadPlan(s.plansDir(), pid)
	if pid == "" || !ok {
		return ToolOutput{}, Fail("stale", "这份方案找不到了（可能过期了），重新查一下再来。")
	}
	choices, ok := args["choices"].(map[string]any)
	if !ok {
		return ToolOutput{}, Fail("invalid", "choices 要是对象")
	}
	// A kind drawn as one row sends one choice for all of its items (planGroups): each of them gets it, unless it was
	// sent on its own too.
	for _, g := range planGroups(plan.Items) {
		v, has := choices[g.key]
		if !has {
			continue
		}
		delete(choices, g.key)
		for _, it := range g.items {
			if _, own := choices[it.Key]; !own {
				choices[it.Key] = v
			}
		}
	}
	keys := map[string]bool{}
	for _, it := range plan.Items {
		keys[it.Key] = true
	}
	var sent []string
	for k := range choices {
		sent = append(sent, k)
	}
	sort.Strings(sent)
	for _, k := range sent {
		if !keys[k] {
			return ToolOutput{}, Fail("invalid", "方案里没有这一项："+k)
		}
	}
	picks := map[string]string{}
	for _, it := range plan.Items {
		v, has := choices[it.Key]
		if !has {
			picks[it.Key] = ChoiceKeep // not sent: leave it alone
			continue
		}
		arr, ok := v.([]any)
		var pick string
		if ok && len(arr) == 1 {
			pick, _ = arr[0].(string)
		}
		if pick == "" || !contains(it.Options, pick) {
			return ToolOutput{}, Fail("invalid", "「"+it.Title+"」的选项不对")
		}
		picks[it.Key] = pick
	}
	if !s.begin(plan.ID) {
		return ToolOutput{}, Fail("not_ready", "这份方案正在处理，等一下再看结果。")
	}
	defer s.end(plan.ID)
	if plan.Admin {
		return s.applyAdmin(plan, picks, meta, false, time.Now().Add(requestLimit))
	}

	// 2. Checking and moving can take minutes; the outbox stays readable meanwhile.
	started := time.Now()
	deadline := started.Add(checkBudget)
	var moved, cloned, removedCaches, changed []titled
	var partly, skipped, unchanged, ignored, gone, unrecorded []string
	partlyDeleted := 0 // of partly, the caches: deleted, not moved to the Trash
	var outcomes []outcome
	var ignoredItems []PlanItem
	var goneIDs []string // items with nothing left where the click found some or all of it already gone (markGone)
	deletedLinks := 0
	// While it works, the window shows which one it is on (luoke-scan#152: a click on 「清理」 gave no sign for minutes).
	progress := s.Server.Progress(meta)
	work, step := 0, 0
	for _, it := range plan.Items {
		if pick := picks[it.Key]; pick != ChoiceKeep && pick != ChoiceIgnore {
			work++
		}
	}
	for _, it := range plan.Items {
		if pick := picks[it.Key]; pick != ChoiceKeep && pick != ChoiceIgnore {
			if time.Since(started) > applyBudget {
				skipped = append(skipped, it.Title+"：这次来不及做完，再点一次")
				continue
			}
			step++
			progress(step, work, progressLine(pick, it))
		}
		switch picks[it.Key] {
		case ChoiceIgnore:
			ignored = append(ignored, it.FindingID)
			ignoredItems = append(ignoredItems, it)
		case ChoiceClone:
			// Nothing moves: each copy becomes a clone of the one that stays, once both are checked again.
			if it.Original == "" {
				skipped = append(skipped, resultName(it.Title)+"：未能清理，不能换成克隆")
				continue
			}
			n := 0
			var why []string
			for _, t := range it.Targets {
				if r := s.refuse(t, it, plan, deadline); r != "" {
					why = append(why, r)
					continue
				}
				if err := s.Config.Clone(it.Original, t.Path); err != nil {
					why = append(why, "没能换成克隆（"+plainErr(err)+"）")
					continue
				}
				n++
			}
			switch {
			case len(why) == 0:
				cloned = append(cloned, titled{it.Title, it.Bytes})
			case n > 0:
				partly = append(partly, fmt.Sprintf("%s：换了 %d/%d，其余%s", resultName(it.Title), n, len(it.Targets), strings.Join(uniq(why), "、")))
			default:
				skipped = append(skipped, resultName(it.Title)+"：未能清理，"+strings.Join(uniq(why), "、"))
			}
			outcomes = append(outcomes, outcome{it, ChoiceClone, n > 0})
		case ChoiceTrash:
			n, absentN := 0, 0
			var why []string
			for _, t := range it.Targets {
				if r := s.refuse(t, it, plan, deadline); r != "" {
					if r == absent {
						absentN++ // already gone: nothing left to do
					} else {
						why = append(why, r)
					}
					continue
				}
				// One of several copies goes only while the one that stays is still there with the same contents.
				if it.Rule == "space.duplicates" {
					_, _, link, there := identity(it.Original)
					if it.Original == "" || !there || link || !core.SameContents(it.Original, t.Path) {
						why = append(why, "要留的那份已经不在或改过了")
						continue
					}
				}
				// Stopped before its plist goes: a job that is running keeps running after the file is moved.
				if it.Rule == "persistence.new" && it.Label != "" {
					s.Config.Command("/bin/launchctl", []string{"bootout", "gui/" + strconv.Itoa(os.Getuid()) + "/" + it.Label})
				}
				// Written down as it goes, so "放回" finds it.
				var b *int64
				if len(it.Targets) == 1 {
					b = it.Bytes
				}
				_, recorded, err := s.trashAndRecord(t.Path, plan.ID, it.Rule, it.Title, b, "", &ident{t.Device, t.Inode})
				if err != nil {
					why = append(why, "没能移进废纸篓（"+plainErr(err)+"）")
					continue
				}
				n++
				if !recorded {
					unrecorded = append(unrecorded, filepath.Base(t.Path))
				}
			}
			if n > 0 && it.Rule == "persistence.launchagent-missing" && it.Label != "" {
				s.Config.Command("/bin/launchctl", []string{"bootout", "gui/" + strconv.Itoa(os.Getuid()) + "/" + it.Label})
			}
			if n > 0 || len(why) > 0 {
				outcomes = append(outcomes, outcome{it, ChoiceTrash, n > 0})
			}
			if len(why) == 0 && absentN > 0 {
				goneIDs = append(goneIDs, it.FindingID)
			}
			switch {
			case len(why) == 0 && n > 0:
				moved = append(moved, titled{it.Title, it.Bytes})
			case len(why) == 0:
				gone = append(gone, resultName(it.Title))
			case n > 0:
				partly = append(partly, fmt.Sprintf("%s：移了 %d/%d，其余%s", resultName(it.Title), n, len(it.Targets)-absentN, strings.Join(uniq(why), "、")))
			default:
				skipped = append(skipped, resultName(it.Title)+"：未能清理，"+strings.Join(uniq(why), "、"))
			}
		case ChoiceRemove:
			freed, why := s.removeCache(it, plan, deadline)
			outcomes = append(outcomes, outcome{it, ChoiceRemove, freed > 0})
			switch {
			case len(why) == 0 && freed > 0:
				removedCaches = append(removedCaches, titled{it.Title, core.Size(freed)})
			case len(why) == 0:
				gone = append(gone, resultName(it.Title))
				goneIDs = append(goneIDs, it.FindingID)
			case freed > 0:
				partly = append(partly, resultName(it.Title)+"：未删完，"+strings.Join(uniq(why), "、"))
				partlyDeleted++ // deleted for good: nothing in the Trash, nothing to put back
			default:
				skipped = append(skipped, resultName(it.Title)+"：未能清理，"+strings.Join(uniq(why), "、"))
			}
		case ChoiceScriptsOff:
			ok, why := s.scriptsOff(it, plan)
			outcomes = append(outcomes, outcome{it, ChoiceScriptsOff, ok})
			switch {
			case ok && why != "":
				changed = append(changed, titled{it.Title + "：" + why, nil})
			case ok:
				changed = append(changed, titled{it.Title, nil})
			default:
				unchanged = append(unchanged, it.Title+"：未能更改，"+why) // a setting, not a file: not 「未能清理」
			}
		case ChoiceDelete:
			n, absentN, links, why := s.deleteHomebrewLinks(it, plan)
			deletedLinks += links
			switch {
			case len(why) == 0 && n == 0:
				gone = append(gone, resultName(it.Title))
				goneIDs = append(goneIDs, it.FindingID)
			case len(why) > 0 && n > 0:
				partly = append(partly, fmt.Sprintf("%s：删了 %d/%d，其余%s", resultName(it.Title), n, len(it.Targets)-absentN, strings.Join(uniq(why), "、")))
			case len(why) > 0:
				skipped = append(skipped, resultName(it.Title)+"：未能清理，"+strings.Join(uniq(why), "、"))
			}
		}
	}

	// 3. Record what the user decided (under the state file's lock).
	var parts []string
	if len(moved) > 0 {
		p := fmt.Sprintf("移到废纸篓 %d 项", len(moved))
		if b := sumBytes(moved); b > 0 {
			p += "（" + core.FormatBytes(b) + "）"
		}
		parts = append(parts, p)
	}
	if len(removedCaches) > 0 {
		p := fmt.Sprintf("删掉会重建的缓存 %d 项", len(removedCaches))
		if b := sumBytes(removedCaches); b > 0 {
			p += "（腾出 " + core.FormatBytes(b) + "）"
		}
		parts = append(parts, p)
	}
	if len(cloned) > 0 {
		p := fmt.Sprintf("换成克隆 %d 项", len(cloned))
		if b := sumBytes(cloned); b > 0 {
			p += "（腾出 " + core.FormatBytes(b) + "）"
		}
		parts = append(parts, p)
	}
	if deletedLinks > 0 {
		parts = append(parts, fmt.Sprintf("删掉了 %d 个失效的链接", deletedLinks))
	}
	if len(changed) > 0 {
		parts = append(parts, fmt.Sprintf("改了 %d 个包管理器的设置，依赖装的时候不再跑脚本", len(changed)))
	}
	if len(partly) > 0 {
		parts = append(parts, fmt.Sprintf("部分处理了 %d 项", len(partly)))
	}
	if len(ignored) > 0 {
		parts = append(parts, fmt.Sprintf("以后不再提 %d 项", len(ignored)))
	}
	if len(gone) > 0 {
		parts = append(parts, fmt.Sprintf("%d 项找不到，已跳过", len(gone)))
	}
	if len(skipped) > 0 {
		parts = append(parts, fmt.Sprintf("%d 项未能清理", len(skipped)))
	}
	if len(unchanged) > 0 {
		parts = append(parts, fmt.Sprintf("%d 项未能更改", len(unchanged)))
	}
	text := "没有改动什么。"
	if len(parts) > 0 {
		text = strings.Join(parts, "，") + "。"
	}
	// Done once nothing the user picked is left: what is already gone counts; what was only partly moved does not.
	done := len(skipped) == 0 && len(unchanged) == 0 && len(partly) == 0
	// What the answer says, besides the card: clicked on a page, the window shows only this one line (a toast), never
	// the card's lines below it, so what was left and why goes in too when it is one or two things (luoke-scan#152)
	said := text
	if left := append(append(append([]string{}, partly...), skipped...), unchanged...); len(left) > 0 && len(left) <= 2 {
		said += strings.Join(left, "；") + "。"
	}
	newly := s.markIgnored(ignored)
	s.markGone(goneIDs)
	// The plan beside it on the card (the one that needs the password) still waits: its controls come back.
	other := s.pendingSibling(plan)
	// Clicked on the low-space card or the round's card in 「今天」 and something was left (a cache whose tool is
	// running, a file it may not move): the answer has nothing to click again, so the card does not stay under 「要你决定」
	// with nothing to decide. It settles as a plan carried out does; what was left is still in the round, on the scan page
	// and on the next round's card. An urgent card stays, with 「再试一次」: the same plan and choices, clicked again.
	own := ownCard(meta, plan)
	settled := done || (other == nil && (own == "round" || own == "space"))
	retry := !done && other == nil && own == "security"
	// Clicked on the round's card (「清理 N 项缓存」) while other things still wait on the scan page: the card stays, as
	// the round is now (the caches gone, 「去扫描页看 N 项」); the round is done with only when nothing is left to look at.
	var round *redraw
	if settled {
		if rd := s.roundRedraw(meta); rd != nil && rd.rest > 0 {
			round = rd
		} else {
			s.finish(plan)
		}
	}
	report := s.Store.LastReport()
	var fresh []PlanItem
	for _, it := range ignoredItems {
		if newly[it.FindingID] {
			fresh = append(fresh, it)
		}
	}
	s.remember(append(s.cleanedRecords(plan.ID, outcomes, report), s.ignoredRecords(fresh, plan.ID, report)...))
	// The answer as data (top-level ADR 0028): the counts and bytes of each outcome; left: what was not done, each
	// with its reason (still sentences: the reasons have no codes yet); what the answer's buttons would do.
	trashedAny := len(moved) > 0 || len(partly) > partlyDeleted
	data := O{"type": "applied", "moved": O{"count": len(moved), "bytes": sumBytes(moved)},
		"removed": O{"count": len(removedCaches), "bytes": sumBytes(removedCaches)},
		"cloned":  O{"count": len(cloned), "bytes": sumBytes(cloned)}, "links": deletedLinks, "scriptsOff": len(changed),
		"partly": len(partly), "ignored": len(ignored), "gone": len(gone), "skipped": len(skipped),
		"unchanged": len(unchanged), "left": strs(append(append(append([]string{}, partly...), skipped...), unchanged...)),
		"trashed": trashedAny, "restore": nil, "retry": nil, "unrecorded": strs(unrecorded), "password": other != nil,
		"round": nil}
	if trashedAny || len(changed) > 0 {
		data["restore"] = plan.ID
	}
	if retry {
		again := O{}
		for k, v := range picks {
			if v != ChoiceKeep {
				again[k] = A{v}
			}
		}
		data["retry"] = O{"plan": plan.ID, "choices": again}
	}
	if round != nil {
		data["round"] = round.data
		return ToolOutput{Text: said, Card: s.answerCard(meta, false, round.card), Done: Bool(false), Extra: O{"data": data}}, nil
	}
	top := s.roundTop(plan) // on the round's card, what was cleaned without a click stays on top
	card := s.answerCard(meta, other != nil, func(c *Card) {
		if top != nil {
			top(c)
		}
		c.Text(text)
		for _, m := range moved {
			c.Text(m.title, true)
		}
		for _, m := range cloned {
			c.Text(m.title+"：换成了克隆，几份都还在", true)
		}
		for _, m := range changed {
			c.Text(m.title, true)
		}
		for _, p := range partly {
			c.Text(p, true)
		}
		for _, x := range skipped {
			c.Text(x, true)
		}
		for _, x := range unchanged {
			c.Text(x, true)
		}
		trashed := len(moved) > 0 || len(partly) > partlyDeleted
		if trashed {
			c.Text("倒掉废纸篓才真正腾出空间。", true)
		}
		var buttons []Button
		if retry {
			again := O{}
			for k, v := range picks {
				if v != ChoiceKeep { // what was not sent is left alone, as now
					again[k] = A{v}
				}
			}
			buttons = append(buttons, Button{Label: "再试一次", Event: "scan_apply", Context: O{"plan_id": plan.ID, "choices": again}, Primary: true})
		}
		if trashed || len(changed) > 0 {
			buttons = append(buttons, Button{Label: "放回", Event: "scan_restore", Context: O{"id": plan.ID}})
		}
		if len(buttons) > 0 {
			c.Buttons(buttons)
		}
		if len(unrecorded) > 0 {
			c.Text("这几项没记进清理记录，要放回得在访达里打开废纸篓："+strings.Join(unrecorded, "、"), true)
		}
		if other != nil {
			s.adminBody(c, *other, nil)
		}
	})
	return ToolOutput{Text: said, Card: card, Done: Bool(settled && other == nil), Extra: O{"data": data}}, nil
}

// ownCard: which of the cards in 「今天」 the plan was offered on the click came from: "round" (the round's card),
// "space" (the low-space card), "security" (an urgent card), or "" (one of this tool's pages, another card, a terminal).
func ownCard(meta O, plan Plan) string {
	ua, _ := meta[UserAction].(map[string]any)
	sid, _ := ua["surfaceId"].(string)
	id := plan.OutboxID
	switch {
	case sid == "":
	case strings.HasPrefix(id, "round/") && sid == roundSurface(id):
		return "round"
	case strings.HasPrefix(id, "space/") && sid == "space-"+core.ShortHash(id):
		return "space"
	case strings.HasPrefix(id, "security/") && sid == "security-"+core.ShortHash(strings.TrimPrefix(id, "security/")):
		return "security"
	}
	return ""
}

// resultName: an item's title in the result lines, without the cache's 「，删了会自动重建」 (it is done or not done now).
func resultName(title string) string { return strings.TrimSuffix(title, "，删了会自动重建") }

// progressLine is what the window shows under the clicked button while an item is being done.
func progressLine(pick string, it PlanItem) string {
	name := resultName(it.Title)
	switch pick {
	case ChoiceRemove:
		return "正在删：" + name
	case ChoiceClone:
		return "正在换成克隆：" + name
	case ChoiceScriptsOff:
		return "正在改设置：" + name
	case ChoiceDelete:
		return "正在删失效的链接：" + name
	}
	return "正在移到废纸篓：" + name
}

// markIgnored records "以后别提" for these findings; the ones not ignored before.
func (s *Service) markIgnored(ids []string) map[string]bool {
	newly := map[string]bool{}
	if len(ids) == 0 {
		return newly
	}
	at := core.Time{Time: s.now()}
	s.mutate(func(st *State) {
		for _, id := range ids {
			if _, had := st.Ignored[id]; !had {
				newly[id] = true
			}
		}
		for _, id := range ids {
			st.Ignored[id] = at
		}
	})
	return newly
}

// markGone: what a click found already gone (State.Gone): the page, the counts and the round's card stop listing it now,
// not a round later.
func (s *Service) markGone(ids []string) {
	if len(ids) == 0 {
		return
	}
	at := core.Time{Time: s.now()}
	s.mutate(func(st *State) {
		if st.Gone == nil {
			st.Gone = map[string]core.Time{}
		}
		for _, id := range ids {
			st.Gone[id] = at
		}
	})
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// MARK: automatic cleaning (ADR 0016, revisions 10-20 and 10-27)

// autoPicker is the picker for this user's state: kinds something was put back from are off, findings the user said
// "以后别提" to are left alone, caches whose tool runs wait. Whoever cleans automatically picks through this.
func (s *Service) autoPicker() core.AutoPick {
	st := s.state()
	p := core.NewAutoPick(s.Config.Context.Home, s.Config.Context.Tmp, s.now(), s.Config.Running())
	p.Added = s.Config.Added
	p.Installed = s.Config.Installed
	if lines, ok := s.Config.CommandLines(); ok {
		p.CommandLines = &lines
	} else {
		p.CommandLines = nil
	}
	for k := range st.AutoOff {
		p.Off[core.AutoKind(k)] = true
	}
	for id := range st.Ignored {
		p.Ignored[id] = true
	}
	return p
}

// autoclean cleans, without a click, what the picker takes from this round: rebuildable caches (deleted by this
// program, never with the tool's own clean command) and the other three kinds (moved to the Trash and written in the
// clean-up record). Off when the user turned it off; a kind something was put back from stays off. Recorded for
// auto-done, also what only partly went; what went is taken out of the report. Stops between items once the round is
// cancelled; the record is written after each item, so whatever was cleaned before a kill is told all the same.
func (s *Service) autoclean(report core.Report) core.Report {
	// A state file that is there but cannot be read: what the user decided is not known, so nothing is done.
	if st, ok := KnownState(s.stateURL()); !ok || st.AutocleanOff != nil {
		return report
	}
	r := report
	picked := s.autoPicker().Pick(r.Findings)
	at := s.now()
	batch := "auto-" + core.ISOTime(at)
	findings := map[string]core.Finding{}
	for _, f := range r.Findings {
		if _, has := findings[s.fid(f)]; !has {
			findings[s.fid(f)] = f
		}
	}
	round := r.StartedAt
	done := AutoDone{ID: core.ISOTime(at), At: core.Time{Time: at}, Tools: []string{}, Round: &round}
	var partial, failed, unrecorded []string
	cleaned := map[string]bool{}
	moved := map[core.AutoKind]*Moved{}
	stop := s.Config.Context.Cancelled
	if stop == nil {
		stop = func() bool { return false }
	}

	soFar := func() AutoDone {
		d := done
		d.Tools = uniq(d.Tools)
		if d.Tools == nil {
			d.Tools = []string{}
		}
		d.Partial = uniq(partial)
		d.Failed = uniq(failed)
		if len(moved) > 0 {
			d.Batch = batch
			d.Moved = nil
			for _, k := range core.AutoKinds {
				if m := moved[k]; m != nil {
					d.Moved = append(d.Moved, *m)
				}
			}
			if len(unrecorded) > 0 {
				d.Unrecorded = unrecorded
			}
		}
		return d
	}
	written := false
	write := func() {
		d := soFar()
		s.mutate(func(st *State) {
			if written {
				for i := len(st.AutoDone) - 1; i >= 0; i-- {
					if st.AutoDone[i].ID == d.ID {
						d.Told = st.AutoDone[i].Told
						st.AutoDone[i] = d
						return
					}
				}
			}
			st.AutoDone = append(st.AutoDone, d)
		})
		written = true
	}

	// Caches. Checked again here: only at their known place, with no link on the way to it, not while their tool runs.
	running := s.Config.Running()
	for _, item := range picked {
		if item.Kind != core.AutoCache {
			continue
		}
		if stop() {
			break // the user is back: the rest waits for the next round
		}
		// Turned off meanwhile (deleting a large cache takes a while): the rest stays.
		current, ok := KnownState(s.stateURL())
		if !ok || current.AutocleanOff != nil {
			continue
		}
		if _, off := current.AutoOff[string(core.AutoCache)]; off {
			continue
		}
		f, has := findings[item.FindingID]
		c, known := knownCacheByRule(f.Rule)
		if !has || !known {
			continue
		}
		at := filepath.Join(s.Config.Context.Home, c.Path)
		_, _, link, there := identity(at)
		if f.Path != at || !s.Config.Context.MayLook(at) || !there || link {
			continue
		}
		// Nor anywhere before it: its real path is the home's real path and the cache's place under it.
		realHome, ok1 := realPath(s.Config.Context.Home)
		real, ok2 := realPath(at)
		if !ok1 || !ok2 || real != realHome+"/"+c.Path {
			continue
		}
		if !core.CacheIdle(c.ID, running) {
			continue // in use, or not known what uses it: next round
		}
		before := core.AllocatedSize(at)
		if f.Bytes != nil {
			before = *f.Bytes
		}
		// Deleted by this program, not with the tool's own clean (that would run whatever is found under that name in
		// a folder the user can write, with this program's Full Disk Access). Opened again from "/" following no link.
		err := s.Config.Remove(real)
		left := int64(0)
		if core.Exists(at) {
			left = core.AllocatedSize(at)
		}
		gone := before - left
		if gone < 0 {
			gone = 0
		}
		if err != nil && gone == 0 {
			failed = append(failed, c.Tool)
			write()
			continue // said, not dropped: it is on
		}
		done.Bytes += gone
		if done.ToolBytes == nil {
			done.ToolBytes = map[string]int64{}
		}
		done.ToolBytes[c.Tool] += gone
		if err == nil && left < 1<<20 {
			done.Tools = append(done.Tools, c.Tool)
			cleaned[s.fid(f)] = true
		} else {
			partial = append(partial, c.Tool)
		}
		// In the record too; deleted, not trashed, so not put back (the tool rebuilds it).
		s.recordRemoved(at, batch, f.Rule, c.Tool+" 的缓存", core.Size(gone), core.AutoCache)
		write()
	}

	// The other three: to the Trash, each checked again first, written down as it goes.
	deadline := time.Now().Add(checkBudget)
	took := map[string]map[string]bool{}
	attached := map[string]bool{}
	if !stop() {
		for _, it := range picked {
			if it.How == core.HowTrash && strings.HasSuffix(strings.ToLower(it.Path), ".dmg") {
				attached = s.Config.AttachedImages()
				break
			}
		}
	}
	changedSince := r.StartedAt.Time
	if r.StartedWall != nil {
		changedSince = r.StartedWall.Time
	}
	for _, item := range picked {
		if item.How != core.HowTrash {
			continue
		}
		if stop() {
			break
		}
		current, ok := KnownState(s.stateURL())
		if !ok || current.AutocleanOff != nil {
			continue
		}
		if _, off := current.AutoOff[string(item.Kind)]; off {
			continue
		}
		f, has := findings[item.FindingID]
		if !has {
			continue
		}
		if attached[core.Canonical(item.Path)] {
			continue // an open disk image, whichever kind
		}
		id, why := s.checkAuto(item, f, r.StartedAt.Time, changedSince, deadline)
		if why != "" {
			continue
		}
		b := item.Bytes
		e, recorded, err := s.trashAndRecord(item.Path, batch, item.Rule, autoTitle(item), &b, item.Kind, &id)
		if err != nil {
			continue
		}
		if !recorded || e.Trashed == nil {
			unrecorded = append(unrecorded, filepath.Base(item.Path))
		}
		m := moved[item.Kind]
		if m == nil {
			m = &Moved{Kind: string(item.Kind), Names: []string{}}
			moved[item.Kind] = m
		}
		m.Items++
		m.Bytes += item.Bytes
		if len(m.Names) < 3 {
			m.Names = append(m.Names, filepath.Base(item.Path))
		}
		if took[item.FindingID] == nil {
			took[item.FindingID] = map[string]bool{}
		}
		took[item.FindingID][item.Path] = true
		write()
	}
	// A finding is done with once nothing it points at is left.
	for id, paths := range took {
		f, has := findings[id]
		if !has {
			continue
		}
		all := true
		for _, p := range s.targetPaths(f) {
			if !paths[p] && core.Exists(p) {
				all = false
				break
			}
		}
		if all {
			cleaned[id] = true
		}
	}

	if !written {
		return r // nothing done, nothing to tell
	}
	var keep []core.Finding
	for _, f := range r.Findings {
		if !cleaned[s.fid(f)] {
			keep = append(keep, f)
		}
	}
	if keep == nil {
		keep = []core.Finding{}
	}
	r.Findings = keep
	if rec, ok := s.autoCleanedRecord(soFar()); ok {
		s.remember([]MemoryRecord{rec})
	}
	return r
}

// checkAuto: something picked, checked again just before it goes: the same checks as a clicked plan, and more, since
// nobody looked at it: not put there or changed since the round began (its ctime), not open in a program, not a
// profile a browser has open; a copy only while the one that stays is another file with the same contents. Its
// identity, or why not. since: the round's start by its clock (modification dates); changedSince: by this Mac's.
func (s *Service) checkAuto(item core.AutoItem, f core.Finding, since, changedSince, deadline time.Time) (ident, string) {
	var st syscall.Stat_t
	if syscall.Lstat(item.Path, &st) != nil {
		return ident{}, absent
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return ident{}, "现在是一个链接"
	}
	// By whole seconds: a saved report keeps no fractions, and a change in the round's first second came before any
	// rule looked at it.
	if st.Ctimespec.Sec > changedSince.Unix() {
		return ident{}, "查过以后又换过或改过"
	}
	if !s.inside(item.Path) || s.protectedPlace(item.Path) {
		return ident{}, "不在能清的地方"
	}
	if syscall.Access(filepath.Dir(item.Path), 2) != nil {
		return ident{}, "要密码"
	}
	if _, mounted := core.MountInside(item.Path); mounted {
		return ident{}, "里面挂着另一个磁盘"
	}
	changed, inTime := touched(item.Path, since, s.now(), deadline)
	if !inTime {
		return ident{}, "来不及核对完"
	}
	if changed {
		return ident{}, "查过以后又改过"
	}
	switch item.Kind {
	case core.AutoDuplicate:
		kd, ki, link, ok := identity(f.Path)
		if !ok || link || (kd == int64(st.Dev) && ki == st.Ino) || !core.SameContents(f.Path, item.Path) {
			return ident{}, "要留的那份已经不在或改过了"
		}
		if len(core.OpenBy(item.Path)) > 0 {
			return ident{}, "正开着"
		}
	case core.AutoInstaller:
		if len(core.OpenBy(item.Path)) > 0 {
			return ident{}, "正开着"
		}
	case core.AutoTemp:
		if core.BrowserRunning(item.Path) {
			return ident{}, "浏览器还开着它"
		}
	}
	return ident{int64(st.Dev), st.Ino}, ""
}

// autoTitle is the clean-up record's title of something cleaned automatically.
func autoTitle(item core.AutoItem) string {
	name := filepath.Base(item.Path)
	switch item.Kind {
	case core.AutoInstaller:
		return "安装包 " + name
	case core.AutoDuplicate:
		return "重复的 " + name
	case core.AutoTemp:
		return "临时文件夹 " + name
	}
	return name
}
