package service

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// Read-only data for the scan page the agent draws itself (top-level ADR 0028): raw facts only — codes, bytes, times
// and counts — with no A2UI and no sentences. Five resources: data/overview, data/category?id=<category>,
// data/history, data/settings, data/usage (usage.go). Every field is described in docs/data-resources.md; a change there is a change of the
// interface with the agent.

// dataSchema: the version of these resources' fields. Raised only when a field changes meaning or goes away; new fields
// can come without it.
const dataSchema = 1

const (
	// dataAutoCleanedFor: how far back the overview lists the automatic cleans.
	dataAutoCleanedFor = 7 * 24 * time.Hour
	// dataHistoryMost: the most batches data/history lists, newest first.
	dataHistoryMost = 100
)

// What data/category lists at most: the items of a category (the biggest first; the rest counted in more), and the
// places of one item (the rest counted in pathsMore; cleaning it still takes them all). Variables for the tests.
var (
	dataItemsMost = 100
	dataPathsMost = 20
)

// dataCategories: what an item of a clean-up plan is, in the order the overview lists them. The four automatic kinds
// keep their names (core.AutoKind).
var dataCategories = []string{"cache", "installer", "duplicate", "temp", "leftover", "project", "large-file",
	"startup", "ai-plugin", "install-scripts", "malware"}

// dataNotReclaimable: categories whose items are not space that can be freed: listed in the overview's settings, not
// its reclaimable, and left out of data/usage's reclaim (data/category has them as any other). install-scripts is a
// setting of a package manager: its item's target is the config file the fix writes a line into.
var dataNotReclaimable = []string{"install-scripts"}

// dataCategory: the category of a rule's items (and of its records in the clean-up record); "other" for a rule that
// has none of these.
func dataCategory(rule string) string {
	switch {
	case strings.HasPrefix(rule, "cache."), rule == "space.ai-model", rule == "space.ipsw", rule == "space.xcode-device-support":
		return "cache"
	case rule == "leftover.installer":
		return "installer"
	case rule == "space.duplicates":
		return "duplicate"
	case strings.HasPrefix(rule, "leak."):
		return "temp"
	case strings.HasPrefix(rule, "leftover."):
		return "leftover"
	case rule == "stale.large-file":
		return "large-file"
	case strings.HasPrefix(rule, "stale."):
		return "project"
	case strings.HasPrefix(rule, "persistence."):
		return "startup"
	case strings.HasPrefix(rule, "skill."), strings.HasPrefix(rule, "model.chat-template"):
		return "ai-plugin"
	case rule == core.InstallScriptsRuleID:
		return "install-scripts"
	case strings.HasPrefix(rule, "malware."):
		return "malware"
	}
	return "other"
}

// dataAutoKind: the automatic kind a category is, "" for none.
func dataAutoKind(category string) string {
	for _, k := range AutoKinds {
		if string(k) == category {
			return category
		}
	}
	return ""
}

// itemData: what one item of a plan is, as raw facts: its group within the category, why it may go (a code and the
// facts behind it), and the three things the judgement on a category is made of.
type itemData struct {
	group, reason string
	facts         O
	rebuilds      bool   // comes back by itself when needed (a tool's or an app's cache)
	userFiles     string // what of the user's own would be lost: "none", "maybe" or "yes"
	app           string // the app it belongs to, "" when none
	appInstalled  *bool  // whether that app is on this Mac, nil when not known
}

// userFilesRank orders userFiles: none < maybe < yes.
var userFilesRank = map[string]int{"none": 0, "maybe": 1, "yes": 2}

// evInt: an evidence value that is a whole number; ok false when it is not one.
func evInt(ev map[string]string, k string) (int, bool) {
	n, err := strconv.Atoi(ev[k])
	return n, err == nil
}

// putFacts copies evidence values that are raw facts (names, versions, days as 2006-01-02) under the names given, and
// leaves out the empty ones and anything else (sentences, sizes already formatted for people).
func putFacts(facts O, ev map[string]string, names map[string]string) {
	for k, name := range names {
		if v := ev[k]; v != "" && v != "?" {
			facts[name] = v
		}
	}
}

// splitList: a list the evidence joins with sep, as an array; empty parts left out.
func splitList(s, sep string) A {
	out := A{}
	for _, x := range strings.Split(s, sep) {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// itemFacts: an item's group, reason and raw facts, by its rule. targets: what the item would move.
func (s *Service) itemFacts(f core.Finding, targets int) itemData {
	ev := f.Evidence
	d := itemData{facts: O{}, userFiles: "none"}
	yes, no := true, false
	switch {
	case strings.HasPrefix(f.Rule, "cache.rebuildable."):
		d.group, d.reason, d.rebuilds = "tool-cache", "rebuilds", true
		d.facts["cache"] = strings.TrimPrefix(f.Rule, "cache.rebuildable.")
		putFacts(d.facts, ev, map[string]string{"tool": "tool"})
		if c, ok := knownCacheByRule(f.Rule); ok && d.facts["tool"] == nil {
			d.facts["tool"] = c.Tool
		}
	case f.Rule == "cache.app", f.Rule == "cache.electron":
		d.group, d.reason, d.rebuilds = "app-cache", "app-rebuilds", true
		putFacts(d.facts, ev, map[string]string{"app": "app", "app_id": "bundleId"})
		d.app, d.appInstalled = ev["app"], &yes // the rule only reports an installed app's cache
	case f.Rule == "cache.logs":
		d.group, d.reason, d.rebuilds = "logs", "logs", true
		putFacts(d.facts, ev, map[string]string{"app": "app"})
	case f.Rule == "space.ai-model":
		d.group, d.reason = "model", "redownload"
		putFacts(d.facts, ev, map[string]string{"tool": "tool", "model": "model", "downloaded": "downloaded"})
	case f.Rule == "space.ipsw":
		d.group, d.reason = "ipsw", "redownload"
		putFacts(d.facts, ev, map[string]string{"downloaded": "downloaded"})
	case f.Rule == "space.xcode-device-support":
		d.group, d.reason, d.rebuilds = "device-support", "newer-version", true
		putFacts(d.facts, ev, map[string]string{"platform": "platform", "version": "version", "newest": "newest"})
	case f.Rule == "leftover.installer":
		d.group, d.reason = "installer", "old-download"
		putFacts(d.facts, ev, map[string]string{"added": "added", "installed": "app", "app_version": "appVersion",
			"installer_version": "installerVersion"})
		if n, ok := evInt(ev, "days"); ok {
			d.facts["days"] = n
		}
		if ev["exact"] != "" {
			d.facts["sameApp"] = true // the file is named exactly as the installed app (what automatic cleaning goes by)
		}
		if ev["downloaded"] == "1" {
			d.facts["fromInternet"] = true
			d.facts["signed"] = ev["signed"] == "1"
		}
		if d.app = ev["installed"]; d.app != "" {
			d.reason, d.appInstalled = "installed", &yes
		}
	case f.Rule == "leftover.partial-download":
		d.group, d.reason = "partial-download", "unfinished"
		putFacts(d.facts, ev, map[string]string{"last_changed": "lastChanged"})
	case f.Rule == "leftover.app-data":
		d.group, d.reason, d.userFiles = "app-data", "app-removed", "maybe"
		putFacts(d.facts, ev, map[string]string{"bundle_id": "bundleId", "last_changed": "lastChanged"})
		d.facts["places"] = targets
		d.app, d.appInstalled = ev["bundle_id"], &no
	case f.Rule == homebrewRule, f.Rule == homebrewLinksRule:
		d.group, d.reason = "intel-homebrew", "intel-homebrew"
	case f.Rule == "space.duplicates":
		d.group, d.reason = "duplicate", "copy-kept"
		d.facts["keep"] = f.Path
		d.facts["copies"] = targets
	case strings.HasPrefix(f.Rule, "leak."):
		d.group, d.reason = "temp", "left-behind"
		putFacts(d.facts, ev, map[string]string{"prefix": "prefix", "first": "first", "last": "last"})
		if n, ok := evInt(ev, "count"); ok {
			d.facts["count"] = n
		}
		if tool, ok := core.AutoKnownTemp[ev["prefix"]]; ok {
			d.facts["tool"] = tool
		}
	case f.Rule == "stale.project":
		d.group, d.reason, d.userFiles = "project", "pushed", "maybe"
		if n, ok := evInt(ev, "repos"); ok {
			d.facts["repos"] = n
		}
		last := ""
		for k, v := range ev {
			if strings.HasPrefix(k, "last_commit:") && v > last {
				last = v
			}
		}
		if last != "" {
			d.facts["lastCommit"] = last
		}
	case f.Rule == "stale.artifacts":
		d.group, d.reason = "build-artifacts", "regenerable"
		d.facts["count"] = targets
	case f.Rule == "stale.large-file":
		d.group, d.reason, d.userFiles = "large-file", "not-opened", "yes"
		putFacts(d.facts, ev, map[string]string{"last_opened": "lastOpened", "last_changed": "lastChanged"})
		if ev["never_opened"] == "1" {
			d.facts["neverOpened"] = true
		}
	case f.Rule == "persistence.launchagent-missing":
		d.group, d.reason = "launch-agent", "program-missing"
		putFacts(d.facts, ev, map[string]string{"label": "label"})
	case strings.HasPrefix(f.Rule, "persistence."):
		d.group, d.reason = "launch-agent", strings.TrimPrefix(f.Rule, "persistence.")
		putFacts(d.facts, ev, map[string]string{"label": "label", "name": "name", "app": "app", "program": "program", "scope": "scope"})
		if p, ok := d.facts["program"].(string); ok {
			d.facts["program"] = s.expandHome(p) // the rule writes it from the home (~/…): absolute, as every path here
		}
		d.app = ev["app"]
	case isMalware(f):
		d.group, d.reason = "malware", "signature"
		putFacts(d.facts, ev, map[string]string{"signature": "signature", "rule": "rule"})
	case f.Rule == core.InstallScriptsRuleID:
		// A setting's state, not a file: what the tool does by default, what was seen here, and what turning it off
		// takes and costs. Codes and literal settings only (docs/data-resources.md).
		d.group, d.reason = "install-scripts", "scripts-on"
		putFacts(d.facts, ev, map[string]string{"tool": "tool", "name": "name", "risk": "risk", "reason": "cause",
			"version": "version", "where": "where", "store": "store", "setting": "setting", "runs": "runs",
			"manual": "manual", "allow": "allow", "allow_in": "allowIn", "cost": "cost",
			"delay": "delay", "delay_since": "delaySince", "fixed_in": "fixedIn"})
		for k, name := range map[string]string{"packages": "packages", "built": "built", "files": "files"} {
			if l := splitList(ev[k], ","); len(l) > 0 {
				d.facts[name] = l
			}
		}
		if ev["config"] != "" {
			d.facts["config"] = O{"file": ev["config"], "exists": ev["config_exists"] == "1", "line": ev["line"]}
		}
		d.facts["canApply"] = ev["append"] != ""
	case strings.HasPrefix(f.Rule, "skill."):
		d.group, d.reason = "skill", strings.TrimPrefix(f.Rule, "skill.")
		putFacts(d.facts, ev, map[string]string{"agent": "agent", "skill": "skill", "scope": "scope"})
		if k := splitList(ev["kinds"], ","); len(k) > 0 {
			d.facts["kinds"] = k
		}
		putHits(d.facts, f)
	case strings.HasPrefix(f.Rule, "model.chat-template"):
		d.group, d.reason = "chat-template", "template-extra"
		putFacts(d.facts, ev, map[string]string{"tool": "tool", "model": "model", "template": "template"})
		if k := splitList(ev["kinds"], ","); len(k) > 0 {
			d.facts["kinds"] = k
		}
		if t, ok := d.facts["template"].(string); ok {
			d.facts["template"] = s.expandHome(t)
		}
		putHits(d.facts, f)
	default:
		d.group, d.reason = "other", f.Rule
	}
	return d
}

// dataItem: one item of a plan in data/category: what to send to scan_apply (the plan and the item's key, the
// choices), where it is and how big, why it may go, and whether moving it can be undone.
type dataItem struct {
	out      O
	category string
	bytes    int64
	files    int
	clears   bool     // suggested to go
	targets  []string // every place it takes, not only the ones listed (data/usage: which row it is in)
	info     itemData
}

func (s *Service) dataItem(it PlanItem, plan Plan, f *core.Finding, r *core.Report) dataItem {
	paths := A{}
	targets := make([]string, 0, len(it.Targets))
	for i, t := range it.Targets {
		if i < dataPathsMost {
			paths = append(paths, t.Path)
		}
		targets = append(targets, t.Path)
	}
	var info itemData
	path, reveal := "", ""
	if f != nil {
		info = s.itemFacts(*f, len(it.Targets))
		path, reveal = f.Path, s.revealTarget(*f)
		// A duplicates item: every copy of the group, the one the rule keeps first and then the plan's targets in the
		// rule's order (luoke-scan#234). Which one stays is the rule's alone.
		if it.Rule == "space.duplicates" {
			members := A{f.Path}
			for _, t := range it.Targets {
				members = append(members, t.Path)
			}
			info.facts["members"] = members
		}
	} else {
		info = itemData{group: "other", reason: it.Rule, facts: O{}, userFiles: "none"}
	}
	// A duplicate's finding is the copy that stays (facts.keep): the item is the copies that go
	// A setting's state (the install-scripts rule) is about no file: path and reveal stay empty. What scripts-off would
	// write is in paths (the plan's target) and in facts.config.
	setting := it.Rule == core.InstallScriptsRuleID
	if (path == "" || it.Rule == "space.duplicates") && len(it.Targets) > 0 && !setting {
		path = it.Targets[0].Path
	}
	if (reveal == "" || it.Rule == "space.duplicates") && len(it.Targets) > 0 && !setting {
		reveal = it.Targets[0].Path
	}
	var bytes any
	if it.Bytes != nil {
		bytes = *it.Bytes
	}
	// Undone with scan_restore on its batch: what goes to the Trash from this user's own folders (not a cache deleted
	// for good, a link deleted, nor what went with the password), but a virus and what starts by itself (a batch put
	// back leaves them out: canPutBack).
	restorable := false
	for _, o := range it.Options {
		if o == ChoiceTrash || o == ChoiceScriptsOff {
			restorable = !plan.Admin && !strings.HasPrefix(it.Rule, "malware.") && !strings.HasPrefix(it.Rule, "persistence.")
		}
	}
	o := O{"key": it.Key, "plan": plan.ID, "finding": it.FindingID, "rule": it.Rule, "group": info.group,
		"reason": info.reason, "facts": info.facts, "path": nilIfEmpty(path), "reveal": nilIfEmpty(reveal), "paths": paths,
		"pathsMore": len(it.Targets) - len(paths), "bytes": bytes,
		"suggested": it.Suggested, "options": stringsA(it.Options), "rebuilds": info.rebuilds, "userFiles": info.userFiles,
		"password": plan.Admin, "restorable": restorable, "modelNotes": A{}}
	if f != nil {
		o["modelNotes"] = modelNotesData(*f, r)
	}
	if info.app != "" {
		o["app"] = info.app
	}
	if info.appInstalled != nil {
		o["appInstalled"] = *info.appInstalled
	}
	// A setting is in no file: the config file the fix would write is not a place the item is at.
	files := len(it.Targets)
	if setting {
		files = 0
	}
	return dataItem{out: o, category: dataCategory(it.Rule), bytes: itemBytes(it), files: files,
		clears: Clears(it.Suggested), targets: targets, info: info}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func stringsA(xs []string) A {
	out := A{}
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

// dataItems: what the last round's plans still offer (the plan of the scan page and the one that needs the password),
// less what already went with a click this round; by category. nil report: none.
func (s *Service) dataItems(r *core.Report, st State) map[string][]dataItem {
	out := map[string][]dataItem{}
	if r == nil {
		return out
	}
	f := s.visible(*r, st)
	v := s.roundView(f, *r, roundID(*r))
	about := map[string]core.Finding{}
	for _, x := range f {
		about[s.fid(x)] = x
	}
	gone := append(append([]PlanItem{}, v.cleaned...), v.done...)
	for _, p := range []*Plan{v.plan, v.admin} {
		if p == nil {
			continue
		}
		for _, it := range p.Items {
			if p == v.plan && hasItem(gone, it.Key) {
				continue
			}
			var fp *core.Finding
			if x, ok := about[it.FindingID]; ok {
				fp = &x
			}
			d := s.dataItem(it, *p, fp, r)
			out[d.category] = append(out[d.category], d)
		}
	}
	for _, items := range out {
		sort.SliceStable(items, func(i, j int) bool { return items[i].bytes > items[j].bytes })
	}
	return out
}

// categorySummary: a category's totals and the facts a one-line summary of it is written from.
func categorySummary(id string, items []dataItem) O {
	var bytes, suggestedBytes int64
	files, suggested, rebuilds, password, installed, missing := 0, 0, 0, 0, 0, 0
	groups := O{}
	apps, tools := []string{}, []string{}
	userFiles := "none"
	for _, d := range items {
		bytes += d.bytes
		files += d.files
		if d.clears {
			suggested++
			suggestedBytes += d.bytes
		}
		if d.info.rebuilds {
			rebuilds++
		}
		if p, _ := d.out["password"].(bool); p {
			password++
		}
		if n, ok := groups[d.info.group].(int); ok {
			groups[d.info.group] = n + 1
		} else {
			groups[d.info.group] = 1
		}
		if d.info.app != "" && !contains(apps, d.info.app) {
			apps = append(apps, d.info.app)
			if d.info.appInstalled != nil {
				if *d.info.appInstalled {
					installed++
				} else {
					missing++
				}
			}
		}
		if t, _ := d.info.facts["tool"].(string); t != "" && !contains(tools, t) {
			tools = append(tools, t)
		}
		if userFilesRank[d.info.userFiles] > userFilesRank[userFiles] {
			userFiles = d.info.userFiles
		}
	}
	sort.Strings(apps)
	sort.Strings(tools)
	var auto any
	if k := dataAutoKind(id); k != "" {
		auto = k
	}
	return O{"id": id, "bytes": bytes, "count": len(items), "files": files, "suggested": suggested,
		"suggestedBytes": suggestedBytes, "auto": auto,
		"facts": O{"groups": groups, "apps": stringsA(apps), "tools": stringsA(tools), "appsInstalled": installed,
			"appsMissing": missing, "rebuilds": rebuilds, "userFiles": userFiles, "password": password}}
}

// scannedData: when the last round ran; nil before the first.
func scannedData(r *core.Report) any {
	if r == nil {
		return nil
	}
	return O{"started": core.ISOTime(r.StartedAt.Time), "finished": core.ISOTime(r.FinishedAt.Time)}
}

// dataOverview: data/overview.
func (s *Service) dataOverview() O {
	st := s.state()
	r := s.Store.LastReport()
	items := s.dataItems(r, st)
	// settings: the categories of dataNotReclaimable that have items, shaped as reclaimable's (the page's way in to them)
	reclaim, settings := A{}, A{}
	for _, id := range append(append([]string{}, dataCategories...), "other") {
		switch {
		case len(items[id]) == 0:
		case slices.Contains(dataNotReclaimable, id):
			settings = append(settings, categorySummary(id, items[id]))
		default:
			reclaim = append(reclaim, categorySummary(id, items[id]))
		}
	}
	large := O{"count": 0, "bytes": int64(0)}
	if ls := items["large-file"]; len(ls) > 0 {
		var b int64
		for _, d := range ls {
			b += d.bytes
		}
		large = O{"count": len(ls), "bytes": b}
	}
	out := O{"schema": dataSchema, "scanned": scannedData(r), "scanning": s.scanningData(r),
		"autoCleaned": s.autoCleanedData(st, s.now().Add(-dataAutoCleanedFor)), "reclaimable": reclaim, "settings": settings,
		"attention": s.attentionData(r, st, items), "largeFiles": large, "disk": s.diskData(),
		"fullDiskAccess": s.permissionStates(st)["fda"], "autoclean": autocleanOn(st), "skipped": skippedData(r),
		"virusDb": virusDbData(r)}
	return out
}

// scanningData: the round running now: when it started, the checks done of all, how far (0 to 1, nil when not
// known); nil when none runs.
func (s *Service) scanningData(last *core.Report) any {
	if !s.IsScanning() {
		return nil
	}
	o := O{"started": nil, "checksDone": 0, "checks": 0, "fraction": nil}
	if p := s.Store.Progress(); p != nil {
		o["started"] = core.ISOTime(p.Started)
		o["checksDone"], o["checks"] = len(p.Done), p.Total
	}
	if _, frac := s.scanProgress(last); frac >= 0 {
		o["fraction"] = frac
	}
	return o
}

// autocleanOn: automatic cleaning is on (switched on, and not every kind put back).
func autocleanOn(st State) bool {
	if st.AutocleanOff != nil {
		return false
	}
	for _, k := range AutoKinds {
		if _, off := st.AutoOff[string(k)]; !off {
			return true
		}
	}
	return false
}

func (s *Service) diskData() any {
	if s.Config.Volume == nil {
		return nil
	}
	free, total, ok := s.Config.Volume(s.Config.Context.Home)
	if !ok || total <= 0 {
		return nil
	}
	// available: what can be written right now; free also counts what the system says it can purge (the Finder's
	// figure), so available is never more than free. nil when not known.
	var available any
	if s.Config.Available != nil {
		if a, ok := s.Config.Available(s.Config.Context.Home); ok {
			if a > free {
				a = free
			}
			available = a
		}
	}
	return O{"free": free, "total": total, "available": available}
}

// skippedData: the checks the last round could not run, by rule, and why as a code: fda (needs Full Disk Access),
// interrupted (the user came back), other.
func skippedData(r *core.Report) A {
	out := A{}
	if r == nil {
		return out
	}
	for _, x := range r.Skipped {
		why := "other"
		switch {
		case strings.Contains(x.Reason, "完全磁盘访问"):
			why = "fda"
		case x.Reason == core.Interrupted:
			why = "interrupted"
		}
		out = append(out, O{"rule": x.Rule, "reason": why})
	}
	return out
}

func virusDbData(r *core.Report) any {
	if r == nil {
		return nil
	}
	v, ok := r.Versions["clamav_db_version"]
	if !ok {
		return nil
	}
	return O{"version": v, "date": nilIfEmpty(r.Versions["clamav_db_date"])}
}

// attentionData: what this Mac has that wants the user's look, outside of what can be cleaned: what the scan page
// lists under 「要你看看」 (serious ones only for reference too), and the urgent ones of the plans (a virus) that are
// still there. Each by its rule, and the category it can also be cleaned from, if any.
func (s *Service) attentionData(r *core.Report, st State, items map[string][]dataItem) O {
	list := A{}
	urgent := 0
	if r != nil {
		f := s.visible(*r, st)
		v := s.roundView(f, *r, roundID(*r))
		planned := map[string]string{}
		for cat, ds := range items {
			for _, d := range ds {
				planned[d.out["finding"].(string)] = cat
			}
		}
		add := func(x core.Finding) {
			u := isUrgent(x)
			if u {
				urgent++
			}
			var cat any
			if c, ok := planned[s.fid(x)]; ok {
				cat = c
			}
			list = append(list, s.findingEntry(x, r, cat))
		}
		look := map[string]bool{}
		for _, x := range v.look {
			look[s.fid(x)] = true
		}
		for _, x := range bySeverity(f) {
			if _, inPlan := planned[s.fid(x)]; look[s.fid(x)] || (inPlan && isUrgent(x)) {
				add(x)
			}
		}
	}
	return O{"count": len(list), "urgent": urgent, "items": list}
}

// attentionFacts: what the rule found, as codes, names and numbers the window writes its own words from (no title,
// hint or how). By the rule; nil for a rule that gives none yet.
func (s *Service) attentionFacts(f core.Finding) any {
	if f.Rule == "permission.stale-grant" {
		return s.staleGrantFacts(f)
	}
	// A skill's and a chat template's: the same facts their items in data/category have.
	if (strings.HasPrefix(f.Rule, "skill.") || f.Rule == "model.chat-template") && !strings.HasSuffix(f.Rule, ".partial") {
		return s.itemFacts(f, 0).facts
	}
	return nil
}

// staleGrantFacts: whose it is (the TCC client: a bundle id or a program's path; the app's name where Login Items
// shows one), the privacy grants it still holds (each a name scan_open_settings takes), and what it left in Login
// Items & Extensions (nil: nothing).
func (s *Service) staleGrantFacts(f core.Finding) O {
	kind := "bundle"
	if strings.HasPrefix(f.Path, "/") {
		kind = "path"
	}
	grants, left := A{}, false
	for _, g := range strings.Split(f.Evidence["grants"], "、") {
		if g == core.LoginItemsGrant {
			left = true
		} else if g != "" {
			grants = append(grants, g)
		}
	}
	var login any
	if left {
		var items []string
		if raw, ok := f.Evidence[core.LeftItemsKey]; ok {
			items = strings.Split(raw, "\n")
		} else { // a round from before the rule kept them apart
			for _, it := range strings.Split(f.Evidence["login_items"], "、") {
				items = append(items, s.expandHome(it))
			}
		}
		known := A{}
		for _, it := range items {
			if it != "" {
				known = append(known, it)
			}
		}
		login = O{"grant": core.LoginItemsGrant, "items": known, "starts": flagOf(f.Evidence, core.LeftStartsKey),
			"root": flagOf(f.Evidence, core.LeftDaemonKey)}
	}
	return O{"client": f.Path, "clientType": kind, "app": nilIfEmpty(f.Evidence["app"]), "grants": grants, "loginItems": login}
}

// flagOf: a rule's yes or no ("1", "0"); nil where the round did not say.
func flagOf(ev map[string]string, key string) any {
	v, ok := ev[key]
	if !ok {
		return nil
	}
	return v == "1"
}

// autoCleanedData: the automatic cleans since then, newest first, each with what it took of each kind and how much of
// it can still be put back. One that took nothing and failed nothing is left out.
func (s *Service) autoCleanedData(st State, since time.Time) A {
	records := map[string][]Cleaned{}
	for _, e := range s.Cleaned() {
		if strings.HasPrefix(e.Batch, "auto-") {
			records[e.Batch] = append(records[e.Batch], e)
		}
	}
	out := A{}
	for i := len(st.AutoDone) - 1; i >= 0; i-- {
		d := st.AutoDone[i]
		if d.At.Before(since) || len(d.Tools)+len(d.Partial)+len(d.Moved)+len(d.Failed) == 0 {
			continue
		}
		batch := d.Batch
		if batch == "" {
			batch = "auto-" + d.ID // caches only: their records are under the clean's batch all the same
		}
		kinds := A{}
		total, restorable := d.Bytes, 0
		if tools := uniq(append(append([]string{}, d.Tools...), d.Partial...)); len(tools) > 0 {
			kinds = append(kinds, O{"kind": string(core.AutoCache), "count": len(tools), "bytes": d.Bytes,
				"tools": stringsA(tools), "partial": stringsA(uniq(d.Partial)), "restorable": 0, "restored": 0})
		}
		for _, m := range d.Moved {
			var mine []Cleaned
			restored := 0
			for _, e := range records[batch] {
				if e.Auto != nil && *e.Auto == m.Kind {
					mine = append(mine, e)
					if e.Restored != nil {
						restored++
					}
				}
			}
			back := len(canPutBack(mine))
			restorable += back
			total += m.Bytes
			kinds = append(kinds, O{"kind": m.Kind, "count": m.Items, "bytes": m.Bytes, "restorable": back, "restored": restored})
		}
		out = append(out, O{"batch": batch, "at": core.ISOTime(d.At.Time), "bytes": total, "kinds": kinds,
			"restorable": restorable, "failed": stringsA(uniq(d.Failed)), "unrecorded": len(d.Unrecorded)})
	}
	return out
}

// dataCategoryDetail: data/category?id=<category>: the category's totals and facts, and each of its items. An id that is
// no category: known false, nothing in it.
func (s *Service) dataCategoryDetail(args map[string]string) O {
	id := args["id"]
	known := id == "other"
	for _, c := range dataCategories {
		known = known || c == id
	}
	r := s.Store.LastReport()
	var items []dataItem
	if known {
		items = s.dataItems(r, s.state())[id]
	}
	out := categorySummary(id, items)
	list := A{}
	for i, d := range items {
		if i >= dataItemsMost {
			break
		}
		list = append(list, d.out)
	}
	out["schema"], out["known"], out["scanned"], out["items"] = dataSchema, known, scannedData(r), list
	out["more"] = len(items) - len(list)
	if id == "duplicate" {
		out["compared"] = s.duplicatesCompared(r)
	}
	return out
}

// duplicatesCompared: what the last round's duplicates check compared, once for the category (luoke-scan#234: a user
// has more copies than an item lists), as codes and numbers. The folders under the home it looked through (the rule's
// places it was allowed to look in), those left out for want of Full Disk Access, those it stopped in after maxFiles
// files (space.duplicates-partial); the least size of a file it compares (its size and what it takes on disk), the
// least a group's other copies must hold of their own to be listed, the most groups listed; finished false when the
// round was interrupted before it (the items are an earlier round's, or none); what it never compares
// (core.DuplicatesNever). nil before the first round, or without that check.
func (s *Service) duplicatesCompared(r *core.Report) any {
	var rule *core.DuplicateRule
	for _, x := range s.Config.Rules {
		if d, ok := x.(*core.DuplicateRule); ok {
			rule = d
		}
	}
	if rule == nil || r == nil {
		return nil
	}
	finished := true
	var left, cut []string
	for _, x := range r.Skipped {
		if x.Rule == rule.ID() {
			left = core.DuplicatesNotLooked(x.Reason)
			finished = strings.HasPrefix(x.Reason, core.NoAccessMark) // looked where it could; else interrupted, or failed
		}
	}
	for _, f := range r.Findings {
		if f.Rule == "space.duplicates-partial" {
			cut = append(cut, strings.Split(f.Evidence["folders"], "、")...)
		}
	}
	places, noAccess, partial := A{}, A{}, A{}
	for _, p := range rule.Places {
		if contains(left, p) {
			noAccess = append(noAccess, p)
		} else {
			places = append(places, p)
		}
		if contains(cut, p) {
			partial = append(partial, p)
		}
	}
	return O{"places": places, "noAccess": noAccess, "partial": partial, "maxFiles": rule.MaxFiles,
		"minBytes": rule.MinBytes, "minWaste": rule.MinWaste, "maxGroups": rule.MaxSets, "finished": finished,
		"never": stringsA(core.DuplicatesNever)}
}

// dataHistory: data/history: the clean-up record, a batch per row (what one 「放回」 puts back together), newest first.
func (s *Service) dataHistory() O {
	all := s.Cleaned()
	var order []string
	batches := map[string][]Cleaned{}
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		if _, has := batches[e.Batch]; !has {
			order = append(order, e.Batch)
		}
		batches[e.Batch] = append(batches[e.Batch], e)
	}
	rows := A{}
	for i, b := range order {
		if i >= dataHistoryMost {
			break
		}
		es := batches[b]
		latest := es[0].At.Time
		var bytes int64
		cats := map[string]O{}
		var catOrder []string
		deleted, restored, password := 0, 0, 0
		for _, e := range es {
			if e.At.After(latest) {
				latest = e.At.Time
			}
			var eb int64
			if e.Bytes != nil {
				eb = *e.Bytes
			}
			bytes += eb
			c := dataCategory(e.Rule)
			if cats[c] == nil {
				cats[c] = O{"id": c, "count": 0, "bytes": int64(0)}
				catOrder = append(catOrder, c)
			}
			cats[c]["count"] = cats[c]["count"].(int) + 1
			cats[c]["bytes"] = cats[c]["bytes"].(int64) + eb
			switch {
			case e.Admin != nil && *e.Admin:
				password++
			case e.Trashed == nil && e.Wrote == nil:
				deleted++
			}
			if e.Restored != nil {
				restored++
			}
		}
		sort.Strings(catOrder)
		list := A{}
		for _, c := range catOrder {
			list = append(list, cats[c])
		}
		rows = append(rows, O{"batch": b, "auto": strings.HasPrefix(b, "auto-"), "at": core.ISOTime(latest), "bytes": bytes,
			"count": len(es), "categories": list, "deleted": deleted, "password": password, "restored": restored,
			"restorable": len(canPutBack(es))})
	}
	return O{"schema": dataSchema, "batches": rows, "more": max(0, len(order)-dataHistoryMost)}
}

// dataSettings: data/settings: what the user set, as it is kept.
func (s *Service) dataSettings() O {
	st := s.state()
	var offSince any
	never := st.AutocleanOff != nil && st.AutocleanOff.Equal(neverOn.Time)
	if st.AutocleanOff != nil && !never {
		offSince = core.ISOTime(st.AutocleanOff.Time)
	}
	kinds := A{}
	for _, k := range AutoKinds {
		o := O{"kind": string(k), "off": false, "offSince": nil}
		if t, off := st.AutoOff[string(k)]; off {
			o["off"], o["offSince"] = true, core.ISOTime(t.Time)
		}
		kinds = append(kinds, o)
	}
	// 「以后别提」: by finding, when; the rule from the id, and where it is when the last round still has it
	where := map[string]core.Finding{}
	if r := s.Store.LastReport(); r != nil {
		for _, f := range r.Findings {
			where[s.fid(f)] = f
		}
	}
	var ids []string
	for id := range st.Ignored {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := st.Ignored[ids[i]], st.Ignored[ids[j]]
		if !a.Equal(b.Time) {
			return a.After(b.Time)
		}
		return ids[i] < ids[j]
	})
	ignored := A{}
	for _, id := range ids {
		rule := id
		if i := strings.LastIndex(id, "/"); i > 0 {
			rule = id[:i]
		}
		o := O{"finding": id, "rule": rule, "at": core.ISOTime(st.Ignored[id].Time), "path": nil, "name": nil}
		if f, ok := where[id]; ok {
			rule = f.Rule
			o["rule"] = rule
			if strings.HasPrefix(f.Path, "/") {
				o["path"] = f.Path
			}
			// A setting has no path: the tool it is a setting of, as the tool writes its own name.
			if f.Rule == core.InstallScriptsRuleID {
				o["name"] = nilIfEmpty(f.Evidence["name"])
			}
		}
		o["category"] = dataCategory(rule)
		ignored = append(ignored, o)
	}
	return O{"schema": dataSchema, "autoclean": O{"on": st.AutocleanOff == nil, "offSince": offSince, "neverOn": never},
		"kinds": kinds, "ignored": ignored}
}

func (s *Service) registerData() {
	srv := s.Server
	srv.Resource("data/overview", "扫描页的数据", func() any { return s.dataOverview() })
	srv.ResourceArgs("data/category", "一类可以清的东西", func(args map[string]string) any { return s.dataCategoryDetail(args) })
	srv.Resource("data/history", "清理记录的数据", func() any { return s.dataHistory() })
	srv.Resource("data/settings", "扫描的设置", func() any { return s.dataSettings() })
	srv.Resource("data/usage", "占地方最多的文件夹", func() any { return s.dataUsage() })
	srv.ResourceArgs("data/finding", "一项发现和它命中的依据", func(args map[string]string) any { return s.dataFinding(args) })
}
