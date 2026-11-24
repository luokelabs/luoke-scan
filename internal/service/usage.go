package service

// data/usage: the folders that take the most room, as data (luoke-scan#165; top-level ADR 0028: the page is
// luoke-agent's, the scan gives codes, numbers and names). The same folders, sizes and folding as the 「状态」 page's
// 「占地方最多的文件夹」 (macFolders), without its words: what a row is comes as a kind and a name, the folders behind it
// as paths. Read-only: everything is what the space rule measured in its rounds (core.SpaceSizes, the subfolders in
// core.SpaceMeasuredTable, the biggest files in core.SpaceTopFilesTable), and what can go in a row is what
// data/overview counts (dataItems: the last round's plans); the folders are not looked at on disk when it is read.
// Every field is described in docs/data-resources.md.

import (
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// What data/usage lists at most: the rows (the biggest first; the rest counted in more), the biggest things in a row,
// the folders of a folded row (the rest counted in pathsMore). Variables for the tests.
var (
	dataUsageMost      = 10
	dataUsageTop       = 5
	dataUsagePathsMost = 20
)

// usageMinBytes: a folder smaller than this is not listed (the page's rule).
const usageMinBytes = 1 << 20

// The kinds of a row of data/usage.
const (
	usageKnown   = "known"        // a folder macOS or a common tool names: id says which (relative to the home)
	usageApp     = "app"          // what an app or a tool keeps: name, holds (data | cache), bundleId when it is an app's
	usageHidden  = "hidden"       // a hidden folder in the home, mostly a tool's: name without the dot
	usageLibrary = "library"      // something else in ~/Library: name is its path under it
	usageFolder  = "folder"       // a folder of the user's own in the home: name
	usageTemp    = "temp"         // the temporary folder
	usageDev     = "dev-caches"   // developer tools' caches, folded into one row
	usageRemoved = "removed-apps" // what apps no longer on this Mac left, folded into one row
)

type usagePath struct {
	path  string
	bytes int64
	grew  *int64 // against the last measurement a week or more before the newest one; nil without one
	day   string // the day of the newest measurement
}

type usageRow struct {
	key, kind            string
	id, name, holds, app string // by kind; app: the bundle id
	paths                []usagePath
	removed              map[string]bool // usageRemoved: the bundle ids
	bytes                int64
}

// usageClass: what a measured folder is: the row it goes into (key: the same key, the same row), ok false for what is
// neither under the home nor the temporary folder. The page's macFolderName, as codes.
func (s *Service) usageClass(path, home string) (usageRow, bool) {
	rel, err := filepath.Rel(home, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		if strings.Contains(path, "/T/") || strings.HasSuffix(path, "/T") || strings.HasPrefix(path, "/private/var/folders") {
			return usageRow{key: usageTemp, kind: usageTemp}, true
		}
		return usageRow{}, false
	}
	if _, ok := macFolderNames[rel]; ok {
		return usageRow{key: usageKnown + "|" + rel, kind: usageKnown, id: rel}, true
	}
	if macDevCaches[filepath.Base(rel)] {
		return usageRow{key: usageDev, kind: usageDev}, true
	}
	// named: a folder named after an app or a tool (the page's macAppName)
	named := func(kind, name, holds string) (usageRow, bool) {
		name = strings.TrimPrefix(name, ".")
		if id := core.StripTeamID(name); core.LooksLikeBundleID(id) {
			if s.Config.AppName != nil {
				if n := s.Config.AppName(id); n != "" {
					return usageRow{key: kind + "|" + n + "|" + holds, kind: kind, name: n, holds: holds, app: id}, true
				}
			}
			return usageRow{key: usageRemoved, kind: usageRemoved}, true
		}
		return usageRow{key: kind + "|" + name + "|" + holds, kind: kind, name: name, holds: holds}, true
	}
	for _, p := range []struct{ prefix, holds string }{{"Library/Application Support/", "data"}, {"Library/Containers/", "data"},
		{"Library/Caches/", "cache"}, {"Library/Developer/", "data"}, {".local/share/", "data"}, {".cache/", "cache"}} {
		if strings.HasPrefix(rel, p.prefix) {
			return named(usageApp, strings.TrimPrefix(rel, p.prefix), p.holds)
		}
	}
	if strings.HasPrefix(rel, ".") {
		return named(usageHidden, rel, "")
	}
	if strings.HasPrefix(rel, "Library/") {
		name := strings.TrimPrefix(rel, "Library/")
		return usageRow{key: usageLibrary + "|" + name, kind: usageLibrary, name: name}, true
	}
	return usageRow{key: usageFolder + "|" + rel, kind: usageFolder, name: rel}, true
}

// usageRows: every measured folder of a megabyte or more, folded into rows, the biggest first. home: the canonical
// home (the space rule keeps canonical paths).
func (s *Service) usageRows(home string) []*usageRow {
	rows := map[string]*usageRow{}
	for path, days := range core.SpaceSizes(s.Store) {
		if len(days) == 0 {
			continue
		}
		keys := make([]string, 0, len(days))
		for d := range days {
			keys = append(keys, d)
		}
		sort.Strings(keys)
		last := keys[len(keys)-1]
		if days[last] < usageMinBytes {
			continue
		}
		class, ok := s.usageClass(path, home)
		if !ok {
			continue
		}
		row := rows[class.key]
		if row == nil {
			row = &class
			rows[class.key] = row
		}
		if row.kind == usageRemoved {
			if row.removed == nil {
				row.removed = map[string]bool{}
			}
			row.removed[core.StripTeamID(strings.TrimPrefix(filepath.Base(path), "."))] = true
		}
		p := usagePath{path: path, bytes: days[last], day: last}
		if t, err := time.Parse("2006-01-02", last); err == nil {
			week := t.AddDate(0, 0, -7).Format("2006-01-02")
			for i := len(keys) - 2; i >= 0; i-- {
				if keys[i] <= week {
					grew := days[last] - days[keys[i]]
					p.grew = &grew
					break
				}
			}
		}
		row.paths = append(row.paths, p)
		row.bytes += p.bytes
	}
	out := make([]*usageRow, 0, len(rows))
	for _, r := range rows {
		sort.Slice(r.paths, func(i, j int) bool {
			if r.paths[i].bytes != r.paths[j].bytes {
				return r.paths[i].bytes > r.paths[j].bytes
			}
			return r.paths[i].path < r.paths[j].path
		})
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes > out[j].bytes
		}
		return out[i].key < out[j].key
	})
	return out
}

// usageTop: the biggest things in a row. A row of one folder: its subfolders (as last measured, a megabyte or more)
// and its own biggest files; a folded row: the folders folded into it.
// exclusive: what deleting a folder of the list gives back (usageShare.exclusive), nil where it is not known.
func usageTop(r *usageRow, measured map[string]core.SpaceMeasured, files map[string][]core.SpaceFile, home string, what usageWhat,
	exclusive func(path string, bytes int64) any) A {
	type thing struct {
		name, path string
		bytes      int64
		dir        bool
	}
	var things []thing
	if len(r.paths) == 1 {
		folder := r.paths[0].path
		for path, m := range measured {
			if filepath.Dir(path) == folder {
				things = append(things, thing{filepath.Base(path), path, m.Bytes, true})
			}
		}
		for _, f := range files[folder] {
			things = append(things, thing{f.Name, filepath.Join(folder, f.Name), f.Bytes, false})
		}
	} else {
		for _, p := range r.paths {
			things = append(things, thing{filepath.Base(p.path), p.path, p.bytes, true})
		}
	}
	sort.Slice(things, func(i, j int) bool {
		if things[i].bytes != things[j].bytes {
			return things[i].bytes > things[j].bytes
		}
		return things[i].path < things[j].path
	})
	out := A{}
	for i, t := range things {
		if i >= dataUsageTop {
			break
		}
		// what: its own entry of the list when it has one (a known folder inside the row's), else the row's
		w := what
		if own, ok := usageListed(t.path, home); ok {
			w = own
		}
		var own any
		if t.dir {
			own = exclusive(t.path, t.bytes)
		}
		out = append(out, O{"name": t.name, "path": t.path, "bytes": t.bytes, "exclusiveBytes": own, "dir": t.dir, "what": w.data(),
			"actions": usageActions([]string{t.path}, home, nil, r.kind, true)})
	}
	return out
}

// usageActions: what can be done about a row (or one of its biggest things: top), as codes: the scan's own cleaning
// first (clean, with the categories of what can go: reclaim; the plans are data/category's), then what
// rules/folders.json lists for the folders (paths: canonical, under the canonical home), each once, in the list's
// order. A folder's actions are those of the entry it is or is inside; when that gives none, those of the entries
// inside it (the row of ~/.ollama, whose entry is models/ below it). Every action has every key; the ones its place
// does not use are null.
// What the apps that are gone left behind (kind usageRemoved) gets nothing done in an app or by a command: the app
// and its command are not there any more. A thing inside the Trash is not told to empty the whole Trash.
func usageActions(paths []string, home string, reclaim *usageReclaim, kind string, top bool) A {
	out := A{}
	if reclaim != nil && reclaim.count > 0 {
		cats := A{}
		for _, c := range reclaim.data()["categories"].(A) {
			cats = append(cats, c.(O)["id"])
		}
		out = append(out, O{"id": core.ActionClean, "by": core.ActionByScan, "pane": nil, "app": nil, "bundleId": nil, "command": nil,
			"categories": cats})
	}
	seen := map[string]bool{}
	for _, p := range paths {
		rel, err := filepath.Rel(home, p)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		rel = filepath.ToSlash(rel)
		acts := core.FolderActions(rel)
		if len(acts) == 0 {
			acts = core.FolderActionsBelow(rel)
		}
		entry, listed := core.WhatFolder(rel)
		for _, a := range acts {
			if seen[a.ID] {
				continue
			}
			if kind == usageRemoved && (a.By == core.ActionByApp || a.By == core.ActionByCommand) {
				continue
			}
			if top && a.ID == core.ActionEmptyTrash && listed && entry.Path != rel {
				continue
			}
			seen[a.ID] = true
			out = append(out, O{"id": a.ID, "by": a.By, "pane": nilIfEmpty(a.Pane), "app": nilIfEmpty(a.App),
				"bundleId": nilIfEmpty(a.BundleID), "command": nilIfEmpty(a.Command), "categories": nil})
		}
	}
	return out
}

// usageShare: files that share their blocks (APFS clones) and files with several names (hard links), as the space
// rule remembered them of each measured folder (core.SpaceClonesTable): what of a row's bytes deleting it gives back,
// and the rows' sum with shared blocks counted once (luoke-scan#226).
type usageShare struct {
	clones map[string]core.SpaceClones
	all    core.SpaceCloneSum // every row's folders
}

func (s *Service) usageShare(rows []*usageRow) *usageShare {
	u := &usageShare{clones: core.SpaceClonesTable(s.Store).Load()}
	for _, r := range rows {
		for _, p := range r.paths {
			if c, ok := u.clones[p.path]; ok {
				u.all.Add(c)
			} else {
				u.all.Unchecked += p.bytes
			}
		}
	}
	return u
}

// of: of these folders together (bytes: their sizes added up): exclusive, what deleting them gives back; shared, the
// blocks in them that files elsewhere hold too (counted once); unchecked, the bytes not looked at for sharing (they
// count as sharing nothing). known false when none of the folders was looked at.
func (u *usageShare) of(paths []string, bytes int64, size func(string) int64) (exclusive, shared, unchecked int64, known bool) {
	var sum core.SpaceCloneSum
	for _, p := range paths {
		if c, ok := u.clones[p]; ok {
			sum.Add(c)
			known = true
		} else {
			sum.Unchecked += size(p)
		}
	}
	repeated, shared := sum.Split(&u.all)
	return max(0, bytes-repeated-shared), shared, sum.Unchecked, known
}

// exclusive: of one folder, for usageTop: nil when it was not looked at for sharing.
func (u *usageShare) exclusive(path string, bytes int64) any {
	own, _, _, known := u.of([]string{path}, bytes, func(string) int64 { return bytes })
	if !known {
		return nil
	}
	return own
}

// usageWhat: what a row (or one of its biggest things) is: whose (a code), what it holds, what deleting it loses. Each
// is "" where it is not known.
type usageWhat struct{ owner, content, ifDeleted string }

func (w usageWhat) data() O {
	return O{"owner": nilIfEmpty(w.owner), "content": nilIfEmpty(w.content), "ifDeleted": nilIfEmpty(w.ifDeleted)}
}

// usageListed: what rules/folders.json says the folder or file at path (canonical, under the canonical home) is.
func usageListed(path, home string) (usageWhat, bool) {
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return usageWhat{}, false
	}
	f, ok := core.WhatFolder(filepath.ToSlash(rel))
	if !ok {
		return usageWhat{}, false
	}
	return usageWhat{f.Owner, f.Content, f.IfDeleted}, true
}

// what: what the row is. By the list when every folder of the row has an entry saying the same; else what its kind
// alone makes certain: a cache comes back, the temporary folder's files are made again, what a removed app left has
// no app to make it again, a folder of the user's own is the user's. An app's data, a hidden folder and the rest of
// ~/Library are not known (an app's data may be the user's work or only its settings).
func (r *usageRow) what(home string) usageWhat {
	var listed usageWhat
	same := len(r.paths) > 0
	for i, p := range r.paths {
		w, ok := usageListed(p.path, home)
		if !ok || (i > 0 && w != listed) {
			same = false
			break
		}
		listed = w
	}
	if same {
		return listed
	}
	switch {
	case r.kind == usageApp && r.holds == "cache", r.kind == usageDev:
		return usageWhat{content: core.ContentCache, ifDeleted: core.DeletedRebuilds}
	case r.kind == usageApp:
		return usageWhat{content: core.ContentAppData}
	case r.kind == usageTemp:
		return usageWhat{content: core.ContentTemp, ifDeleted: core.DeletedRebuilds}
	case r.kind == usageRemoved:
		return usageWhat{content: core.ContentAppData, ifDeleted: core.DeletedLost}
	case r.kind == usageFolder:
		return usageWhat{owner: "user", content: core.ContentUser, ifDeleted: core.DeletedLost}
	}
	return usageWhat{}
}

// What a row's mix lists at most: the kinds (the rest are folded into other), the years (the oldest are folded into
// the last one listed, marked before), the files.
var (
	dataUsageMixKinds = 8
	dataUsageMixYears = 10
	dataUsageMixFiles = 10
)

// usageMix: what a row is made of, all the way down: its folders' mixes (core.SpaceMixTable) together. nil when none
// of its folders has one yet (measured by a version before this one, not walked again since).
func usageMix(r *usageRow, mixes map[string]core.SpaceMix) any {
	kinds, years := map[string]core.SpaceTally{}, map[string]int64{}
	type file struct {
		core.SpaceBigFile
		path string
	}
	var files []file
	found := false
	var unknown int64
	for _, p := range r.paths {
		m, ok := mixes[p.path]
		if !ok {
			unknown += p.bytes
			continue
		}
		found = true
		unknown += m.Unknown
		for k, t := range m.Kinds {
			x := kinds[k]
			x.Bytes += t.Bytes
			x.Count += t.Count
			kinds[k] = x
		}
		for y, b := range m.Years {
			years[y] += b
		}
		for _, f := range m.Top {
			files = append(files, file{f, filepath.Join(p.path, filepath.FromSlash(f.Path))})
		}
	}
	if !found {
		return nil
	}
	var bytes, count int64
	ids := make([]string, 0, len(kinds))
	for k, t := range kinds {
		bytes += t.Bytes
		count += t.Count
		if k != core.KindOther {
			ids = append(ids, k)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		if kinds[ids[i]].Bytes != kinds[ids[j]].Bytes {
			return kinds[ids[i]].Bytes > kinds[ids[j]].Bytes
		}
		return ids[i] < ids[j]
	})
	other := kinds[core.KindOther]
	ks := A{}
	for i, k := range ids {
		if i >= dataUsageMixKinds || kinds[k].Bytes == 0 {
			other.Bytes += kinds[k].Bytes
			other.Count += kinds[k].Count
			continue
		}
		ks = append(ks, O{"id": k, "bytes": kinds[k].Bytes, "count": kinds[k].Count})
	}
	if other.Count > 0 {
		ks = append(ks, O{"id": core.KindOther, "bytes": other.Bytes, "count": other.Count})
	}
	// years: the newest first; the ones past the limit folded into the last listed (before: true); a date that is not
	// one (before 1980, in the future) last, year null
	var ys []string
	for y := range years {
		if y != "" {
			ys = append(ys, y)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ys)))
	yo := A{}
	for i, y := range ys {
		n, _ := strconv.Atoi(y)
		if i < dataUsageMixYears {
			yo = append(yo, O{"year": n, "bytes": years[y], "before": false})
			continue
		}
		last := yo[len(yo)-1].(O)
		last["bytes"] = last["bytes"].(int64) + years[y]
		last["before"] = true
	}
	if b, ok := years[""]; ok {
		yo = append(yo, O{"year": nil, "bytes": b, "before": false})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].Bytes != files[j].Bytes {
			return files[i].Bytes > files[j].Bytes
		}
		return files[i].path < files[j].path
	})
	fo := A{}
	for i, f := range files {
		if i >= dataUsageMixFiles {
			break
		}
		fo = append(fo, O{"name": filepath.Base(f.path), "path": f.path, "bytes": f.Bytes, "kind": core.FileKind(filepath.Base(f.path)),
			"modified": f.Modified})
	}
	return O{"bytes": bytes, "count": count, "unknown": unknown, "kinds": ks, "years": yo, "files": fo}
}

// usageAlign: a plan's target written as the rows' folders are. The space rule keeps canonical paths (core.Canonical);
// a plan keeps a target as its rule found it, under the home and the temporary folder as configured. Those two roots
// (and /private/var/…, /private/tmp/… for /var/…, /tmp/…, as Canonical shortens them) become their canonical form;
// nothing else is looked at on disk. home: the canonical home.
func (s *Service) usageAlign(home string) func(string) string {
	type alias struct{ raw, canon string }
	var as []alias
	add := func(raw, canon string) {
		raw = filepath.Clean(raw)
		if raw != canon {
			as = append(as, alias{raw, canon})
		}
		for _, d := range []string{"/var", "/tmp", "/etc"} {
			if canon == d || strings.HasPrefix(canon, d+"/") {
				as = append(as, alias{"/private" + canon, canon})
			}
		}
	}
	add(s.Config.Context.Home, home)
	if tmp := s.Config.Context.Tmp; tmp != "" {
		add(tmp, core.Canonical(tmp))
	}
	sort.SliceStable(as, func(i, j int) bool { return len(as[i].raw) > len(as[j].raw) })
	return func(p string) string {
		p = filepath.Clean(p)
		for _, a := range as {
			if p == a.raw || strings.HasPrefix(p, a.raw+"/") {
				return a.canon + p[len(a.raw):]
			}
		}
		return p
	}
}

// usageTally: what can go, items and their bytes.
type usageTally struct {
	bytes int64
	count int
}

// usageReclaim: what can go in a row, all of it and by category.
type usageReclaim struct {
	usageTally
	by map[string]*usageTally
}

// usageReclaims: what can go in each row (by its index in rows): the items data/overview's reclaimable counts
// (dataItems), each put where its targets are. A target is in a row when it is one of the row's folders (all of them,
// not only the ones listed) or inside one, by whole path segments. An item counts in the row that holds the most of
// its targets; where rows hold as many, in the first of them in the rows' order (the bigger, then by key). A row
// nested in another (a folder measured whole and its subfolder measured too) holds the same targets, and counts the
// item as well, as their bytes count the same folders twice. An item with no target in any row counts in none. Its
// bytes are the item's, all of them, also when some of its targets are in other rows or in none. The categories in
// dataNotReclaimable count in no row.
func usageReclaims(rows []*usageRow, items map[string][]dataItem, align func(string) string) []usageReclaim {
	at := map[string]int{} // a row's folder → the row
	for i, r := range rows {
		for _, p := range r.paths {
			at[p.path] = i
		}
	}
	out := make([]usageReclaim, len(rows))
	for id, list := range items {
		if slices.Contains(dataNotReclaimable, id) {
			continue
		}
		for _, d := range list {
			held := map[int][]int{} // row → the item's targets in it, by index
			for ti, t := range d.targets {
				for p := align(t); ; p = filepath.Dir(p) {
					if i, ok := at[p]; ok {
						if ts := held[i]; len(ts) == 0 || ts[len(ts)-1] != ti {
							held[i] = append(ts, ti)
						}
					}
					if p == "/" || p == "." {
						break
					}
				}
			}
			best := -1
			for i, ts := range held {
				if best < 0 || len(ts) > len(held[best]) || (len(ts) == len(held[best]) && i < best) {
					best = i
				}
			}
			if best < 0 {
				continue
			}
			for i, ts := range held {
				if !slices.Equal(ts, held[best]) {
					continue
				}
				u := &out[i]
				u.bytes += d.bytes
				u.count++
				if u.by == nil {
					u.by = map[string]*usageTally{}
				}
				c := u.by[id]
				if c == nil {
					c = &usageTally{}
					u.by[id] = c
				}
				c.bytes += d.bytes
				c.count++
			}
		}
	}
	return out
}

// data: a row's reclaim, the biggest category first (then in the overview's order of categories).
func (u usageReclaim) data() O {
	rank := func(id string) int {
		if i := slices.Index(dataCategories, id); i >= 0 {
			return i
		}
		return len(dataCategories)
	}
	ids := make([]string, 0, len(u.by))
	for id := range u.by {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := u.by[ids[i]], u.by[ids[j]]
		if a.bytes != b.bytes {
			return a.bytes > b.bytes
		}
		if rank(ids[i]) != rank(ids[j]) {
			return rank(ids[i]) < rank(ids[j])
		}
		return ids[i] < ids[j]
	})
	cats := A{}
	for _, id := range ids {
		cats = append(cats, O{"id": id, "bytes": u.by[id].bytes, "count": u.by[id].count})
	}
	return O{"bytes": u.bytes, "count": u.count, "categories": cats}
}

// dataUsage: data/usage.
func (s *Service) dataUsage() O {
	r := s.Store.LastReport()
	home := core.Canonical(s.Config.Context.Home)
	rows := s.usageRows(home)
	reclaim := usageReclaims(rows, s.dataItems(r, s.state()), s.usageAlign(home))
	measured := core.SpaceMeasuredTable(s.Store).Load()
	files := core.SpaceTopFilesTable(s.Store).Load()
	mixes := core.SpaceMixTable(s.Store).Load()
	share := s.usageShare(rows)
	folders := A{}
	var listed, all int64
	for i, row := range rows {
		all += row.bytes
		if i >= dataUsageMost {
			continue
		}
		listed += row.bytes
		paths := A{}
		for j, p := range row.paths {
			if j >= dataUsagePathsMost {
				break
			}
			paths = append(paths, p.path)
		}
		// grew7d: what the folders with a measurement a week back grew by, together; day: the oldest of their newest
		// measurements (a folder the last round did not get to keeps an older day)
		var grew any
		var sum int64
		day := ""
		for _, p := range row.paths {
			if p.grew != nil {
				sum += *p.grew
				grew = sum
			}
			if day == "" || p.day < day {
				day = p.day
			}
		}
		what := row.what(home)
		// exclusiveBytes, sharedBytes: null while none of the row's folders was looked at for sharing
		var exclusive, shared any
		folderPaths, sizes := make([]string, 0, len(row.paths)), map[string]int64{}
		for _, p := range row.paths {
			folderPaths = append(folderPaths, p.path)
			sizes[p.path] = p.bytes
		}
		own, with, unchecked, known := share.of(folderPaths, row.bytes, func(p string) int64 { return sizes[p] })
		if known {
			exclusive, shared = own, with
		}
		o := O{"kind": row.kind, "what": what.data(), "id": nilIfEmpty(row.id), "name": nilIfEmpty(row.name), "holds": nilIfEmpty(row.holds),
			"bundleId": nilIfEmpty(row.app), "apps": nil, "paths": paths, "pathsMore": max(0, len(row.paths)-dataUsagePathsMost),
			"bytes": row.bytes, "exclusiveBytes": exclusive, "sharedBytes": shared, "shareUncheckedBytes": unchecked,
			"grew7d": grew, "day": day, "top": usageTop(row, measured, files, home, what, share.exclusive), "reclaim": reclaim[i].data(),
			"mix": usageMix(row, mixes)}
		all := make([]string, 0, len(row.paths))
		for _, p := range row.paths {
			all = append(all, p.path)
		}
		o["actions"] = usageActions(all, home, &reclaim[i], row.kind, false)
		if row.kind == usageRemoved {
			o["apps"] = len(row.removed)
		}
		folders = append(folders, o)
	}
	// complete: the last round looked everywhere; without Full Disk Access the guarded folders were not measured that
	// round (what is listed of them is from an earlier round, by its day), unseen says which, relative to the home
	var complete any
	unseen := A{}
	if r != nil {
		full := roundHadFullAccess(*r)
		complete = full
		if !full {
			unseen = stringsA(core.Guarded)
		}
	}
	return O{"schema": dataSchema, "scanned": scannedData(r), "complete": complete, "unseen": unseen, "folders": folders,
		"more": max(0, len(rows)-dataUsageMost), "listedBytes": listed,
		// measuredBytes: what the rows take on disk together: their bytes added up, blocks several files share (clones)
		// counted once. listedBytes stays the listed rows' bytes added up.
		"measuredBytes": max(0, all-share.all.Repeated()), "shareUncheckedBytes": share.all.Unchecked,
		"reconcile": s.reconcileData()}
}

// reconcileData: the last round's account of the disk (core.ReconcileRule): what the disk says is
// used, what was measured of it by part, what was not measured and why, and what is left that nothing explains. nil
// when no account was made (never scanned, the disk's use not known). unexplained is nil while something that can be
// large was not measured (complete false): the rest is not called unexplained then.
func (s *Service) reconcileData() any {
	a, ok := core.LastReconcile(s.Store)
	if !ok {
		return nil
	}
	parts, gaps := A{}, A{}
	for _, p := range a.Parts {
		parts = append(parts, O{"id": p.ID, "bytes": p.Bytes})
	}
	for _, g := range a.Gaps {
		gaps = append(gaps, O{"id": g.ID, "why": g.Why, "blocks": g.Open})
	}
	var unexplained any
	if a.Complete {
		unexplained = a.Unexplained
	}
	return O{"day": a.Day, "total": a.Total, "used": a.Used, "purgeable": a.Purgeable, "parts": parts,
		"measured": a.Measured(), "unmeasured": gaps, "complete": a.Complete, "unexplained": unexplained,
		"threshold": a.Threshold, "over": a.Over()}
}
