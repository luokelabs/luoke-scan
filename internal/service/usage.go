package service

// data/usage: the folders that take the most room, as data (luoke-scan#165; top-level ADR 0028: the page is
// luoke-agent's, the scan gives codes, numbers and names). The same folders, sizes and folding as the 「状态」 page's
// 「占地方最多的文件夹」 (macFolders), without its words: what a row is comes as a kind and a name, the folders behind it
// as paths. Read-only: everything is what the space rule measured in its rounds (core.SpaceSizes, the subfolders in
// core.SpaceMeasuredTable, the biggest files in core.SpaceTopFilesTable); nothing is looked at on disk when it is read.
// Every field is described in docs/data-resources.md.

import (
	"path/filepath"
	"sort"
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

// usageRows: every measured folder of a megabyte or more, folded into rows, the biggest first.
func (s *Service) usageRows() []*usageRow {
	home := core.Canonical(s.Config.Context.Home)
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
func usageTop(r *usageRow, measured map[string]core.SpaceMeasured, files map[string][]core.SpaceFile) A {
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
		out = append(out, O{"name": t.name, "path": t.path, "bytes": t.bytes, "dir": t.dir})
	}
	return out
}

// dataUsage: data/usage.
func (s *Service) dataUsage() O {
	r := s.Store.LastReport()
	rows := s.usageRows()
	measured := core.SpaceMeasuredTable(s.Store).Load()
	files := core.SpaceTopFilesTable(s.Store).Load()
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
		o := O{"kind": row.kind, "id": nilIfEmpty(row.id), "name": nilIfEmpty(row.name), "holds": nilIfEmpty(row.holds),
			"bundleId": nilIfEmpty(row.app), "apps": nil, "paths": paths, "pathsMore": max(0, len(row.paths)-dataUsagePathsMost),
			"bytes": row.bytes, "grew7d": grew, "day": day, "top": usageTop(row, measured, files)}
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
		"more": max(0, len(rows)-dataUsageMost), "listedBytes": listed, "measuredBytes": all}
}
