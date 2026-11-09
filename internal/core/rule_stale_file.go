package core

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() { Register("stale.large-file", NewStaleFileRule) }

// StaleFileRule finds large files in the home nobody has opened for a long time, as Spotlight knows it
// (kMDItemLastUsedDate, set when a file is opened from Finder or an app). One never opened counts from when it last
// changed. Spotlight's index is asked, nothing is walked; folders it does not index (Library, hidden ones) are not
// looked at here.
type StaleFileRule struct {
	Unused   time.Duration
	MinBytes int64
	MaxFiles int
	// Query is the paths Spotlight finds under home: at least minBytes, last opened before cutoff (or never opened and
	// last changed before it); ok false when Spotlight does not answer. nil: this Mac's (mdfind).
	Query func(home string, cutoff time.Time, minBytes int64) ([]string, bool)
	// Dates are when Spotlight saw the file last opened and when it last changed (zero: not known). nil: this Mac's (mdls).
	Dates func(path string) (used, changed time.Time)
}

// NewStaleFileRule makes the rule; for a fake home Spotlight's answers are its fakes' and files count from 1 MiB.
func NewStaleFileRule(l *Layout, f *Fakes) Rule {
	r := &StaleFileRule{Unused: 365 * 24 * time.Hour, MinBytes: 500_000_000, MaxFiles: 20}
	if l != nil {
		r.MinBytes = 1 << 20
		stale := f.StaleFiles
		r.Query = func(string, time.Time, int64) ([]string, bool) {
			if stale == nil {
				return nil, false
			}
			paths := make([]string, len(*stale))
			for i, s := range *stale {
				paths[i] = s.Path
			}
			return paths, true
		}
		r.Dates = func(p string) (time.Time, time.Time) {
			var used, changed time.Time
			found := false
			if stale != nil {
				for _, s := range *stale {
					if s.Path == p {
						found = true
						if s.Used != nil {
							used = *s.Used
						}
						if s.Changed != nil {
							changed = *s.Changed
						}
						break
					}
				}
			}
			if !found || changed.IsZero() {
				changed, _ = Modified(p)
			}
			return used, changed
		}
	}
	return r
}

func (r *StaleFileRule) ID() string      { return "stale.large-file" }
func (r *StaleFileRule) Emits() []string { return []string{"stale.large-file"} }

// staleQueryText is the Spotlight query for files of at least minBytes not opened (or, never opened, not changed)
// since cutoff.
func staleQueryText(cutoff time.Time, minBytes int64) string {
	t := "$time.iso(" + ISOTime(cutoff) + ")"
	return "kMDItemFSSize > " + strconv.FormatInt(minBytes, 10) + " && ((kMDItemLastUsedDate == * && kMDItemLastUsedDate < " + t + ")" +
		" || (kMDItemLastUsedDate != * && kMDItemFSContentChangeDate < " + t + "))"
}

func thisMacStaleQuery(home string, cutoff time.Time, minBytes int64) ([]string, bool) {
	r := Run("/usr/bin/mdfind", []string{"-0", "-onlyin", home, staleQueryText(cutoff, minBytes)}, RunOpts{Timeout: 120 * time.Second})
	if r.Status != 0 {
		return nil, false
	}
	var out []string
	for _, p := range strings.Split(r.Stdout, "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out, true
}

// thisMacStaleDates asks Spotlight (mdls) when a file was last opened and changed; the file's own modification time
// when Spotlight does not say when it changed.
func thisMacStaleDates(path string) (time.Time, time.Time) {
	var used, changed time.Time
	r := Run("/usr/bin/mdls", []string{"-raw", "-name", "kMDItemLastUsedDate", "-name", "kMDItemFSContentChangeDate", path},
		RunOpts{Timeout: 20 * time.Second})
	if r.Status == 0 {
		parts := strings.Split(r.Stdout, "\x00")
		parse := func(s string) time.Time {
			t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(s))
			if err != nil {
				return time.Time{}
			}
			return t
		}
		if len(parts) >= 2 {
			used, changed = parse(parts[0]), parse(parts[1])
		}
	}
	if changed.IsZero() {
		changed, _ = Modified(path)
	}
	return used, changed
}

// staleSkipped says whether a path is inside a package (an app, a photo or iMovie library, a VM bundle: anything
// Finder shows as one file; deleting a part breaks the whole), in ~/Library, the Trash, or git's own.
func staleSkipped(path, home string) bool {
	rel := path
	if strings.HasPrefix(path, home+"/") {
		rel = path[len(home):]
	}
	if strings.HasPrefix(rel, "/Library/") || strings.HasPrefix(rel, "/.Trash/") || strings.Contains(path, "/.git/") ||
		strings.Contains(path, "/node_modules/") {
		return true
	}
	for dir := filepath.Dir(path); len([]rune(dir)) > 1 && dir != home; dir = filepath.Dir(dir) {
		if StalePackageExtensions[strings.ToLower(spaceExt(dir))] || spaceHasBundleBit(dir) {
			return true
		}
	}
	return false
}

func (r *StaleFileRule) Run(ctx *Context) ([]Finding, error) {
	query, dates := r.Query, r.Dates
	if query == nil {
		query = thisMacStaleQuery
	}
	if dates == nil {
		dates = thisMacStaleDates
	}
	cutoff := ctx.Now.Add(-r.Unused)
	paths, ok := query(ctx.Home, cutoff, r.MinBytes)
	if !ok {
		return nil, Skip("Spotlight 没答复（可能关掉了索引）")
	}
	// The home as the Swift version spelled it (its --fixture went through standardizedFileURL): compared as text below,
	// so a path Spotlight spells another way (/private/var… for /var…) is not taken as under it.
	home := spaceStandardized(ctx.Home)
	var out []Finding
	for _, p := range paths {
		if !ctx.MayLook(p) || staleSkipped(p, home) {
			continue
		}
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, out...)
		}
		item, ok := Item(p)
		if !ok || item.IsDir || item.IsLink || item.Bytes < r.MinBytes {
			continue
		}
		// The index can be behind: the dates are checked again here.
		used, changed := dates(p)
		last := used
		if last.IsZero() {
			last = changed
		}
		if last.IsZero() || !last.Before(cutoff) {
			continue
		}
		years := ctx.Now.Sub(last).Seconds() / (365 * 86400)
		age := "一年多"
		if years >= 2 {
			age = strconv.Itoa(int(years)) + " 年多"
		}
		name := filepath.Base(p)
		ev := map[string]string{"how": "还要就留着（可以挪到外接硬盘）；不要了就移到废纸篓"}
		title := name + "（" + FormatBytes(item.Bytes) + "）" + age + "没打开过"
		if !used.IsZero() {
			ev["last_opened"] = ISODay(used)
		} else {
			ev["never_opened"] = "1"
			ev["last_changed"] = ISODay(last)
			title = name + "（" + FormatBytes(item.Bytes) + "）没打开过，" + age + "前放进来的"
		}
		out = append(out, Finding{Rule: "stale.large-file", Category: CatSpace, Severity: Low, Verdict: Confirm, Path: p,
			Bytes: Size(item.Bytes), Title: title, Evidence: ev})
	}
	sort.SliceStable(out, func(i, j int) bool { return bytesOf(out[i]) > bytesOf(out[j]) })
	if len(out) > r.MaxFiles {
		out = out[:r.MaxFiles]
	}
	if ctx.FullDiskAccess != nil && !*ctx.FullDiskAccess {
		return nil, Skip(NotLooked("桌面、文稿、下载里很久没打开的大文件"), out...)
	}
	return out, nil
}
