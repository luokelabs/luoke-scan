package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The cleanup eval (ADR 0016, revision 10-27): fake homes with the answers buried in them, run through the real rules
// and AutoPick. Each case says what must be picked (auto) and what must not (keep); anything picked that the case did
// not list under auto counts as wrong too. A wrong pick is the hard limit: automatic cleaning stays off while there is
// one. A miss only lowers recall.
//
// Cases are JSON (evals/cleanup/cases.json). Paths are relative to the fake home; $TMP/ is its temp folder and $APPS/
// its Applications folder. In auto and keep, * matches any run of characters ($TMP/lighthouse.old*).

// CleanupSuite is the cases file.
type CleanupSuite struct {
	Version int           `json:"version"`
	Cases   []CleanupCase `json:"cases"`
}

// CleanupCase is one fake home and its answers.
type CleanupCase struct {
	ID      string        `json:"id"`
	Kind    AutoKind      `json:"kind"`
	Why     string        `json:"why"`
	Setup   []CleanupStep `json:"setup"`
	Running []string      `json:"running"`
	Off     []AutoKind    `json:"off"`
	Ignore  []string      `json:"ignore"`
	Auto    []string      `json:"auto"`
	Keep    []string      `json:"keep"`
}

// CleanupStep is one thing put in the fake home: exactly one of file, cache, temp_group, app, link, hardlink, clone,
// attached is set.
type CleanupStep struct {
	File         *string  `json:"file"`
	MB           *int     `json:"mb"`
	Content      *string  `json:"content"`
	Variant      *string  `json:"variant"`
	Quarantine   *bool    `json:"quarantine"`
	Signed       *bool    `json:"signed"`
	ModifiedDays *float64 `json:"modified_days"`
	AddedDays    *float64 `json:"added_days"`
	Cache        *string  `json:"cache"`
	TempGroup    *string  `json:"temp_group"`
	Count        *int     `json:"count"`
	Tag          *string  `json:"tag"`
	MBEach       *int     `json:"mb_each"`
	IdleDays     *float64 `json:"idle_days"`
	Sep          *string  `json:"sep"`
	Locked       *bool    `json:"locked"`
	StaleLock    *bool    `json:"stale_lock"`
	App          *string  `json:"app"`
	Version      *string  `json:"version"`
	BundleID     *string  `json:"bundle_id"`
	WebShim      *bool    `json:"web_shim"`
	Link         *string  `json:"link"`
	Hardlink     *string  `json:"hardlink"`
	Clone        *string  `json:"clone"`
	To           *string  `json:"to"`
	Attached     *string  `json:"attached"`
}

// CleanupResult is how one case went.
type CleanupResult struct {
	ID, Why       string
	Kind          AutoKind
	Auto, Keep    int
	Wrong, Missed []string
	Skipped       []string // rules that did not run, with why (a case must not pass because its rule was skipped)
}

// CleanupScore is the whole eval.
type CleanupScore struct{ Results []CleanupResult }

func (s CleanupScore) sum(f func(CleanupResult) int) int {
	n := 0
	for _, r := range s.Results {
		n += f(r)
	}
	return n
}

// Passed: no wrong pick, and every rule ran.
func (s CleanupScore) Passed() bool {
	return s.sum(func(r CleanupResult) int { return len(r.Wrong) }) == 0 && s.sum(func(r CleanupResult) int { return len(r.Skipped) }) == 0
}

// Text is the scorecard, per kind: what should go and what was picked, what must stay and what was picked anyway.
func (s CleanupScore) Text() string {
	lines := []string{fmt.Sprintf("清理规则评测：%d 个用例", len(s.Results)), "",
		"| 类 | 用例 | 该清 | 挑中 | 漏了 | 不该清 | 挑错 |", "|---|---|---|---|---|---|---|"}
	for _, k := range AutoKinds {
		n, auto, missed, keep, wrong := 0, 0, 0, 0, 0
		for _, r := range s.Results {
			if r.Kind == k {
				n++
				auto += r.Auto
				missed += len(r.Missed)
				keep += r.Keep
				wrong += len(r.Wrong)
			}
		}
		lines = append(lines, fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %d |", k, n, auto, auto-missed, missed, keep, wrong))
	}
	for _, r := range s.Results {
		if len(r.Wrong) == 0 && len(r.Missed) == 0 && len(r.Skipped) == 0 {
			continue
		}
		lines = append(lines, "", r.ID+"（"+r.Why+"）")
		for _, x := range r.Wrong {
			lines = append(lines, "  挑错："+x)
		}
		for _, x := range r.Missed {
			lines = append(lines, "  漏了："+x)
		}
		for _, x := range r.Skipped {
			lines = append(lines, "  没跑："+x)
		}
	}
	lines = append(lines, "")
	wrong := s.sum(func(r CleanupResult) int { return len(r.Wrong) })
	skipped := s.sum(func(r CleanupResult) int { return len(r.Skipped) })
	switch {
	case wrong > 0:
		lines = append(lines, fmt.Sprintf("挑错 %d 个：不过，自动清理不能开", wrong))
	case skipped > 0:
		lines = append(lines, "有规则没跑成，这些用例不算数：不过")
	default:
		lines = append(lines, "不该清的一个都没挑：过")
	}
	return strings.Join(lines, "\n")
}

// cleanupBroken: the case is written wrong.
type cleanupBroken struct{ what string }

func (b cleanupBroken) Error() string { return b.what }

// LoadCleanupEval reads the cases file.
func LoadCleanupEval(path string) (CleanupSuite, error) {
	var s CleanupSuite
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

// RunCleanupEval runs every case in a folder of its own under the temp folder (removed afterwards). adjust changes
// the picker before each case (to check that the eval catches a looser one).
func RunCleanupEval(suite CleanupSuite, adjust func(*AutoPick)) (CleanupScore, error) {
	b := make([]byte, 16)
	rand.Read(b)
	root := filepath.Join(os.TempDir(), "luoke-scan-cleanup-eval-"+strings.ToUpper(hex.EncodeToString(b)))
	defer os.RemoveAll(root)
	var score CleanupScore
	for _, c := range suite.Cases {
		r, err := runCleanupCase(c, filepath.Join(root, c.ID), adjust)
		if err != nil {
			return score, err
		}
		score.Results = append(score.Results, r)
		os.RemoveAll(filepath.Join(root, c.ID)) // a few hundred MB each
	}
	return score, nil
}

type cleanupPlace struct {
	home, tmp, apps, data string
	added                 map[string]time.Time
	attached, signed      map[string]bool
	now                   time.Time
}

func newCleanupPlace(root string, now time.Time) (*cleanupPlace, error) {
	p := &cleanupPlace{home: filepath.Join(root, "home"), tmp: filepath.Join(root, "tmp"), apps: filepath.Join(root, "Applications"),
		data: filepath.Join(root, "data"), added: map[string]time.Time{}, attached: map[string]bool{}, signed: map[string]bool{}, now: now}
	for _, d := range []string{filepath.Join(p.home, "Downloads"), p.tmp, p.apps, p.data} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *cleanupPlace) path(rel string) (string, error) {
	if strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
		return "", cleanupBroken{"路径要相对：" + rel}
	}
	switch {
	case strings.HasPrefix(rel, "$TMP/"):
		return filepath.Join(p.tmp, rel[5:]), nil
	case strings.HasPrefix(rel, "$APPS/"):
		return filepath.Join(p.apps, rel[6:]), nil
	}
	return filepath.Join(p.home, rel), nil
}

func (p *cleanupPlace) ago(days *float64) time.Time {
	d := 0.0
	if days != nil {
		d = *days
	}
	return p.now.Add(-time.Duration(d * 86400 * float64(time.Second)))
}

// spot: the folder resolved, the name itself not (a link that is picked stays the link, not what it points at).
func spot(p string) string { return Canonical(filepath.Dir(p)) + "/" + filepath.Base(p) }

func runCleanupCase(c CleanupCase, root string, adjust func(*AutoPick)) (CleanupResult, error) {
	now := time.Now()
	place, err := newCleanupPlace(root, now)
	if err != nil {
		return CleanupResult{}, err
	}
	for _, s := range c.Setup {
		if err := makeCleanupStep(s, place); err != nil {
			return CleanupResult{}, err
		}
	}
	store, err := OpenStore(place.data)
	if err != nil {
		return CleanupResult{}, err
	}
	ctx := NewContext(place.home)
	ctx.Tmp, ctx.Now, ctx.Store, ctx.AppDirs = place.tmp, now, store, []string{place.apps}
	when := func(p string) (time.Time, bool) {
		if t, ok := place.added[Canonical(p)]; ok {
			return t, true
		}
		return DateAdded(p)
	}
	cache := NewCacheRule(nil, nil).(*CacheRule)
	cache.Installed = func(string, string) bool { return false }
	installers := NewInstallLeftoverRule(nil, nil).(*InstallLeftoverRule)
	installers.Shared = filepath.Join(root, "no-shared")
	installers.UsrLocal = filepath.Join(root, "no-usr-local")
	installers.OptHomebrew = filepath.Join(root, "no-opt-homebrew")
	installers.AppleSilicon = func() bool { return true }
	installers.AttachedImages = func() map[string]bool { return place.attached }
	installers.Added = when
	installers.Signed = func(p string) bool { return place.signed[Canonical(p)] }
	rules := []Rule{cache, installers, NewDuplicateRule(nil, nil), NewTempLeakRule(nil, nil)}
	var findings []Finding
	var skipped []string
	for _, r := range rules {
		f, err := r.Run(&ctx)
		findings = append(findings, f...)
		if err != nil {
			skipped = append(skipped, r.ID()+"："+err.Error())
		}
	}

	running := map[string]bool{}
	for _, r := range c.Running {
		running[r] = true
	}
	pick := NewAutoPick(place.home, place.tmp, now, running)
	for _, k := range c.Off {
		pick.Off[k] = true
	}
	pick.Added = when
	pick.Installed = func(string, string) bool { return false }
	var ignore []string
	for _, rel := range c.Ignore {
		p, err := place.path(rel)
		if err != nil {
			return CleanupResult{}, err
		}
		ignore = append(ignore, spot(p))
	}
	for _, f := range findings {
		for _, pat := range ignore {
			if fnmatch(pat, spot(f.Path)) {
				pick.Ignored[f.ID()] = true
			}
		}
	}
	if len(ignore) > 0 && len(pick.Ignored) == 0 {
		return CleanupResult{}, cleanupBroken{c.ID + "：ignore 一条发现也没对上，用例写错了"}
	}
	if adjust != nil {
		adjust(&pick)
	}
	var list []string
	picked, count := map[string]bool{}, map[string]int{}
	for _, it := range pick.Pick(findings) {
		s := spot(it.Path)
		list = append(list, s)
		picked[s] = true
		count[s]++
	}
	var twice []string
	for p, n := range count {
		if n > 1 {
			twice = append(twice, p)
		}
	}
	sort.Strings(twice)

	expand := func(patterns []string) (map[string]bool, error) {
		out := map[string]bool{}
		for _, rel := range patterns {
			p, err := place.path(rel)
			if err != nil {
				return nil, err
			}
			full := spot(p)
			dir := filepath.Dir(full)
			n := 0
			for _, child := range Children(dir) {
				cand := Canonical(dir) + "/" + filepath.Base(child)
				if fnmatch(full, cand) {
					out[cand] = true
					n++
				}
			}
			if n == 0 {
				return nil, cleanupBroken{c.ID + "：" + rel + " 一个也对不上，用例写错了"}
			}
		}
		return out, nil
	}
	autoPaths, err := expand(c.Auto)
	if err != nil {
		return CleanupResult{}, err
	}
	keepPaths, err := expand(c.Keep)
	if err != nil {
		return CleanupResult{}, err
	}
	for p := range autoPaths {
		if keepPaths[p] {
			return CleanupResult{}, cleanupBroken{c.ID + "：" + p + " 既在 auto 又在 keep"}
		}
	}
	rel := func(p string) string {
		p = strings.ReplaceAll(p, Canonical(place.tmp)+"/", "$TMP/")
		return strings.ReplaceAll(p, Canonical(place.home)+"/", "")
	}
	var wrong, missed []string
	for _, p := range sortedKeys(picked) {
		if !autoPaths[p] {
			wrong = append(wrong, rel(p))
		}
	}
	for _, p := range twice {
		wrong = append(wrong, "挑了两次："+rel(p))
	}
	for _, p := range sortedKeys(autoPaths) {
		if !picked[p] {
			missed = append(missed, rel(p))
		}
	}
	_ = list
	return CleanupResult{ID: c.ID, Kind: c.Kind, Why: c.Why, Auto: len(autoPaths), Keep: len(keepPaths), Wrong: wrong, Missed: missed,
		Skipped: skipped}, nil
}

// fnmatch is fnmatch(3) with no flags: * and ? match any character, / included; [...] is a set.
func fnmatch(pattern, name string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			b.WriteString("(?s:.*)")
		case '?':
			b.WriteString("(?s:.)")
		case '[':
			if j := strings.IndexByte(pattern[i+1:], ']'); j > 0 {
				set := pattern[i+1 : i+1+j]
				if strings.HasPrefix(set, "!") {
					set = "^" + set[1:]
				}
				b.WriteString("[" + set + "]")
				i += j + 1
			} else {
				b.WriteString(regexp.QuoteMeta("["))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(name)
}

func makeCleanupStep(s CleanupStep, place *cleanupPlace) error {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	num := func(p *int, d int) int {
		if p == nil {
			return d
		}
		return *p
	}
	yes := func(p *bool) bool { return p != nil && *p }
	switch {
	case s.File != nil:
		u, err := place.path(*s.File)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(u), 0o755)
		seed := *s.File
		if s.Content != nil {
			seed = *s.Content
		}
		if err := writeSeeded(u, num(s.MB, 1), seed, str(s.Variant) == "middle"); err != nil {
			return err
		}
		if yes(s.Signed) {
			place.signed[Canonical(u)] = true
		}
		if yes(s.Quarantine) {
			mark := "0083;" + strconv.FormatInt(place.now.Unix(), 16) + ";Safari;"
			if putXattr(u, "com.apple.quarantine", []byte(mark)) != nil {
				return cleanupBroken{"隔离标记没写上：" + *s.File}
			}
		}
		if err := setFileDates(u, place.ago(s.ModifiedDays)); err != nil {
			return err
		}
		added := s.AddedDays
		if added == nil {
			added = s.ModifiedDays
		}
		place.added[Canonical(u)] = place.ago(added)
	case s.Cache != nil:
		var c *RebuildableCache
		for i := range KnownCaches {
			if KnownCaches[i].ID == *s.Cache {
				c = &KnownCaches[i]
			}
		}
		if c == nil {
			return cleanupBroken{"没有这种缓存：" + *s.Cache}
		}
		u := filepath.Join(place.home, c.Path, "blob")
		os.MkdirAll(filepath.Dir(u), 0o755)
		return writeSeeded(u, num(s.MB, 60), *s.Cache, false)
	case s.TempGroup != nil:
		prefix := *s.TempGroup
		sep := "-"
		if prefix == "lighthouse" {
			sep = "."
		}
		if s.Sep != nil {
			sep = *s.Sep
		}
		tag := "a"
		if s.Tag != nil {
			tag = *s.Tag
		}
		for i := 0; i < num(s.Count, 22); i++ {
			d := filepath.Join(place.tmp, prefix+sep+tag+fmt.Sprintf("%04d", i)+"zz")
			f := filepath.Join(d, "Default/data")
			os.MkdirAll(filepath.Dir(f), 0o755)
			if err := writeSeeded(f, num(s.MBEach, 5), filepath.Base(d), false); err != nil {
				return err
			}
			at := place.ago(s.IdleDays)
			if yes(s.Locked) || yes(s.StaleLock) {
				// pid 999999 is past the largest a Mac hands out: that browser is gone.
				pid := 999999
				if yes(s.Locked) {
					pid = os.Getpid()
				}
				lock := filepath.Join(d, "SingletonLock")
				if err := os.Symlink("localhost-"+strconv.Itoa(pid), lock); err != nil {
					return err
				}
				if lutimes(lock, at) != nil {
					return cleanupBroken{"锁的时间没改成"}
				}
			}
			for _, u := range []string{f, filepath.Dir(f), d} {
				if err := setFileDates(u, at); err != nil {
					return err
				}
			}
		}
	case s.App != nil:
		name := *s.App
		app := filepath.Join(place.apps, name+".app/Contents")
		os.MkdirAll(filepath.Join(app, "MacOS"), 0o755)
		if s.Version != nil || s.BundleID != nil || yes(s.WebShim) {
			entries := [][2]string{{"CFBundleName", name}}
			if s.Version != nil {
				entries = append(entries, [2]string{"CFBundleShortVersionString", *s.Version})
			}
			if s.BundleID != nil {
				entries = append(entries, [2]string{"CFBundleIdentifier", *s.BundleID})
			}
			if yes(s.WebShim) {
				entries = append(entries, [2]string{"CrAppModeShortcutID", "abcdefghijklmnop"})
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i][0] < entries[j][0] })
			var b strings.Builder
			b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n")
			for _, e := range entries {
				b.WriteString("\t<key>" + xmlEscape(e[0]) + "</key>\n\t<string>" + xmlEscape(e[1]) + "</string>\n")
			}
			b.WriteString("</dict>\n</plist>\n")
			return os.WriteFile(filepath.Join(app, "Info.plist"), []byte(b.String()), 0o644)
		}
	case s.Link != nil && s.To != nil:
		u, err := place.path(*s.Link)
		if err != nil {
			return err
		}
		to, err := place.path(*s.To)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(u), 0o755)
		return os.Symlink(to, u)
	case s.Hardlink != nil && s.To != nil:
		u, err := place.path(*s.Hardlink)
		if err != nil {
			return err
		}
		to, err := place.path(*s.To)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(u), 0o755)
		if os.Link(to, u) != nil {
			return cleanupBroken{"硬链接没建成：" + *s.Hardlink}
		}
	case s.Clone != nil && s.To != nil:
		u, err := place.path(*s.Clone)
		if err != nil {
			return err
		}
		to, err := place.path(*s.To)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(u), 0o755)
		if clonefile(to, u) != nil {
			return cleanupBroken{"克隆没建成：" + *s.Clone}
		}
		if err := setFileDates(u, place.ago(s.ModifiedDays)); err != nil {
			return err
		}
		added := s.AddedDays
		if added == nil {
			added = s.ModifiedDays
		}
		place.added[Canonical(u)] = place.ago(added)
	case s.Attached != nil:
		u, err := place.path(*s.Attached)
		if err != nil {
			return err
		}
		place.attached[Canonical(u)] = true
	default:
		return cleanupBroken{"看不懂的一步"}
	}
	return nil
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// writeSeeded writes mb MB made from seed (the same seed and size give the same bytes); middle changes one MB in the
// middle, so the first and last 64 KB stay the same.
func writeSeeded(path string, mb int, seed string, middle bool) error {
	block := func(s string) []byte {
		x := uint64(1469598103934665603)
		for _, c := range []byte(s) {
			x = (x ^ uint64(c)) * 1099511628211
		}
		x |= 1
		d := make([]byte, 1<<20)
		for i := 0; i < len(d); i += 8 {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			for k := 0; k < 8; k++ {
				d[i+k] = byte(x >> (8 * k))
			}
		}
		return d
	}
	f, err := os.Create(path)
	if err != nil {
		return cleanupBroken{"写不了 " + path}
	}
	defer f.Close()
	b, other := block(seed), block(seed+"/middle")
	if mb < 1 {
		mb = 1
	}
	for i := 0; i < mb; i++ {
		chunk := b
		if middle && mb > 2 && i == mb/2 {
			chunk = other
		}
		if _, err := f.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

// setFileDates sets the modification and creation dates.
func setFileDates(path string, t time.Time) error {
	if err := os.Chtimes(path, t, t); err != nil {
		return err
	}
	return setDates(path, syscall.NsecToTimespec(t.UnixNano()), syscall.Timespec{}, false)
}

// lutimes sets a link's own access and modification times (setattrlist without following it).
func lutimes(path string, t time.Time) error {
	tv := unix.NsecToTimeval(t.Truncate(time.Second).UnixNano())
	return unix.Lutimes(path, []unix.Timeval{tv, tv})
}
