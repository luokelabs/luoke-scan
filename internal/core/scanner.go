package core

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Rule is one check of a round.
type Rule interface {
	ID() string
	// Emits are the names its findings start with (its id, and others it reports under, like its .partial notes).
	Emits() []string
	// Run returns what it found, or a *Skipped error when it could not run.
	Run(ctx *Context) ([]Finding, error)
}

// SkippedError is a rule that could not run, with what it had already found.
type SkippedError struct {
	Reason  string
	Partial []Finding
}

func (e *SkippedError) Error() string { return e.Reason }

// Skip makes a SkippedError.
func Skip(reason string, partial ...Finding) error {
	return &SkippedError{Reason: reason, Partial: partial}
}

// Interrupted is why a check did not run in an interrupted round.
const Interrupted = "这一轮被打断了（你回来了），下一轮接着查"

const carried = "这一轮被打断了，沿用"

// Versions every report records: the rule pack, the virus database's date and version, the scanners'.
func Versions(ctx *Context) map[string]string {
	v := map[string]string{"rule_pack": RulePackVersion}
	if ctx.Store != nil {
		db := NewVirusDB(ctx.Store, ctx.Tools)
		if d, ok := db.Date(); ok {
			v["clamav_db_date"] = ISODay(d)
		}
		if ver, ok := ctx.Store.Get("clamav.version"); ok && ver != "" {
			v["clamav_db_version"] = ver
		} else if ver := db.DailyVersion(); ver != "" {
			v["clamav_db_version"] = ver
		}
		if d, ok := MalListDate(ctx.Store.Dir); ok {
			v["malicious_list_date"] = d
		}
	}
	for _, tool := range []string{"clamscan", "yara"} {
		if ctx.IsCancelled() {
			break
		}
		p := ctx.Tools.Path(tool)
		if p == "" {
			continue
		}
		if line := toolVersion(p, ctx.IsCancelled); line != "" {
			v[tool] = line
		}
	}
	return v
}

// toolVersionTries is how often a tool is asked for its version before the report goes without it.
const toolVersionTries = 3

// toolVersion is the first line a tool prints for --version ("" when it does not answer). A tool that fails is asked
// again, twice: on a busy machine starting it has failed once and worked the next time, and a report that drops the
// scanner's version reads as "this scanner is not there".
func toolVersion(path string, cancelled func() bool) string {
	for try := 0; try < toolVersionTries; try++ {
		if try > 0 {
			if cancelled != nil && cancelled() {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if r := Run(path, []string{"--version"}, RunOpts{Timeout: 10 * time.Second}); r.Status == 0 {
			return strings.SplitN(r.Stdout, "\n", 2)[0]
		}
	}
	return ""
}

// RunRound runs the rules. A rule that fails is reported in Skipped, never as "nothing found". In an interrupted
// round the checks it did not get to keep what previous found for them.
func RunRound(ctx *Context, rules []Rule, clock func() time.Time, previous *Report) (report Report) {
	withAppIndex(func() { report = runRound(ctx, rules, clock, previous) })
	return report
}

func runRound(ctx *Context, rules []Rule, clock func() time.Time, previous *Report) Report {
	ctx.Replays = NewJournalCache() // a replay from an earlier round knows nothing of what changed since
	defer limitWalks(ctx)()
	start, wall := clock(), time.Now()
	var findings []Finding
	var skipped []Skipped
	seconds := map[string]float64{}
	tookOver := false
	lookable := func(f Finding) bool { return !strings.HasPrefix(f.Path, "/") || ctx.MayLook(f.Path) }
	stopped := func(r Rule, partial []Finding) {
		findings = append(findings, partial...)
		if previous == nil {
			skipped = append(skipped, Skipped{r.ID(), Interrupted})
			return
		}
		for _, s := range previous.Skipped {
			if s.Rule == r.ID() && !strings.HasPrefix(s.Reason, carried) && !strings.HasPrefix(s.Reason, NoAccessMark) {
				reason := "这一轮被打断了；上一轮也没查成（" + s.Reason + "）"
				if s.Reason == Interrupted {
					reason = Interrupted
				}
				skipped = append(skipped, Skipped{r.ID(), reason})
				return
			}
		}
		have := map[string]bool{}
		for _, f := range partial {
			have[f.Rule+"\x00"+f.Path] = true
		}
		for _, f := range previous.Findings {
			if Owner(f, rules) == r.ID() && !have[f.Rule+"\x00"+f.Path] && lookable(f) {
				findings = append(findings, f)
			}
		}
		reason := fmt.Sprintf("%s %s 那一轮的结果", carried, ISODay(previous.StartedAt.Time))
		for _, s := range previous.Skipped {
			if s.Rule == r.ID() {
				reason = s.Reason
				if strings.HasPrefix(s.Reason, NoAccessMark) {
					reason = fmt.Sprintf("%s %s 那一轮的结果（%s）", carried, ISODay(previous.StartedAt.Time), s.Reason)
				}
			}
		}
		skipped = append(skipped, Skipped{r.ID(), reason})
		tookOver = true
	}
	var done []string
	for _, r := range rules {
		began := time.Now()
		ctx.Store.SaveProgress(RoundProgress{Started: wall, Done: done, Total: len(rules), Current: r.ID()})
		if ctx.IsCancelled() {
			stopped(r, nil)
		} else if found, err := r.Run(ctx); err == nil {
			if ctx.IsCancelled() {
				stopped(r, nil)
			} else {
				findings = append(findings, found...)
			}
		} else if se, ok := err.(*SkippedError); ok && se.Reason == Interrupted {
			stopped(r, se.Partial)
		} else if ok {
			findings = append(findings, se.Partial...)
			skipped = append(skipped, Skipped{r.ID(), se.Reason})
		} else {
			skipped = append(skipped, Skipped{r.ID(), err.Error()})
		}
		seconds[r.ID()] = float64(int(time.Since(began).Seconds()*10+0.5)) / 10
		done = append(done, r.ID())
	}
	if previous != nil && tookOver {
		have := map[string]bool{}
		for _, f := range findings {
			have[f.Rule+"\x00"+f.Path] = true
		}
		for _, f := range previous.Findings {
			if Owner(f, rules) == "" && !have[f.Rule+"\x00"+f.Path] && lookable(f) {
				findings = append(findings, f)
			}
		}
	}
	SortFindings(findings)
	w := Time{wall}
	return Report{Schema: "luoke-scan.report/v1", RulePack: RulePackVersion, StartedAt: Time{start}, FinishedAt: Time{clock()},
		Findings: nonNil(findings), Skipped: nonNilSkipped(skipped), Versions: Versions(ctx), RuleSeconds: seconds, StartedWall: &w}
}

// SortFindings orders findings the most serious and biggest first (stable).
func SortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return bytesOf(a) > bytesOf(b)
	})
}

func bytesOf(f Finding) int64 {
	if f.Bytes == nil {
		return 0
	}
	return *f.Bytes
}

func nonNil(f []Finding) []Finding {
	if f == nil {
		return []Finding{}
	}
	return f
}

func nonNilSkipped(s []Skipped) []Skipped {
	if s == nil {
		return []Skipped{}
	}
	return s
}

// Owner is the rule that made a finding: the one whose longest name the finding's rule starts with; "" none.
func Owner(f Finding, rules []Rule) string {
	best, bestLen := "", -1
	for _, r := range rules {
		for _, n := range r.Emits() {
			if (f.Rule == n || strings.HasPrefix(f.Rule, n+".")) && len(n) > bestLen {
				best, bestLen = r.ID(), len(n)
			}
		}
	}
	return best
}

// Replacing is report with what rule found replaced by part (a later check of that rule alone).
func Replacing(report Report, rule Rule, part Report, rules []Rule) Report {
	r := report
	r.Findings = nil
	for _, f := range report.Findings {
		if Owner(f, rules) != rule.ID() {
			r.Findings = append(r.Findings, f)
		}
	}
	for _, f := range part.Findings {
		if Owner(f, rules) == rule.ID() {
			r.Findings = append(r.Findings, f)
		}
	}
	SortFindings(r.Findings)
	r.Findings = nonNil(r.Findings)
	r.Skipped = nil
	for _, s := range report.Skipped {
		if s.Rule != rule.ID() {
			r.Skipped = append(r.Skipped, s)
		}
	}
	for _, s := range part.Skipped {
		if s.Rule == rule.ID() {
			r.Skipped = append(r.Skipped, s)
		}
	}
	r.Skipped = nonNilSkipped(r.Skipped)
	r.Versions = map[string]string{}
	for k, v := range report.Versions {
		r.Versions[k] = v
	}
	for k, v := range part.Versions {
		r.Versions[k] = v
	}
	return r
}
