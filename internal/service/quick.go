package service

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// QuickLookWaits is why the quick look between rounds waits now, "" when it can go. It loads the whole virus database
// (about 1 GB, ten-odd seconds of CPU) while the user is most likely at the Mac: only on mains power, not in Low Power
// Mode, not while memory is tight. What came meanwhile stays in the journal for the next look.
func QuickLookWaits(onBattery, lowPower bool, memoryPressure int32) string {
	switch {
	case onBattery:
		return "在用电池，接上电源再看"
	case lowPower:
		return "开着低电量模式"
	case memoryPressure > 1:
		return "内存紧张"
	}
	return ""
}

// QuickLookWaitsNow is QuickLookWaits for this Mac as it is now.
func QuickLookWaitsNow() string {
	return QuickLookWaits(onBatteryNow(), lowPowerNow(), memoryPressureNow())
}

// onBatteryNow says whether this Mac runs on its battery (one without a battery never does): pmset's "Now drawing
// from 'Battery Power'".
func onBatteryNow() bool {
	r := core.Run("/usr/bin/pmset", []string{"-g", "ps"}, core.RunOpts{Timeout: 10 * time.Second})
	return r.Status == 0 && strings.Contains(strings.SplitN(r.Stdout, "\n", 2)[0], "'Battery Power'")
}

// lowPowerNow says whether Low Power Mode is on (pmset's lowpowermode setting).
func lowPowerNow() bool {
	r := core.Run("/usr/bin/pmset", []string{"-g"}, core.RunOpts{Timeout: 10 * time.Second})
	if r.Status != 0 {
		return false
	}
	for _, line := range strings.Split(r.Stdout, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "lowpowermode" {
			return f[1] == "1"
		}
	}
	return false
}

// memoryPressureNow is 1 normal, 2 warning, 4 critical (kern.memorystatus_vm_pressure_level); 1 when it cannot be read.
func memoryPressureNow() int32 {
	v, err := syscall.SysctlUint32("kern.memorystatus_vm_pressure_level")
	if err != nil {
		return 1
	}
	return int32(v)
}

// RunQuick is a quick look between rounds (luoke-scan scan --quick, every few minutes): only when the journal shows
// something written in Downloads or on the Desktop since the last look, only the virus scan (its record skips what it
// has seen already), what it finds put into the last round's report in place of what it found then. nil when there was
// nothing to look at, or no full round yet (the first is a full one).
//
// It does not hold the round lock while it scans (a full round is never kept waiting by it): it looks first and does
// nothing while a round runs, and takes the lock only to save, then only if the report is still the one it started
// from. It gives clamscan minutes, not half an hour: more than that is left to the next full round. A file still being
// written is left for the next look, which then scans whatever the journal shows.
func (s *Service) RunQuick(journal core.JournalSource) *core.Report {
	if core.LockHeld(s.Store.Dir) {
		return nil
	}
	last := s.Store.LastReport()
	if last == nil {
		return nil
	}
	var malware core.Rule
	for _, r := range s.Config.Rules {
		if r.ID() == "malware" {
			malware = r
			break
		}
	}
	if malware == nil {
		return nil
	}
	unsettled := 0 // files the scan left for later, still being written
	if m, ok := malware.(*core.MalwareRule); ok {
		q := *m
		q.ClamscanTimeout, q.YaraTimeout, q.SettleFor = 240*time.Second, 120*time.Second, 120*time.Second
		q.Quick = true
		q.LeftUnsettled = func(n int) { unsettled = n }
		malware = &q
	}
	ctx := s.Config.Context
	ctx.Store = s.Store
	ctx.Now = s.now()
	// Without Full Disk Access neither may be looked into: nothing for a quick look to do.
	var roots []string
	for _, name := range []string{"Downloads", "Desktop"} {
		if u := filepath.Join(ctx.Home, name); ctx.MayLook(u) && core.Exists(u) {
			roots = append(roots, u)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	start := journal.CurrentEventID()
	var ids []string
	known := true
	for _, r := range roots {
		id := journal.JournalID(r)
		known = known && id != ""
		ids = append(ids, id)
	}
	id := ""
	if known {
		sort.Strings(ids)
		id = strings.Join(ids, ",")
	}
	if v, ok := s.Store.Get("quick.event"); ok && id != "" {
		was, _ := s.Store.Get("quick.journal")
		if since, err := strconv.ParseUint(v, 10, 64); err == nil && was == id {
			changes := journal.Replay(roots, since, ctx.IsCancelled)
			touched := false
			for _, r := range roots {
				touched = touched || changes.Touched(core.Canonical(r), since)
			}
			if !changes.Unknown && !touched {
				s.Store.Set("quick.event", strconv.FormatUint(start, 10))
				return nil
			}
		}
	}
	part := core.RunRound(&ctx, []core.Rule{malware}, s.Config.Clock, last)
	if !core.LockHeld(s.Store.Dir) { // what this one check wrote of its progress is not a round's
		s.Store.ClearProgress()
	}
	// Stopped, timed out or not run: what the round found stands.
	if ctx.IsCancelled() {
		return nil
	}
	for _, sk := range part.Skipped {
		if sk.Rule == malware.ID() {
			return nil
		}
	}
	lock := core.TakeLock(s.Store.Dir, "round.lock", 3*time.Second)
	if lock == nil {
		return nil
	}
	defer lock.Release()
	now := s.Store.LastReport()
	if now == nil || !now.StartedAt.Equal(last.StartedAt.Time) || !now.FinishedAt.Equal(last.FinishedAt.Time) {
		return nil
	}
	report := core.Replacing(*last, malware, part, s.Config.Rules)
	s.Store.SaveReport(report)
	// What wrote a file left for later is in the journal before start: replayed from there, the next look would see
	// nothing new and leave the file to the next full round, a day later. So no event id is kept then: the next look
	// scans again (what has not changed is taken from the record, not rescanned).
	if unsettled > 0 {
		s.Store.Set("quick.event", "")
	} else {
		s.Store.Set("quick.event", strconv.FormatUint(start, 10))
	}
	s.Store.Set("quick.journal", id)
	return &report
}
