package service

import (
	"fmt"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The round running now, as the overview page, the summary and scan_status show it (luoke-scan#101): a round started
// with 「现在查一下」 runs in a process of its own, and writes how far it has got (core.RoundProgress) for the pages drawn
// meanwhile by other processes.
//
// The window draws a page when it opens it, and again when the agent tells it the app changed: the agent compares the
// summary each time it reads the outbox (once a minute, and right after a button), so the summary says that a round
// runs and how far it is. It changes when the round starts, as it goes, and when it ends, and each change has the
// window draw the page again: the bar moves, and the new results replace the old ones once the round is done.

// scanProgress: the round running now in a few words, and how far it is (0 to 1; below 0 not known). How far is
// weighed by how long each check took last time, when there is a last time; else checks done of all. The overview,
// the summary, scan_status and the 「状态」 page all say it this way.
func (s *Service) scanProgress(last *core.Report) (string, float64) {
	p := s.Store.Progress()
	if p == nil || p.Total == 0 {
		return "刚开始", -1
	}
	if p.Current == "model" {
		return "都查完了，在写说明", 1
	}
	frac := float64(len(p.Done)) / float64(p.Total)
	left := time.Duration(0)
	if last != nil && len(last.RuleSeconds) > 0 {
		var all, done float64
		doneSet := map[string]bool{}
		for _, id := range p.Done {
			doneSet[id] = true
		}
		for id, sec := range last.RuleSeconds {
			all += sec
			if doneSet[id] {
				done += sec
			}
		}
		if all > 0 {
			frac = done / all
			left = time.Duration((all - done) * float64(time.Second))
		}
	}
	if frac > 1 {
		frac = 1
	}
	what := fmt.Sprintf("查了 %d%%", int(frac*100))
	switch {
	case left >= 90*time.Second:
		what += fmt.Sprintf("，大约还要 %d 分钟", int(left.Minutes()+0.5))
	case left > 0:
		what += "，快好了"
	}
	return what, frac
}

// scanningRow: while a round runs, a row 「正在查这台 Mac」 with how far it is and a bar; says whether it drew one.
func (s *Service) scanningRow(c *Card, last *core.Report) bool {
	if !s.IsScanning() {
		return false
	}
	what, frac := s.scanProgress(last)
	c.Line("正在查这台 Mac", what, frac)
	return true
}

// scanningSummary: the summary's sentence while a round runs ("" when none does).
func (s *Service) scanningSummary() string {
	if !s.IsScanning() {
		return ""
	}
	what, _ := s.scanProgress(s.Store.LastReport())
	return "正在查这台 Mac，" + what
}

// summaryNow: the summary, its sentence saying so while a round runs (the count stays the last round's).
func (s *Service) summaryNow(st State) O {
	o := s.summary(st)
	if t := s.scanningSummary(); t != "" {
		o["text"] = t
	}
	return o
}

// waitStarted waits, at most max, until the round scan_now started in a process of its own holds the round's lock:
// the agent reads the summary right after the click, and it should already say that a round runs.
func (s *Service) waitStarted(max time.Duration) {
	for end := time.Now().Add(max); !s.IsScanning() && time.Now().Before(end); {
		time.Sleep(50 * time.Millisecond)
	}
}
