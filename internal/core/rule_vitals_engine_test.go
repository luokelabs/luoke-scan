package core

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The model engine 螺壳's main body runs takes the most memory: memory is still tight, the card names the next one, and
// never the engine (by where it is: luoke-core's env folder, or LUOKE_ENV_DIR). An oMLX the user installed is named.
func TestMemoryLeavesOutLuokesEngine(t *testing.T) {
	home := t.TempDir()
	lab := t.TempDir()
	t.Setenv("LUOKE_ENV_DIR", lab)
	slack := filepath.Join(home, "Applications/Slack.app/Contents/MacOS/Slack")
	for _, engine := range []string{
		filepath.Join(home, "Library/Application Support/luoke-core/engines/omlx-0.7.3/oMLX.app/Contents/MacOS/oMLX"),
		filepath.Join(lab, "engines/omlx-0.7.3/oMLX.app/Contents/MacOS/oMLX"),
	} {
		v := Vitals{Pressure: 2, Swap: 3 << 30, SwapKnown: true, ProcsKnown: true, Procs: []ProcUse{
			{PID: 10, Path: engine, Footprint: 6800 << 20},
			{PID: 11, PPID: 10, Path: filepath.Join(filepath.Dir(filepath.Dir(engine)), "Resources/python/bin/python3"), Footprint: 900 << 20},
			{PID: 12, Path: slack, Footprint: 1200 << 20},
		}}
		fs := vitalsMemory(v, luokeEngine(home))
		if len(fs) != 1 {
			t.Fatalf("%s: %d findings", engine, len(fs))
		}
		f := fs[0]
		all := f.Title + " " + f.Evidence["top"]
		if strings.Contains(all, "oMLX") || strings.Contains(all, "python3") {
			t.Errorf("%s: names the engine: %q", engine, all)
		}
		if !strings.Contains(f.Title, "「Slack」占了") {
			t.Errorf("%s: title %q", engine, f.Title)
		}
	}
	mine := filepath.Join(home, "Applications/oMLX.app/Contents/MacOS/oMLX")
	v := Vitals{Pressure: 2, Swap: 3 << 30, SwapKnown: true, ProcsKnown: true, Procs: []ProcUse{
		{PID: 20, Path: mine, Footprint: 5 << 30}, {PID: 21, Path: slack, Footprint: 1200 << 20}}}
	if fs := vitalsMemory(v, luokeEngine(home)); len(fs) != 1 || !strings.Contains(fs[0].Title, "「oMLX」占了") {
		t.Errorf("the user's own oMLX: %+v", fs)
	}
}

// The engine keeps cores busy for long, and is the busiest program while the Mac is hot: neither card names it (by where
// it is, as the memory card); the heat is told all the same, with the next busiest program. An oMLX the user installed
// is named.
func TestBusyLeavesOutLuokesEngine(t *testing.T) {
	home := t.TempDir()
	now := time.Now()
	engine := filepath.Join(home, "Library/Application Support/luoke-core/engines/omlx-0.7.3/oMLX.app/Contents/MacOS/oMLX")
	mine := filepath.Join(home, "Applications/oMLX.app/Contents/MacOS/oMLX")
	slack := filepath.Join(home, "Applications/Slack.app/Contents/MacOS/Slack")
	long := now.Add(-3 * time.Hour)
	busy := func(pid int32, path string, cores float64) ProcUse {
		return ProcUse{PID: pid, Path: path, Busy: cores, CPU: cores * now.Sub(long).Seconds(), Started: long}
	}
	ctx := &Context{Now: now}
	v := Vitals{ProcsKnown: true, Procs: []ProcUse{busy(10, engine, 3), busy(11, mine, 1)}}
	fs := vitalsStuck(ctx, v, luokeEngine(home))
	if len(fs) != 1 || fs[0].Path != mine || !strings.Contains(fs[0].Title, "「oMLX」") {
		t.Errorf("stuck: %+v", fs)
	}
	for _, f := range fs {
		if f.Path == engine {
			t.Errorf("stuck names the engine: %q", f.Title)
		}
	}
	hot := Vitals{Thermal: []int{2, 3}, ProcsKnown: true, Procs: []ProcUse{busy(10, engine, 3), busy(12, slack, 0.8)}}
	fs = vitalsThermal(hot, luokeEngine(home))
	if len(fs) != 1 || !strings.HasSuffix(fs[0].Title, "最忙的是「Slack」") || strings.Contains(fs[0].Evidence["busiest"], "oMLX") {
		t.Errorf("hot: %+v", fs)
	}
	hot.Procs = []ProcUse{busy(10, engine, 3)}
	if fs = vitalsThermal(hot, luokeEngine(home)); len(fs) != 1 || strings.Contains(fs[0].Title, "最忙") {
		t.Errorf("hot, only the engine busy: %+v", fs)
	}
	hot.Procs = []ProcUse{busy(11, mine, 2)}
	if fs = vitalsThermal(hot, luokeEngine(home)); len(fs) != 1 || !strings.Contains(fs[0].Title, "最忙的是「oMLX」") {
		t.Errorf("hot, the user's own oMLX: %+v", fs)
	}
}
