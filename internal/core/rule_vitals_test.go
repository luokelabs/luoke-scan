package core

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func vitalsRun(t *testing.T, s *Store, now time.Time, v Vitals) []Finding {
	t.Helper()
	ctx := NewContext(t.TempDir())
	ctx.Now, ctx.Store = now, s
	found, err := (&VitalsRule{Read: func(*Context) Vitals { return v }}).Run(&ctx)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func vitalsRules(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func vitalsHealthy() Vitals {
	return Vitals{ProcsKnown: true, Pressure: 1, SwapKnown: true, BatteryKnown: true, Thermal: []int{0, 0}, MemTotal: 16 << 30}
}

func TestVitalsStuckProgram(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	v := vitalsHealthy()
	v.Self = 900
	v.Procs = []ProcUse{
		{PID: 1, Path: "/Applications/Sync.app/Contents/MacOS/Sync", Started: now.Add(-3 * time.Hour), Busy: 0.99, CPU: 0.95 * 3 * 3600},
		{PID: 2, Path: "/usr/local/bin/young", Started: now.Add(-10 * time.Minute), Busy: 1, CPU: 590},
		{PID: 3, Path: "/Applications/Browser.app/Contents/MacOS/Browser", Started: now.Add(-120 * time.Hour), Busy: 1, CPU: 0.2 * 120 * 3600},
		{PID: 4, PPID: 900, Path: "/bin/sh", Started: now.Add(-5 * time.Hour), Busy: 1, CPU: 5 * 3600},                           // started by this program
		{PID: 900, Path: "/x/luoke-scan", Started: now.Add(-5 * time.Hour), Busy: 1, CPU: 5 * 3600},                              // this program
		{PID: 5, Path: "/x/clamscan", Started: now.Add(-5 * time.Hour), Busy: 1, CPU: 5 * 3600},                                  // a tool of the round's
		{PID: 6, Path: "/Applications/Lazy.app/Contents/MacOS/Lazy", Started: now.Add(-5 * time.Hour), Busy: 0.5, CPU: 5 * 3600}, // not now
	}
	s, _ := OpenStore(t.TempDir())
	found := vitalsRun(t, s, now, v)
	if len(found) != 1 || found[0].Rule != "vitals.cpu" || found[0].Evidence["program"] != "Sync" ||
		found[0].Title != "「Sync」这 3 小时一直占满一个处理器核，可能卡住了" || found[0].Verdict != Confirm {
		t.Fatalf("%+v", found)
	}

	// The browser, busy since the last round's look an hour ago: told then.
	v.Procs = []ProcUse{{PID: 3, Path: "/Applications/Browser.app/Contents/MacOS/Browser", Started: now.Add(-120 * time.Hour), Busy: 1,
		CPU: 0.2*120*3600 + 0.97*3600}}
	found = vitalsRun(t, s, now.Add(time.Hour), v)
	if len(found) != 1 || found[0].Evidence["program"] != "Browser" || !strings.Contains(found[0].Title, "这 1 小时") {
		t.Fatalf("since the last look: %+v", found)
	}
	// Not after ten minutes only.
	v.Procs[0].CPU += 0.99 * 600
	if found = vitalsRun(t, s, now.Add(time.Hour+10*time.Minute), v); len(found) != 0 {
		t.Fatalf("ten minutes since the last look: %+v", found)
	}
}

// Rounds closer together than vitalsBusyFor: the look kept from the first stays until it is that old, so three rounds
// a quarter of an hour apart tell a program busy all along whose life's average is low, at the third.
func TestVitalsStuckOverCloseRounds(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-120 * time.Hour)
	life := 0.1 * 120 * 3600 // ten percent over five days
	v := vitalsHealthy()
	s, _ := OpenStore(t.TempDir())
	for i, want := range []int{0, 0, 1} {
		v.Procs = []ProcUse{{PID: 7, Path: "/Applications/Indexer.app/Contents/MacOS/Indexer", Started: started, Busy: 1,
			CPU: life + 0.97*float64(i)*15*60}}
		found := vitalsRun(t, s, now.Add(time.Duration(i)*15*time.Minute), v)
		if len(found) != want {
			t.Fatalf("round %d: %+v", i+1, found)
		}
		if want == 1 && (found[0].Rule != "vitals.cpu" || found[0].Evidence["program"] != "Indexer" ||
			found[0].Title != "「Indexer」这半小时一直占满一个处理器核，可能卡住了" ||
			!strings.HasPrefix(found[0].Evidence["busy_average"], "97%")) {
			t.Fatalf("round %d: %+v", i+1, found)
		}
	}
}

// The look kept for a process is not replaced while under vitalsBusyFor old, and is once it is that old; one from
// later than now (the clock went back) is replaced; a process not seen again is dropped.
func TestVitalsBaselineKeptUntilOldEnough(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-time.Hour)
	key := fmt.Sprintf("8@%d", started.Unix())
	v := vitalsHealthy()
	s, _ := OpenStore(t.TempDir())
	round := func(at time.Duration, cpu float64, others ...ProcUse) map[string]cpuLook {
		v.Procs = append([]ProcUse{{PID: 8, Path: "/Applications/Calm.app/Contents/MacOS/Calm", Started: started, Busy: 0.1,
			CPU: cpu}}, others...)
		vitalsRun(t, s, now.Add(at), v)
		return vitalsLooks(s).Load()
	}
	other := ProcUse{PID: 9, Path: "/Applications/Other.app/Contents/MacOS/Other", Started: started, Busy: 0.1, CPU: 5}
	for _, c := range []struct {
		at       time.Duration
		cpu      float64
		others   []ProcUse
		wantCPU  float64
		wantAt   time.Duration
		wantRows int
	}{
		{0, 100, []ProcUse{other}, 100, 0, 2},
		{20 * time.Minute, 200, nil, 100, 0, 1}, // kept; the other process, gone, is dropped
		{30 * time.Minute, 300, nil, 300, 30 * time.Minute, 1},
		{50 * time.Minute, 400, nil, 300, 30 * time.Minute, 1},
		{85 * time.Minute, 500, nil, 500, 85 * time.Minute, 1},
		{60 * time.Minute, 600, nil, 600, 60 * time.Minute, 1}, // the clock went back
	} {
		rows := round(c.at, c.cpu, c.others...)
		got := rows[key]
		if len(rows) != c.wantRows || got.CPU != c.wantCPU || !got.At.Time.Equal(now.Add(c.wantAt)) {
			t.Fatalf("at %v: %d rows, %+v; want %d rows, cpu %v at %v", c.at, len(rows), got, c.wantRows, c.wantCPU, c.wantAt)
		}
	}
}

func TestVitalsMemory(t *testing.T) {
	now := time.Now()
	v := vitalsHealthy()
	v.Procs = []ProcUse{
		{PID: 1, Path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", Footprint: 1 << 30},
		{PID: 2, Path: "/Applications/Google Chrome.app/Contents/Frameworks/X.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper", Footprint: 5 << 30},
		{PID: 3, Path: "/Applications/Slack.app/Contents/MacOS/Slack", Footprint: 600 << 20},
		{PID: 4, Path: "/usr/local/bin/tiny", Footprint: 20 << 20},
	}
	for _, c := range []struct {
		pressure int
		swap     int64
		want     bool
	}{{1, 8 << 30, false}, {2, 200 << 20, false}, {2, 1 << 30, true}, {4, 0, true}} {
		v.Pressure, v.Swap = c.pressure, c.swap
		found := vitalsRun(t, nil, now, v)
		if (len(found) == 1) != c.want {
			t.Fatalf("pressure %d swap %d: %+v", c.pressure, c.swap, found)
		}
		if c.want && (found[0].Title != "内存不够用了，「Google Chrome」占了 6.44 GB" || found[0].Evidence["top"] != "Google Chrome 6.44 GB、Slack 629.1 MB") {
			t.Fatalf("%+v", found[0])
		}
	}
}

func TestVitalsBatteryAndHeat(t *testing.T) {
	now := time.Now()
	v := vitalsHealthy()
	v.Battery = &Battery{Cycles: 300, DesignCycles: 1000, Capacity: 4750, DesignCapacity: 5000}
	if found := vitalsRun(t, nil, now, v); len(found) != 0 {
		t.Fatalf("a good battery: %+v", found)
	}
	v.Battery.Capacity = 3600
	if found := vitalsRun(t, nil, now, v); len(found) != 1 || found[0].Title != "电池老化了：充满也只有新电池的 72%" {
		t.Fatalf("worn: %+v", found)
	}
	v.Battery = &Battery{Cycles: 1000, Capacity: 4500, DesignCapacity: 5000} // no design cycle count: 1000
	if found := vitalsRun(t, nil, now, v); len(found) != 1 || found[0].Title != "电池已经充放电 1000 次，过了设计的 1000 次" {
		t.Fatalf("cycles: %+v", found)
	}
	v.Battery = nil
	v.Procs = []ProcUse{{PID: 7, Path: "/Applications/Render.app/Contents/MacOS/Render", Busy: 2.4}}
	v.Thermal = []int{2, 1}
	if found := vitalsRun(t, nil, now, v); len(found) != 0 {
		t.Fatalf("hot once: %+v", found)
	}
	v.Thermal = []int{2, 3}
	if found := vitalsRun(t, nil, now, v); len(found) != 1 || found[0].Title != "这台 Mac 太热了，系统正在给它降速，最忙的是「Render」" {
		t.Fatalf("hot: %+v", found)
	}
}

func TestVitalsNotRead(t *testing.T) {
	ctx := NewContext(t.TempDir())
	_, err := (&VitalsRule{Read: func(*Context) Vitals { return Vitals{} }}).Run(&ctx)
	if se, ok := err.(*SkippedError); !ok || se.Reason != "读不到这台 Mac 的运行状况" {
		t.Fatalf("nothing read: %v", err)
	}
	v := Vitals{Pressure: 1, SwapKnown: true}
	found := vitalsRun(t, nil, time.Now(), v)
	if got := vitalsRules(found); len(got) != 1 || got[0] != "vitals.partial" ||
		found[0].Evidence["missing"] != "各程序占的处理器和内存、电池、发热档位" || found[0].Verdict != Info {
		t.Fatalf("partly: %+v", found)
	}
}

func TestProgramName(t *testing.T) {
	for path, want := range map[string]string{
		"/Applications/Google Chrome.app/Contents/Frameworks/G.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper": "Google Chrome",
		"/opt/homebrew/bin/node": "node", "/Applications/.app/x": "x",
	} {
		if got := ProgramName(path); got != want {
			t.Errorf("%s: %q", path, got)
		}
	}
}

func TestParseBatteryAndThermal(t *testing.T) {
	out := `+-o AppleSmartBattery  <class AppleSmartBattery, id 0x100000123, registered, matched, active, busy 0 (0 ms), retain 7>
    {
      "PostChargeWaitSeconds" = 120
      "BatteryData" = {"CycleCount"=9,"DesignCapacity"=1}
      "CycleCount" = 812
      "DesignCapacity" = 4563
      "AppleRawMaxCapacity" = 3901
      "NominalChargeCapacity" = 3950
      "DesignCycleCount9C" = 1000
      "InstantAmperage" = 18446744073709551000
    }
`
	b, ok := parseBattery(out)
	if !ok || b == nil || *b != (Battery{Cycles: 812, DesignCycles: 1000, Capacity: 3950, DesignCapacity: 4563}) {
		t.Fatalf("%+v %v", b, ok)
	}
	if b, ok := parseBattery(""); !ok || b != nil {
		t.Errorf("no battery: %+v %v", b, ok)
	}
	if _, ok := parseBattery("+-o AppleSmartBattery <class AppleSmartBattery>\n  {\n  }\n"); ok {
		t.Error("a battery without its capacities is not known")
	}
	if n, ok := parseThermal("com.apple.system.thermalpressurelevel 2\n"); !ok || n != 2 {
		t.Errorf("thermal: %d %v", n, ok)
	}
	for _, bad := range []string{"", "other.key 2", "com.apple.system.thermalpressurelevel x"} {
		if _, ok := parseThermal(bad); ok {
			t.Errorf("%q read", bad)
		}
	}
}

// The CPU times proc_info gives count in the Mach clock's ticks: read for this test's own process, a fifth of a
// second of work comes out near a fifth of a second (not 41 times more or less).
func TestOwnCPUTimeInSeconds(t *testing.T) {
	freq, ok := ticksPerSecond()
	if !ok {
		t.Skip("no hw.tbfrequency")
	}
	pid := int32(os.Getpid())
	a, ok := procUsageOf(pid)
	if !ok {
		t.Fatal("own rusage")
	}
	x := 0
	for end := time.Now().Add(200 * time.Millisecond); time.Now().Before(end); {
		x++
	}
	b, _ := procUsageOf(pid)
	used := float64(b.ticks-a.ticks) / freq
	if used < 0.1 || used > 1.5 {
		t.Fatalf("200 ms of work read as %.3f s (%d)", used, x)
	}
	if b.footprint < 1<<20 || b.footprint > 8<<30 {
		t.Fatalf("own footprint %d", b.footprint)
	}
}
