package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() { Register("vitals", NewVitalsRule) }

// How this Mac runs (luoke-scan#126): why it is slow, hot or drains its battery, said when it is so. Rules decide, with
// public interfaces only (no private frameworks, no sudo, no temperatures or fans): a background program of this
// user's that keeps a processor core busy, memory pressure with swap in use and what takes the memory, the battery's
// wear (cycles and capacity from IOKit, as ioreg shows it), and the system's thermal pressure level. Conservative: one
// look (two readings a few seconds apart) at a time the user is away, and only what holds over time is told. Nothing
// is ended or changed: each finding comes with one thing to do and a button that opens Activity Monitor or Settings.

// Thresholds (conservative; luoke-scan#126 「要定的」 3: tuned from testers' feedback later).
const (
	// A program is stuck at full CPU when it used vitalsBusyNow of a core over the look, and vitalsBusyLong on average
	// over its life, or since the look kept from an earlier round, at least vitalsBusyFor ago (vitalsBaseline).
	vitalsBusyNow  = 0.9
	vitalsBusyLong = 0.8
	vitalsBusyFor  = 30 * time.Minute
	// vitalsMostStuck: the most stuck programs told in a round.
	vitalsMostStuck = 3
	// Memory is tight at pressure 4 (critical), or at 2 (warning) with vitalsSwap of swap in use.
	vitalsSwap = 1 << 30
	// vitalsMemNamed: a program (an app's processes together) that takes this much is named; the title names the
	// biggest when it takes vitalsMemTitle.
	vitalsMemNamed = 500 << 20
	vitalsMemTitle = 1 << 30
	// The battery is worn below vitalsHealth of its design capacity, or past its design cycle count (vitalsCycles when
	// the battery does not say).
	vitalsHealth = 0.8
	vitalsCycles = 1000
	// Thermal pressure is high from level 2 (heavy) at every reading; the busiest program is named from vitalsBusyNamed.
	vitalsHot       = 2
	vitalsBusyNamed = 0.5
	// vitalsLook: how long the two readings are apart on this Mac.
	vitalsLook = 3 * time.Second
)

// VitalsRule reports how this Mac runs. Read is what it reads of this Mac (or of a fake home's fakes).
type VitalsRule struct {
	Read func(ctx *Context) Vitals
}

// Vitals is one look at how this Mac runs.
type Vitals struct {
	// Procs are this user's processes with their use over the look; ProcsKnown false: the process table or their
	// use could not be read.
	Procs      []ProcUse
	ProcsKnown bool
	// Pressure: 1 normal, 2 warning, 4 critical (kern.memorystatus_vm_pressure_level); 0 not known.
	Pressure int
	// Swap: bytes of swap in use; SwapKnown false: not known.
	Swap      int64
	SwapKnown bool
	// MemTotal: bytes of memory (0 not known).
	MemTotal int64
	// Battery: nil when this Mac has none; BatteryKnown false: could not be read.
	Battery      *Battery
	BatteryKnown bool
	// Thermal: the thermal pressure levels read (0 nominal … 4 sleeping); none: not known.
	Thermal []int
	// Self: this program's process (its own and its children's use are the round's); 0 none.
	Self int32
}

// ProcUse is one process's use of the processor and memory.
type ProcUse struct {
	PID     int32
	PPID    int32
	Path    string
	Started time.Time
	// Busy: cores used over the look (1: one core all the time); CPU: seconds of processor time since it started.
	Busy, CPU float64
	// Footprint: bytes of memory it takes (as Activity Monitor's 「内存」).
	Footprint int64
}

// Battery is what IOKit tells of the battery.
type Battery struct {
	Cycles, DesignCycles     int
	Capacity, DesignCapacity int // mAh it holds now, and new
}

// NewVitalsRule makes the rule; for a fake home it answers from the fakes' vitals (none: nothing to tell).
func NewVitalsRule(l *Layout, f *Fakes) Rule {
	r := &VitalsRule{}
	if l != nil {
		r.Read = func(*Context) Vitals { return fakeVitals(f) }
	}
	return r
}

func (r *VitalsRule) ID() string      { return "vitals" }
func (r *VitalsRule) Emits() []string { return []string{"vitals"} }

func (r *VitalsRule) Run(ctx *Context) ([]Finding, error) {
	read := r.Read
	if read == nil {
		read = readVitals
	}
	v := read(ctx)
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}
	if !v.ProcsKnown && v.Pressure == 0 && !v.SwapKnown && !v.BatteryKnown && len(v.Thermal) == 0 {
		return nil, Skip("读不到这台 Mac 的运行状况")
	}
	var out []Finding
	engine := luokeEngine(ctx.Home)
	out = append(out, vitalsStuck(ctx, v, engine)...)
	out = append(out, vitalsMemory(v, engine)...)
	out = append(out, vitalsBattery(v)...)
	out = append(out, vitalsThermal(v, engine)...)
	var missing []string
	if !v.ProcsKnown {
		missing = append(missing, "各程序占的处理器和内存")
	}
	if v.Pressure == 0 {
		missing = append(missing, "内存压力")
	}
	if !v.BatteryKnown {
		missing = append(missing, "电池")
	}
	if len(v.Thermal) == 0 {
		missing = append(missing, "发热档位")
	}
	if len(missing) > 0 {
		out = append(out, Finding{Rule: "vitals.partial", Category: CatVitals, Severity: Low, Verdict: Info,
			Title: "运行状况有几项没读到：" + strings.Join(missing, "、"), Evidence: map[string]string{"missing": strings.Join(missing, "、")}})
	}
	return out, nil
}

// ProgramName is what a program is called for the user: the outermost app it is inside ("Google Chrome" for its
// helpers), else its file's name.
func ProgramName(path string) string {
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if strings.HasSuffix(p, ".app") && len(p) > len(".app") {
			return strings.TrimSuffix(p, ".app")
		}
	}
	return filepath.Base(path)
}

// ownTools are the programs a round runs itself: not reported as busy (the round is what keeps them busy).
var ownTools = map[string]bool{"luoke-scan": true, "luoke-scan-admin": true, "clamscan": true, "freshclam": true,
	"sigtool": true, "yara": true, "codesign": true, "mdfind": true, "mdls": true, "git": true, "du": true}

// vitalsMine: the processes worth judging: not this program, nor what it started, nor the tools a round runs.
func vitalsMine(v Vitals) []ProcUse {
	var out []ProcUse
	for _, p := range v.Procs {
		if (v.Self != 0 && (p.PID == v.Self || p.PPID == v.Self)) || p.Path == "" || ownTools[filepath.Base(p.Path)] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// cpuLook is an earlier round's look at a process, the one this round compares with: its processor seconds then, and
// when.
type cpuLook struct {
	CPU float64 `json:"cpu"`
	At  Time    `json:"at"`
}

// vitalsLooks: the look kept for each process this round saw (pid@start), no other.
func vitalsLooks(s *Store) Table[cpuLook] { return NewTable[cpuLook](s, "vitals", 1) }

// vitalsBaseline: the look to keep for a process after this round. One under vitalsBusyFor old stays as it was, so
// rounds closer together than that still add up to the time it takes to tell (three rounds a quarter of an hour apart
// compare the third with the first); one that old or older, or none, is replaced with this round's. A look from later
// than now (the clock went back) is replaced too.
func vitalsBaseline(before cpuLook, cpu float64, now time.Time) cpuLook {
	if since := now.Sub(before.At.Time); !before.At.IsZero() && since >= 0 && since < vitalsBusyFor {
		return before
	}
	return cpuLook{CPU: cpu, At: Time{now}}
}

// vitalsStuck: a background program that keeps a core busy (this user's; luoke-scan#126). Busy over this look, and
// busy on average for long: over its whole life, or since the look kept from an earlier round (vitalsBaseline). Not
// 螺壳's own engine (engine, as vitalsMemory): busy while it answers, and a name the user does not know.
func vitalsStuck(ctx *Context, v Vitals, engine func(string) bool) []Finding {
	if !v.ProcsKnown {
		return nil
	}
	now := ctx.Now
	var before map[string]cpuLook
	if ctx.Store != nil {
		before = vitalsLooks(ctx.Store).Load()
	}
	seen := map[string]cpuLook{}
	type stuck struct {
		p       ProcUse
		avg     float64
		over    time.Duration
		program string
	}
	var found []stuck
	for _, p := range vitalsMine(v) {
		key := fmt.Sprintf("%d@%d", p.PID, p.Started.Unix())
		seen[key] = vitalsBaseline(before[key], p.CPU, now)
		if p.Busy < vitalsBusyNow || (engine != nil && engine(p.Path)) {
			continue
		}
		life := now.Sub(p.Started)
		if life > 0 && life >= vitalsBusyFor && p.CPU/life.Seconds() >= vitalsBusyLong {
			found = append(found, stuck{p, p.CPU / life.Seconds(), life, ProgramName(p.Path)})
			continue
		}
		if b, ok := before[key]; ok {
			since := now.Sub(b.At.Time)
			if since >= vitalsBusyFor && (p.CPU-b.CPU)/since.Seconds() >= vitalsBusyLong {
				found = append(found, stuck{p, (p.CPU - b.CPU) / since.Seconds(), since, ProgramName(p.Path)})
			}
		}
	}
	if ctx.Store != nil {
		vitalsLooks(ctx.Store).Replace(seen)
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].p.Busy != found[j].p.Busy {
			return found[i].p.Busy > found[j].p.Busy
		}
		return found[i].p.PID < found[j].p.PID
	})
	var out []Finding
	for i, s := range found {
		if i == vitalsMostStuck {
			break
		}
		cores := "一个处理器核"
		if s.p.Busy >= 1.9 {
			cores = " " + strconv.Itoa(int(s.p.Busy+0.1)) + " 个处理器核" // 「一直占满 2 个处理器核」
		}
		out = append(out, Finding{Rule: "vitals.cpu", Category: CatVitals, Severity: Medium, Verdict: Confirm, Path: s.p.Path,
			Title: "「" + s.program + "」" + vitalsFor(s.over) + "一直占满" + cores + "，可能卡住了",
			Key:   s.p.Path,
			Evidence: map[string]string{"program": s.program, "busy_now": percent(s.p.Busy) + "（这会儿占一个核的多少）",
				"busy_average": percent(s.avg) + "（" + vitalsFor(s.over) + "平均）", "running_for": vitalsDuration(now.Sub(s.p.Started))}})
	}
	return out
}

// vitalsFor: 「这半小时」, 「这 3 小时」, 「这 2 天」 for how long something has held.
func vitalsFor(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "这半小时"
	case d < 48*time.Hour:
		return "这 " + strconv.Itoa(int(d.Hours())) + " 小时"
	}
	return "这 " + strconv.Itoa(int(d.Hours()/24)) + " 天"
}

// vitalsDuration: 「3 小时」, 「2 天」, 「40 分钟」.
func vitalsDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " 分钟"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " 小时"
	}
	return strconv.Itoa(int(d.Hours()/24)) + " 天"
}

func percent(x float64) string { return strconv.Itoa(int(x*100+0.5)) + "%" }

// coresUsed: 「占一个核的 60%」, or 「差不多占满 2 个核」 from one and a half.
func coresUsed(busy float64) string {
	if busy >= 1.5 {
		return "差不多占满 " + strconv.Itoa(int(busy+0.5)) + " 个核"
	}
	return "占一个核的 " + percent(busy)
}

// luokeEngine says whether a program is the model engine 螺壳's main body runs: luoke-core installs it under its env
// folder, <env>/engines/<版本>/oMLX.app (LUOKE_ENV_DIR, else ~/Library/Application Support/luoke-core). Told by where
// it is, not by its name: an oMLX the user installed elsewhere is theirs, and is named.
func luokeEngine(home string) func(path string) bool {
	var dirs []string
	for _, env := range []string{filepath.Join(home, "Library/Application Support/luoke-core"), os.Getenv("LUOKE_ENV_DIR")} {
		if filepath.IsAbs(env) {
			for _, d := range []string{Standardized(env), Canonical(env)} {
				dirs = append(dirs, strings.ToLower(filepath.Join(d, "engines"))+"/")
			}
		}
	}
	return func(path string) bool {
		p := strings.ToLower(Standardized(path))
		for _, d := range dirs {
			if strings.HasPrefix(p, d) || strings.HasPrefix(p, "/system/volumes/data"+d) {
				return true
			}
		}
		return false
	}
}

// vitalsMemory: memory is tight (pressure, and swap in use), and what takes it: each app's processes together. Not
// 螺壳's own engine (engine): the user does not know its name and would take it for another app; how to say what 螺壳
// itself takes is decided later. The pressure is told all the same.
func vitalsMemory(v Vitals, engine func(string) bool) []Finding {
	if v.Pressure < 2 || (v.Pressure < 4 && (!v.SwapKnown || v.Swap < vitalsSwap)) {
		return nil
	}
	byProgram := map[string]int64{}
	for _, p := range vitalsMine(v) {
		if engine != nil && engine(p.Path) {
			continue
		}
		byProgram[ProgramName(p.Path)] += p.Footprint
	}
	var names []string
	for n, b := range byProgram {
		if b >= vitalsMemNamed {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if byProgram[names[i]] != byProgram[names[j]] {
			return byProgram[names[i]] > byProgram[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) > 3 {
		names = names[:3]
	}
	title := "内存不够用了"
	ev := map[string]string{"pressure": map[int]string{2: "警告", 4: "严重"}[v.Pressure]}
	if ev["pressure"] == "" {
		ev["pressure"] = "偏高"
	}
	if v.SwapKnown && v.Swap > 0 {
		ev["swap"] = FormatBytes(v.Swap) + "（内存不够时借用的硬盘空间）"
	}
	if v.MemTotal > 0 {
		ev["memory"] = strconv.Itoa(int(float64(v.MemTotal)/(1<<30)+0.5)) + " GB（这台 Mac 的内存）" // as About This Mac says it
	}
	if len(names) > 0 {
		var top []string
		for _, n := range names {
			top = append(top, n+" "+FormatBytes(byProgram[n]))
		}
		ev["top"] = strings.Join(top, "、")
		if byProgram[names[0]] >= vitalsMemTitle {
			title += "，「" + names[0] + "」占了 " + FormatBytes(byProgram[names[0]])
		}
	}
	return []Finding{{Rule: "vitals.memory", Category: CatVitals, Severity: Medium, Verdict: Confirm, Title: title, Evidence: ev}}
}

// vitalsBattery: the battery is worn: it holds clearly less than new, or it is past its design cycle count.
func vitalsBattery(v Vitals) []Finding {
	b := v.Battery
	if b == nil {
		return nil
	}
	design := b.DesignCycles
	if design <= 0 {
		design = vitalsCycles
	}
	ev := map[string]string{"cycles": strconv.Itoa(b.Cycles) + " 次", "design_cycles": strconv.Itoa(design) + " 次"}
	worn := b.DesignCapacity > 0 && b.Capacity > 0 && float64(b.Capacity)/float64(b.DesignCapacity) < vitalsHealth
	if b.DesignCapacity > 0 && b.Capacity > 0 {
		ev["capacity"] = percent(float64(b.Capacity)/float64(b.DesignCapacity)) + "（和新电池比）"
	}
	old := b.Cycles >= design
	var title string
	switch {
	case worn:
		title = "电池老化了：充满也只有新电池的 " + percent(float64(b.Capacity)/float64(b.DesignCapacity))
	case old:
		title = "电池已经充放电 " + strconv.Itoa(b.Cycles) + " 次，过了设计的 " + strconv.Itoa(design) + " 次"
	default:
		return nil
	}
	return []Finding{{Rule: "vitals.battery", Category: CatVitals, Severity: Medium, Verdict: Confirm, Title: title, Evidence: ev}}
}

// vitalsThermal: the system's thermal pressure stayed high over the look (it slows the Mac down to cool it), and
// the busiest program then: not 螺壳's own engine (engine, as vitalsMemory); the heat is told all the same.
func vitalsThermal(v Vitals, engine func(string) bool) []Finding {
	if len(v.Thermal) == 0 {
		return nil
	}
	for _, t := range v.Thermal {
		if t < vitalsHot {
			return nil
		}
	}
	level := v.Thermal[len(v.Thermal)-1]
	ev := map[string]string{"thermal": map[int]string{2: "重", 3: "很重", 4: "最重"}[min(level, 4)] + "（系统的发热档位，共五档）"}
	title := "这台 Mac 太热了，系统正在给它降速"
	var busiest *ProcUse
	for _, p := range vitalsMine(v) {
		if engine != nil && engine(p.Path) {
			continue
		}
		if p.Busy >= vitalsBusyNamed && (busiest == nil || p.Busy > busiest.Busy) {
			q := p
			busiest = &q
		}
	}
	if busiest != nil {
		ev["busiest"] = ProgramName(busiest.Path) + "（" + coresUsed(busiest.Busy) + "）"
		title += "，最忙的是「" + ProgramName(busiest.Path) + "」"
	}
	return []Finding{{Rule: "vitals.thermal", Category: CatVitals, Severity: Medium, Verdict: Confirm, Title: title, Evidence: ev}}
}

// fakeVitals: a fake home's vitals (fakes.json "vitals"); none: nothing to tell, as a Mac that runs well.
func fakeVitals(f *Fakes) Vitals {
	v := Vitals{Pressure: 1, SwapKnown: true, BatteryKnown: true, ProcsKnown: true, Thermal: []int{0, 0}}
	if f == nil || f.Vitals == nil {
		return v
	}
	fv := f.Vitals
	v.Pressure, v.MemTotal, v.Thermal = fv.Pressure, fv.MemTotal, fv.Thermal
	v.SwapKnown = fv.Swap != nil
	if fv.Swap != nil {
		v.Swap = *fv.Swap
	}
	v.BatteryKnown = !fv.BatteryUnknown
	if fv.Battery != nil {
		v.Battery = &Battery{Cycles: fv.Battery.Cycles, DesignCycles: fv.Battery.DesignCycles, Capacity: fv.Battery.Capacity,
			DesignCapacity: fv.Battery.DesignCapacity}
	}
	v.ProcsKnown = fv.CPU != nil
	me := uint32(os.Getuid())
	for _, p := range f.Processes {
		if p.UID != me {
			continue
		}
		u := ProcUse{PID: p.PID, PPID: p.PPID, Path: p.Path, Started: p.Started}
		if c, ok := fv.CPU[strconv.Itoa(int(p.PID))]; ok && fv.SampleSeconds > 0 {
			u.CPU = c[1]
			u.Busy = (c[1] - c[0]) / fv.SampleSeconds
		}
		u.Footprint = fv.Footprint[strconv.Itoa(int(p.PID))]
		v.Procs = append(v.Procs, u)
	}
	return v
}
