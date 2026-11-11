package core

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Reading how this Mac runs, with public interfaces only: proc_info's rusage of this user's processes (as Activity
// Monitor's CPU time and 「内存」), sysctl (memory pressure, swap, memory size, the clock the CPU times count in),
// `notifyutil -g` for the thermal pressure level (OSThermalNotification.h's notify key), `ioreg` for the battery.

const (
	procCallPidRusage = 9 // PROC_INFO_CALL_PIDRUSAGE
	rusageInfoV0      = 0 // RUSAGE_INFO_V0
	// thermalKey is the notify key whose state is the thermal pressure level (OSThermalNotification.h).
	thermalKey = "com.apple.system.thermalpressurelevel"
)

// procUsage is one reading of a process: processor time (in the Mach clock's ticks) and memory footprint.
type procUsage struct {
	ticks     uint64
	footprint int64
}

// procUsageOf reads a process's rusage (rusage_info_v0: ri_user_time at 16, ri_system_time at 24, ri_phys_footprint
// at 72); only this user's processes can be read.
func procUsageOf(pid int32) (procUsage, bool) {
	buf := make([]byte, 96)
	r, e := procInfo(procCallPidRusage, int(pid), rusageInfoV0, 0, buf)
	if e != 0 || r < 0 {
		return procUsage{}, false
	}
	le := binary.LittleEndian
	return procUsage{ticks: le.Uint64(buf[16:24]) + le.Uint64(buf[24:32]), footprint: int64(le.Uint64(buf[72:80]))}, true
}

// ticksPerSecond is the Mach clock the CPU times count in (hw.tbfrequency: 24 MHz on Apple silicon).
func ticksPerSecond() (float64, bool) {
	f, err := unix.SysctlUint64("hw.tbfrequency")
	if err != nil || f == 0 {
		return 0, false
	}
	return float64(f), true
}

// readVitals: one look at this Mac. This user's processes are read twice vitalsLook apart (the round waits in
// between, and stops waiting when it is cancelled), the thermal level before and after.
func readVitals(ctx *Context) Vitals {
	v := Vitals{Self: int32(os.Getpid())}
	if t, ok := thermalNow(); ok {
		v.Thermal = append(v.Thermal, t)
	}
	me := uint32(os.Getuid())
	var mine []ProcInfo
	for _, p := range ProcSnapshot() {
		if p.UID == me {
			mine = append(mine, p)
		}
	}
	first := map[int32]procUsage{}
	t0 := time.Now()
	for _, p := range mine {
		if u, ok := procUsageOf(p.PID); ok {
			first[p.PID] = u
		}
	}
	for end := t0.Add(vitalsLook); time.Now().Before(end) && !ctx.IsCancelled(); {
		time.Sleep(100 * time.Millisecond)
	}
	if ctx.IsCancelled() {
		return v
	}
	t1 := time.Now()
	freq, ok := ticksPerSecond()
	if ok && len(first) > 0 {
		v.ProcsKnown = true
		total := 0.0
		for _, p := range mine {
			a, had := first[p.PID]
			b, ok := procUsageOf(p.PID)
			if !had || !ok || b.ticks < a.ticks {
				continue
			}
			u := ProcUse{PID: p.PID, PPID: p.PPID, Path: p.Path, Started: p.Started, Footprint: b.footprint,
				CPU: float64(b.ticks) / freq, Busy: float64(b.ticks-a.ticks) / freq / t1.Sub(t0).Seconds()}
			total += u.Busy
			v.Procs = append(v.Procs, u)
		}
		// The units checked against the machine: all of this user's processes together cannot use more cores than
		// there are. When they seem to, the clock is not what was assumed: nothing is said of them.
		if cores, err := unix.SysctlUint32("hw.logicalcpu"); err != nil || total > float64(cores)*1.25 {
			v.ProcsKnown, v.Procs = false, nil
		}
	}
	if p, err := unix.SysctlUint32("kern.memorystatus_vm_pressure_level"); err == nil {
		v.Pressure = int(p)
	}
	v.Swap, v.SwapKnown = swapUsed()
	if m, err := unix.SysctlUint64("hw.memsize"); err == nil {
		v.MemTotal = int64(m)
	}
	v.Battery, v.BatteryKnown = batteryNow()
	if t, ok := thermalNow(); ok && len(v.Thermal) > 0 {
		v.Thermal = append(v.Thermal, t)
	} else {
		v.Thermal = nil // both readings, or none
	}
	return v
}

// thermalNow is the thermal pressure level (0 nominal, 1 moderate, 2 heavy, 3 trapping, 4 sleeping): the state of its
// notify key, as `notifyutil -g` prints it ("<key> <level>").
func thermalNow() (int, bool) {
	r := Run("/usr/bin/notifyutil", []string{"-g", thermalKey}, RunOpts{Timeout: 5 * time.Second})
	if r.Status != 0 {
		return 0, false
	}
	return parseThermal(r.Stdout)
}

func parseThermal(out string) (int, bool) {
	f := strings.Fields(out)
	if len(f) != 2 || f[0] != thermalKey {
		return 0, false
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// batteryNow is the battery as IOKit tells it (`ioreg -r -c AppleSmartBattery`); nil when this Mac has none; ok false
// when it cannot be read.
func batteryNow() (*Battery, bool) {
	r := Run("/usr/sbin/ioreg", []string{"-r", "-c", "AppleSmartBattery"}, RunOpts{Timeout: 10 * time.Second})
	if r.Status != 0 {
		return nil, false
	}
	return parseBattery(r.Stdout)
}

// parseBattery reads ioreg's text: the battery's own properties, one per line ("CycleCount" = 75); not those nested in
// the dictionaries on one line. Capacity: NominalChargeCapacity (what Settings' 「最大容量」 is from), else
// AppleRawMaxCapacity.
func parseBattery(out string) (*Battery, bool) {
	if !strings.Contains(out, "AppleSmartBattery") {
		return nil, true
	}
	n := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		k, val, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok || len(k) < 3 || k[0] != '"' || k[len(k)-1] != '"' {
			continue
		}
		if x, err := strconv.Atoi(val); err == nil {
			n[k[1:len(k)-1]] = x
		}
	}
	if _, ok := n["DesignCapacity"]; !ok {
		return nil, false
	}
	b := &Battery{Cycles: n["CycleCount"], DesignCycles: n["DesignCycleCount9C"], DesignCapacity: n["DesignCapacity"],
		Capacity: n["NominalChargeCapacity"]}
	if b.Capacity == 0 {
		b.Capacity = n["AppleRawMaxCapacity"]
	}
	return b, true
}
