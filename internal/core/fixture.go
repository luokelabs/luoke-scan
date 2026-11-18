package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FixtureNow is the fake home's "now" when no clock is given.
var FixtureNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// Layout is a fake home (blackbox/README.md): home/, tmp/, tools/, data/, the fake system folders, fakes.json.
type Layout struct{ Root string }

func (l Layout) Home() string     { return filepath.Join(l.Root, "home") }
func (l Layout) Tmp() string      { return filepath.Join(l.Root, "tmp") }
func (l Layout) Projects() string { return filepath.Join(l.Root, "home/Projects") }
func (l Layout) Data() string     { return filepath.Join(l.Root, "data") }
func (l Layout) ToolDir() string  { return filepath.Join(l.Root, "tools") }
func (l Layout) TCC() string {
	return filepath.Join(l.Home(), "Library/Application Support/com.apple.TCC/TCC.db")
}

// BackgroundItems is the fake BackgroundItemsDir.
func (l Layout) BackgroundItems() string { return filepath.Join(l.Root, "backgroundtaskmanagement") }

// Tools are the fake scanners in tools/.
func (l Layout) Tools() Tools {
	d := l.ToolDir()
	return Tools{Clamscan: filepath.Join(d, "clamscan"), Freshclam: filepath.Join(d, "freshclam"), Sigtool: filepath.Join(d, "sigtool"),
		Yara: filepath.Join(d, "yara"), XProtect: filepath.Join(d, "XProtect.yara")}
}

// Context is the round's context for the fake home: only its own folders, its own TCC database and apps.
func (l Layout) Context(s *Store) Context {
	c := NewContext(l.Home())
	c.Tmp, c.ProjectRoots, c.Now, c.Store, c.Tools = l.Tmp(), []string{l.Projects()}, FixtureNow, s, l.Tools()
	c.TCCDatabases = []string{l.TCC()}
	c.AppDirs = []string{filepath.Join(l.Home(), "Applications")}
	c.SystemLibrary, c.Receipts = filepath.Join(l.Root, "SystemLibrary"), filepath.Join(l.Root, "receipts")
	c.BackgroundItems = l.BackgroundItems()
	return c
}

// Fakes are what a fake home's round takes for this Mac's own state (fakes.json; every key written).
type Fakes struct {
	Version   int           `json:"version"`
	Processes []FakeProcess `json:"processes"`
	// LaunchdPIDs nil: launchctl did not answer.
	LaunchdPIDs       *[]int32             `json:"launchdPIDs"`
	Commands          []FakeCommand        `json:"commands"`
	OtherCommands     FakeOutput           `json:"otherCommands"`
	BootTime          *time.Time           `json:"bootTime"`
	PendingUpdates    *int                 `json:"pendingUpdates"`
	XProtectUpdated   *time.Time           `json:"xprotectUpdated"`
	Signatures        []FakeSigned         `json:"signatures"`
	OtherSignature    string               `json:"otherSignature"`
	EventTaps         *[]FakeTap           `json:"eventTaps"`
	Snapshots         *[]time.Time         `json:"snapshots"`
	AppleSilicon      bool                 `json:"appleSilicon"`
	Running           []string             `json:"running"`
	CommandLines      *[]string            `json:"commandLines"`
	AttachedImages    []string             `json:"attachedImages"`
	Crontab           *string              `json:"crontab"`
	InstalledCommands []string             `json:"installedCommands"`
	Volume            *FakeVolume          `json:"volume"`
	StaleFiles        *[]FakeSpotlit       `json:"staleFiles"`
	Downloaded        *[]string            `json:"downloaded"`
	AppsAdded         map[string]time.Time `json:"appsAdded"`
	Codesign          map[string]string    `json:"codesign"`
	AppTrust          map[string]string    `json:"appTrust"`
	OnBattery         bool                 `json:"onBattery"`
	LowPower          bool                 `json:"lowPower"`
	MemoryPressure    int32                `json:"memoryPressure"`
	// Vitals: how this Mac runs, for the vitals rule (luoke-scan#126); nil: nothing to tell.
	Vitals *FakeVitals `json:"vitals"`
}

// FakeVitals is one look at how the fake Mac runs. CPU: processor seconds of a process (by pid; Processes says what
// it is) at the look's two readings, SampleSeconds apart; nil: not read. Footprint: its memory, bytes. Pressure: 1
// normal, 2 warning, 4 critical (0: not read). Swap: bytes in use (nil: not read). Battery: nil when there is none;
// BatteryUnknown: it could not be read. Thermal: the thermal pressure levels read (none: not read).
type FakeVitals struct {
	CPU            map[string][2]float64 `json:"cpu"`
	SampleSeconds  float64               `json:"sampleSeconds"`
	Footprint      map[string]int64      `json:"footprint"`
	MemTotal       int64                 `json:"memTotal"`
	Pressure       int                   `json:"pressure"`
	Swap           *int64                `json:"swap"`
	Battery        *FakeBattery          `json:"battery"`
	BatteryUnknown bool                  `json:"batteryUnknown"`
	Thermal        []int                 `json:"thermal"`
}

// FakeBattery is IOKit's battery: charge cycles so far and by design, capacity now and new (mAh).
type FakeBattery struct {
	Cycles         int `json:"cycles"`
	DesignCycles   int `json:"designCycles"`
	Capacity       int `json:"capacity"`
	DesignCapacity int `json:"designCapacity"`
}

type FakeProcess struct {
	PID       int32     `json:"pid"`
	PPID      int32     `json:"ppid"`
	UID       uint32    `json:"uid"`
	Path      string    `json:"path"`
	Started   time.Time `json:"started"`
	Arguments *[]string `json:"arguments"`
	// Environment: what it was started with (KERN_PROCARGS2 after argv); nil: not readable.
	Environment *[]string `json:"environment"`
	// Cwd: its working directory; nil: not readable.
	Cwd *string `json:"cwd"`
	// Libraries: the files it has mapped as code beside its program; nil: not readable.
	Libraries *[]FakeLibrary `json:"libraries"`
	Listening []FakeListen   `json:"listening"`
}

// FakeLibrary is a file a fake process has mapped as code; Deleted: removed since (no link left).
type FakeLibrary struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted"`
}

type FakeListen struct {
	Port    int    `json:"port"`
	Address string `json:"address"`
}

type FakeCommand struct {
	Tool   string   `json:"tool"`
	Args   []string `json:"args"`
	Status int      `json:"status"`
	Output string   `json:"output"`
}

type FakeOutput struct {
	Status int    `json:"status"`
	Output string `json:"output"`
}

type FakeSigned struct {
	PathContains string `json:"pathContains"`
	Signature    string `json:"signature"`
}

type FakeTap struct {
	Program    string `json:"program"`
	ListenOnly bool   `json:"listenOnly"`
	AllApps    bool   `json:"allApps"`
	PID        *int32 `json:"pid"`
}

type FakeVolume struct {
	Free  int64  `json:"free"`
	Total int64  `json:"total"`
	Swap  *int64 `json:"swap"`
}

type FakeSpotlit struct {
	Path    string     `json:"path"`
	Used    *time.Time `json:"used"`
	Changed *time.Time `json:"changed"`
}

// LoadFakes reads fakes.json at the root; ok false when there is none. The black-box tests always write one; the
// fake homes of the Swift version's unit tests (Fixture.build) are not supported here.
func (l Layout) LoadFakes() (*Fakes, bool, error) {
	data, err := os.ReadFile(filepath.Join(l.Root, "fakes.json"))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var f Fakes
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, false, err
	}
	return &f, true, nil
}

// Answer is a system command's answer: the first entry for the tool whose args are all among the arguments.
func (f *Fakes) Answer(tool string, args []string) (int, string) {
	for _, c := range f.Commands {
		if c.Tool != tool {
			continue
		}
		all := true
		for _, a := range c.Args {
			found := false
			for _, b := range args {
				if a == b {
					found = true
					break
				}
			}
			if !found {
				all = false
				break
			}
		}
		if all {
			return c.Status, c.Output
		}
	}
	return f.OtherCommands.Status, f.OtherCommands.Output
}

// Signature is what the persistence check sees of a program: missing when not there, else the first pattern that
// matches, else otherSignature.
func (f *Fakes) Signature(path string) Signature {
	if !Exists(SignatureSubject(path)) {
		return Signature{Kind: SigMissing}
	}
	for _, s := range f.Signatures {
		if strings.Contains(path, s.PathContains) {
			return ParseSignature(s.Signature)
		}
	}
	return ParseSignature(f.OtherSignature)
}
