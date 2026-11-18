// Package service is what the agent and luoke-core's jobs talk to: rounds with their automatic cleaning, the outbox,
// cards, plans and putting back, the model's tasks.
package service

import (
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// ToolVersion is this build's version; it must be the accessory manifest's (packaging/luoke-accessory.json).
const ToolVersion = "0.3.42"

// ModelLink is luoke-core's model for the generate tasks.
type ModelLink struct {
	Socket, Accessory      string
	Prompts                fs.FS // the prompt files (Prompts)
	AskNew                 bool
	Budget, RequestTimeout time.Duration
	Caps                   map[string]int
	KeepFor                time.Duration
}

// Config is how a service runs: where it looks, which rules, its clock, and what it asks of this Mac (tests and fake
// homes replace those).
type Config struct {
	Context   core.Context
	Rules     []core.Rule
	Accessory string
	Version   string
	Clock     func() time.Time
	// Trash moves to the Trash and says where it went ("" not known).
	Trash        func(path string) (string, error)
	TrashFolders []string // nil: the home's .Trash
	Remove       func(path string) error
	// Command runs a system command (open, launchctl) and returns its exit status.
	Command        func(tool string, args []string) int
	FullDiskAccess func() *bool
	Model          *ModelLink
	Remember       func([]MemoryRecord)
	StartScan      func() bool
	Running        func() map[string]bool
	CommandLines   func() ([]string, bool)
	AttachedImages func() map[string]bool
	Installed      func(command, home string) bool
	Added          func(path string) (time.Time, bool)
	// Elevate runs the password step; wait is the most it may take, dialog included.
	Elevate func(args []string, prompt string, wait time.Duration) Elevated
	// Front asks 螺壳's main body to bring Finder or Settings forward ("reveal" {"path"}, "open_settings" {"pane"});
	// false: it did not (no main body, not right after a click), open it with Command instead.
	Front func(method string, params map[string]any) bool
	// Clone turns copy into a clone of original (checking the contents again).
	Clone func(original, copy string) error
	// QuickWaits is why the quick look between rounds waits now (on battery, Low Power Mode, memory tight); "" it can go.
	QuickWaits func() string
	// Volume is the free and total bytes of the disk home is on, read when the 「状态」 page is drawn; ok false when
	// not known. A fake home answers its fakes' volume, so the page is the same each time.
	Volume func(home string) (free, total int64, ok bool)
	// AppName is an installed app's own name for its bundle id ("" when it is not on this Mac): the 「状态」 page
	// names a folder kept under a bundle id after its app.
	AppName func(bundleID string) string
}

// Elevated is how the password step went.
type Elevated struct {
	Kind string // "done", "cancelled", "failed"
	Why  string
	// Uncertain: failed, but the step may have done part of it, and may still be running (the main app stopped waiting
	// after its time limit; the root step it started does not stop with it).
	Uncertain bool
	Output    string // done: the step's answer, one JSON line per target (AdminLine)
}

// MemoryRecord is one thing written into the user's memory.
type MemoryRecord struct {
	Topic, Speaker, Kind, Text, Ref string
	HappenedAt                      time.Time
	Data                            map[string]any
}

// NewConfig is the default settings for a context.
func NewConfig(ctx core.Context) Config {
	return Config{Context: ctx, Rules: core.DefaultRules(), Accessory: "luoke-scan", Version: ToolVersion, Clock: time.Now,
		Trash:  trashForReal,
		Remove: core.RemoveNoFollow,
		Clone:  core.ReplaceWithClone,
		Command: func(tool string, args []string) int {
			return core.Run(tool, args, core.RunOpts{Timeout: 120 * time.Second}).Status
		},
		Running:        func() map[string]bool { return map[string]bool{} },
		CommandLines:   func() ([]string, bool) { return nil, false },
		AttachedImages: func() map[string]bool { return map[string]bool{} },
		Installed:      func(string, string) bool { return false },
		Added:          func(string) (time.Time, bool) { return time.Time{}, false },
		Elevate: func([]string, string, time.Duration) Elevated {
			return Elevated{Kind: "failed", Why: "这一版的要密码那一步还没接上螺壳本体"}
		},
		Front:      func(string, map[string]any) bool { return false },
		QuickWaits: QuickLookWaitsNow,
		Volume:     core.VolumeCapacity,
		AppName:    installedAppName,
	}
}

// trashForReal moves to the user's Trash with Finder's own naming (osascript is not used: no dialog).
func trashForReal(path string) (string, error) {
	h, _ := os.UserHomeDir()
	return trashInto(filepath.Join(h, ".Trash"), path)
}

// trashInto moves path into the folder trash under its own name, else "name 2.ext", "name 3.ext"… as Finder names
// them. Each try is one exclusive rename (RENAME_EXCL): never over what is there, even what came after the name was
// picked or a link pointing nowhere; a name taken is tried again with the next.
func trashInto(trash, path string) (string, error) {
	name := filepath.Base(path)
	dest := filepath.Join(trash, name)
	for n := 1; n <= 1000; n++ {
		if n > 1 {
			dest = filepath.Join(trash, numbered(name, n))
		}
		err := core.RenameatxNp(core.AtFDCWD, path, core.AtFDCWD, dest, core.RenameExcl)
		if err == nil {
			return dest, nil
		}
		if err != syscall.EEXIST {
			return "", &os.LinkError{Op: "rename", Old: path, New: dest, Err: err}
		}
	}
	return "", &os.LinkError{Op: "rename", Old: path, New: dest, Err: syscall.EEXIST}
}

// FixtureConfig is the settings for a fake home: its own folders and the fakes' answers for this Mac's state; nothing
// of the real Mac changes (its own Trash, commands written down instead of run).
func FixtureConfig(l core.Layout, f *core.Fakes) Config {
	cfg := NewConfig(l.Context(nil))
	cfg.Rules = core.FixtureRules(l, f)
	cfg.AppName = func(id string) string { // 假家目录里装着的应用，不问这台 Mac 的 LaunchServices
		if p := core.FindAppIn(id, cfg.Context.AppDirs); p != "" {
			return core.NameWithoutExtension(p)
		}
		return ""
	}
	cfg.Volume = func(string) (int64, int64, bool) {
		if f == nil || f.Volume == nil {
			return 0, 0, false
		}
		return f.Volume.Free, f.Volume.Total, true
	}
	if PermissionOff(fdaPermission) {
		no := false
		cfg.Context.FullDiskAccess, cfg.Context.AccessOff = &no, true
		cfg.FullDiskAccess = func() *bool { return &no }
	}
	trash := filepath.Join(l.Root, "Trash")
	cfg.Trash = func(p string) (string, error) {
		os.MkdirAll(trash, 0o755)
		to := filepath.Join(trash, randomHex8()+"-"+filepath.Base(p))
		return to, os.Rename(p, to)
	}
	cfg.TrashFolders = []string{trash}
	log := filepath.Join(l.Root, "commands.log")
	cfg.Command = func(tool string, args []string) int {
		if args == nil {
			args = []string{}
		}
		line := Serialize(O{"tool": tool, "args": args}) + "\n"
		if fh, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			fh.WriteString(line)
			fh.Close()
		}
		return 0
	}
	cfg.Elevate = func([]string, string, time.Duration) Elevated {
		return Elevated{Kind: "failed", Why: "假目录不用密码删除"}
	}
	if f != nil {
		running := map[string]bool{}
		for _, p := range f.Running {
			running[filepath.Base(p)] = true
		}
		cfg.Running = func() map[string]bool { return running }
		cfg.CommandLines = func() ([]string, bool) {
			if f.CommandLines == nil {
				return nil, false
			}
			return *f.CommandLines, true
		}
		attached := map[string]bool{}
		for _, p := range f.AttachedImages {
			attached[p] = true
		}
		cfg.AttachedImages = func() map[string]bool { return attached }
		installed := map[string]bool{}
		for _, c := range f.InstalledCommands {
			installed[c] = true
		}
		cfg.Installed = func(c, _ string) bool { return installed[c] }
		// A fake home's power and memory are its fakes', not this Mac's.
		waits := QuickLookWaits(f.OnBattery, f.LowPower, f.MemoryPressure)
		cfg.QuickWaits = func() string { return waits }
	}
	cfg.Added = addedDate
	return cfg
}

// addedDate is when a file came into its folder (Finder's date added), else when it was made.
func addedDate(path string) (time.Time, bool) {
	return core.DateAdded(path)
}

func randomHex8() string {
	b := make([]byte, 4)
	rand.Read(b)
	return toUpper(hex.EncodeToString(b))
}

func toUpper(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - 32
		}
	}
	return string(out)
}

// ThisMacConfig is the settings for this Mac: the real home and temp folder, the usual project folders, the system's
// Library and receipts, Full Disk Access as it is now. otherData: a data directory other than ~/.luoke-scan (then
// nothing is written into memory and nothing needs the password).
func ThisMacConfig(s *core.Store, t core.Tools, otherData bool) Config {
	h, _ := os.UserHomeDir()
	h = core.Standardized(h)
	ctx := core.NewContext(h)
	ctx.Store, ctx.Tools = s, t
	ctx.Tmp = userTempDir()
	ctx.SystemLibrary, ctx.Receipts = "/Library", "/var/db/receipts"
	ctx.BackgroundItems = core.BackgroundItemsDir
	// Not known (the probe failed some other way): as without, so a round never brings up a dialog.
	fda := false
	if v := FullDiskAccessNow(h); v != nil {
		fda = *v
	}
	ctx.FullDiskAccess, ctx.AccessOff = &fda, PermissionOff(fdaPermission)
	ctx.ProjectRoots = usualProjectRoots(h, fda)
	cfg := NewConfig(ctx)
	cfg.FullDiskAccess = func() *bool { return FullDiskAccessNow(h) }
	cfg.Running = runningNames
	cfg.CommandLines = commandLines
	cfg.AttachedImages = core.AttachedImagesNow
	cfg.Installed = core.CommandExists
	cfg.Added = core.DateAdded
	// The password step goes through 螺壳's main body, which shows the dialog (LUOKE_HOST_FD); a terminal uses sudo
	// (luoke-scan system sets its own).
	cfg.Elevate = HostElevate
	cfg.Front = HostFront // 在访达里显示、打开设置 by the main body, which is in front (LUOKE_HOST_FD); without it, open
	if otherData {
		cfg.Elevate = func([]string, string, time.Duration) Elevated {
			return Elevated{Kind: "failed", Why: "用别的数据目录时不用密码删除"}
		}
	}
	return cfg
}

// PermissionsOffEnv: the permissions this app may not use (ids in the manifest, comma-separated): those the manifest
// declares under 螺壳's name that the user has not confirmed for this app in 螺壳, whether never confirmed or switched
// off again. Set by 螺壳's main body.
const PermissionsOffEnv = "LUOKE_PERMISSIONS_OFF"

const fdaPermission = "fda"

// PermissionOff says whether this app may not use this permission: the user has not confirmed it (LUOKE_PERMISSIONS_OFF).
func PermissionOff(id string) bool {
	for _, p := range strings.Split(os.Getenv(PermissionsOffEnv), ",") {
		if strings.TrimSpace(p) == id {
			return true
		}
	}
	return false
}

// FullDiskAccessNow: false when the user has not confirmed it for this app, whatever macOS would allow. Else opening the
// user's TCC database needs Full Disk Access, and macOS never shows a dialog for it; else the Mac's. nil: not known
// (the probe failed some other way).
func FullDiskAccessNow(home string) *bool {
	if PermissionOff(fdaPermission) {
		no := false
		return &no
	}
	for _, p := range []string{filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db"), "/Library/Application Support/com.apple.TCC/TCC.db"} {
		fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err == nil {
			syscall.Close(fd)
			yes := true
			return &yes
		}
		if err == syscall.EPERM || err == syscall.EACCES {
			no := false
			return &no
		}
	}
	return nil
}

// userTempDir is this user's temp folder (confstr _CS_DARWIN_USER_TEMP_DIR; $TMPDIR is the same), standardized.
func userTempDir() string {
	d := os.Getenv("TMPDIR")
	if d == "" {
		return ""
	}
	return core.Standardized(d)
}

// usualProjectRoots are where projects usually are. Without Full Disk Access the one in Documents is kept without
// being checked for: looking would bring up macOS's dialog.
func usualProjectRoots(home string, fda bool) []string {
	var out []string
	for _, r := range []string{"Developer", "Projects", "Documents/GitHub", "code", "src", "repos", "workspace"} {
		p := filepath.Join(home, r)
		if !fda && strings.HasPrefix(p, filepath.Join(home, "Documents")+"/") {
			out = append(out, p)
			continue
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// runningNames are the programs this user is running, by name, and a script's own name (pip3 runs as python).
func runningNames() map[string]bool {
	me := uint32(os.Getuid())
	names := map[string]bool{}
	for _, p := range core.ProcSnapshot() {
		if p.UID != me || p.Path == "" {
			continue
		}
		names[filepath.Base(p.Path)] = true
		if args, ok := core.ProcArguments(p.PID); ok {
			for n := range core.ScriptNames(args) {
				names[n] = true
			}
		}
	}
	return names
}

// commandLines are this user's processes' command lines, lowercased; not ok when none could be read.
func commandLines() ([]string, bool) {
	me := uint32(os.Getuid())
	var lines []string
	for _, p := range core.ProcSnapshot() {
		if p.UID != me {
			continue
		}
		args, _ := core.ProcArguments(p.PID)
		lines = append(lines, strings.ToLower(strings.Join(append([]string{p.Path}, args...), " ")))
	}
	return lines, len(lines) > 0
}

// Service runs rounds and answers requests on one data directory.
type Service struct {
	Store  *core.Store
	Config Config
	Server *Server
	ids    sync.Map
	mu     sync.Mutex
	held   map[string]*os.File
	noPlan sync.Map // plan ids nothing could be planned for (also kept on disk as <id>.empty)
}

func New(s *core.Store, cfg Config) *Service {
	cfg.Context.Store = s
	if cfg.Accessory == "" {
		cfg.Accessory = "luoke-scan"
	}
	svc := &Service{Store: s, Config: cfg, held: map[string]*os.File{}}
	svc.Server = NewServer(cfg.Accessory, cfg.Version)
	svc.register()
	return svc
}

func (s *Service) now() time.Time   { return s.Config.Clock() }
func (s *Service) stateURL() string { return filepath.Join(s.Store.Dir, "agent-state.json") }
func (s *Service) plansDir() string { return filepath.Join(s.Store.Dir, "plans") }

// OutboxURI is the outbox resource.
func (s *Service) OutboxURI() string { return "luoke://" + s.Config.Accessory + "/outbox" }

func (s *Service) state() State { return LoadState(s.stateURL()) }

func (s *Service) mutate(body func(*State)) State { return MutateState(s.stateURL(), s.now(), body) }

// fid is a finding's id, worked out once per (rule, path).
func (s *Service) fid(f core.Finding) string {
	key := f.Rule + "\x00" + f.Path + "\x00" + f.Key
	if v, ok := s.ids.Load(key); ok {
		return v.(string)
	}
	v := f.ID()
	s.ids.Store(key, v)
	return v
}

// begin takes the plan's lock (one process carries a plan out at a time); false when someone else holds it.
func (s *Service) begin(plan string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held[plan] != nil {
		return false
	}
	os.MkdirAll(s.plansDir(), 0o700)
	path := filepath.Join(s.plansDir(), plan+".lock")
	for i := 0; i < 5; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return false
		}
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			f.Close()
			return false
		}
		var a, b syscall.Stat_t
		if syscall.Fstat(int(f.Fd()), &a) == nil && syscall.Stat(path, &b) == nil && a.Dev == b.Dev && a.Ino == b.Ino {
			s.held[plan] = f
			return true
		}
		f.Close()
	}
	return false
}

func (s *Service) end(plan string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.held[plan]
	if f == nil {
		return
	}
	delete(s.held, plan)
	os.Remove(filepath.Join(s.plansDir(), plan+".lock"))
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

// IsScanning says whether a round is running on this data directory.
func (s *Service) IsScanning() bool { return core.LockHeld(s.Store.Dir) }

// RunRound runs one round (cleaning the four kinds when autoclean), asks the model, keeps the report.
func (s *Service) RunRound(autoclean bool) core.Report {
	lock := core.TakeLock(s.Store.Dir, "round.lock", 0)
	defer lock.Release()
	defer s.Store.ClearProgress()
	s.reconcileAdmin()
	ctx := s.Config.Context
	ctx.Store = s.Store
	ctx.Now = s.now()
	report := core.RunRound(&ctx, s.Config.Rules, s.Config.Clock, s.Store.LastReport())
	if autoclean && !ctx.IsCancelled() {
		report = s.autoclean(report)
	}
	if p := s.Store.Progress(); p != nil { // 规则都跑完了，模型在写说明
		p.Done, p.Current = append(p.Done, p.Current), "model"
		s.Store.SaveProgress(*p)
	}
	report = s.withModel(report, &ctx)
	s.Store.SaveReport(report)
	PrunePlans(s.plansDir(), s.now(), 30*24*time.Hour)
	return report
}

func (s *Service) display(path string) string {
	if len(path) > 0 && path[0] == '/' {
		return s.Config.Context.Shown(path)
	}
	return path
}

func (s *Service) visible(r core.Report, st State) []core.Finding {
	var out []core.Finding
	for _, f := range r.Findings {
		if _, ignored := st.Ignored[s.fid(f)]; !ignored {
			out = append(out, f)
		}
	}
	return out
}

// answerCard is the card a tool answers with: replacing the card clicked on, or a new one.
func (s *Service) answerCard(meta O, keepChoices bool, fill func(*Card)) []any {
	if ua, ok := meta[UserAction].(map[string]any); ok {
		if sid, ok := ua["surfaceId"].(string); ok {
			c := NewCard(sid, "r"+strconv.FormatInt(s.now().Unix()%100000, 10)+"-")
			fill(c)
			return c.Updates(!keepChoices)
		}
	}
	b := make([]byte, 16)
	rand.Read(b)
	c := NewCard("scan-" + core.ShortHash(hex.EncodeToString(b)))
	fill(c)
	return c.Messages()
}

var marks = map[core.Verdict]string{core.Safe: "放心删", core.Confirm: "要确认", core.Info: "仅供参考"}

// Self is this program, to start a round of its own (scan_now from luoke-scan mcp).
func Self() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return exe
}

// StartDetached starts this program with args, its output thrown away, and does not wait.
func StartDetached(args []string) bool {
	cmd := exec.Command(Self(), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if core.Packed() {
		return startVouched(cmd) // the installed one checks who started it (FromApp)
	}
	return cmd.Start() == nil
}

// installedAppName: an app's own name for its bundle id, from one read of the usual app folders kept for ten minutes.
// Not AppsWithBundleID: outside a round that asks Spotlight once per id (up to 10 s each), and a page names hundreds
// of folders; the agent gives up on a page after 10 s (the 「状态」 page showed 「没在运行」, 11-09).
func installedAppName(id string) string {
	appNames.Lock()
	defer appNames.Unlock()
	if appNames.index == nil || time.Since(appNames.at) > 10*time.Minute {
		home, _ := os.UserHomeDir()
		appNames.index = core.AppIndexIn([]string{"/Applications", "/System/Applications", filepath.Join(home, "Applications")})
		appNames.at = time.Now()
	}
	if p := appNames.index[strings.ToLower(id)]; p != "" {
		return core.NameWithoutExtension(p)
	}
	return ""
}

var appNames struct {
	sync.Mutex
	index map[string]string
	at    time.Time
}
