// Command luoke-scan looks over this Mac (or a fake home) and answers 螺壳's agent. See usage.go.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
	"github.com/luokelabs/luoke-scan/internal/service"
)

var args []string

// freeToRun are the commands the installed luoke-scan runs for anyone: they only read the last report it wrote.
var freeToRun = map[string]bool{"version": true, "report": true, "findings": true, "status": true}

func fail(msg string, code ...int) {
	os.Stderr.WriteString(msg + "\n")
	c := 64
	if len(code) > 0 {
		c = code[0]
	}
	os.Exit(c)
}

// take removes every "name value" from the arguments and returns the values.
func take(name string) []string {
	var out []string
	for {
		i := indexOf(args, name)
		if i < 0 {
			return out
		}
		if i+1 >= len(args) {
			fail(name + " 后面要跟一个值")
		}
		out = append(out, args[i+1])
		args = append(args[:i:i], args[i+2:]...)
	}
}

func last(v []string) (string, bool) {
	if len(v) == 0 {
		return "", false
	}
	return v[len(v)-1], true
}

// flag removes the first name from the arguments and says whether it was there.
func flag(name string) bool {
	i := indexOf(args, name)
	if i < 0 {
		return false
	}
	args = append(args[:i:i], args[i+1:]...)
	return true
}

func indexOf(a []string, s string) int {
	for i, x := range a {
		if x == s {
			return i
		}
	}
	return -1
}

func dir(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		h, _ := os.UserHomeDir()
		p = filepath.Join(h, strings.TrimPrefix(p, "~"))
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return core.Standardized(a) // as Swift's standardizedFileURL: /private/var/… is /var/… (the goldens are spelled so)
}

func noExtra() {
	if len(args) > 0 {
		fail("不认识的参数：" + strings.Join(args, " ") + "\n\n" + usage)
	}
}

func openStore(data string, ok bool) *core.Store {
	if !ok {
		fail("要给 --data\n\n" + usage)
	}
	s, err := core.OpenStore(dir(data))
	if err != nil {
		fail(fmt.Sprintf("打不开数据目录：%v", err), 1)
	}
	return s
}

func toolsIn(toolDir string, ok bool) core.Tools {
	if !ok {
		return core.Tools{Packed: core.Packed()}
	}
	d := dir(toolDir)
	t := func(n string) string {
		if p := filepath.Join(d, n); core.IsExecutable(p) {
			return p
		}
		return ""
	}
	x := filepath.Join(d, "XProtect.yara")
	if f, err := os.Open(x); err == nil {
		f.Close()
	} else {
		x = ""
	}
	return core.Tools{Clamscan: t("clamscan"), Freshclam: t("freshclam"), Sigtool: t("sigtool"), Yara: t("yara"), XProtect: x}
}

func emit(r core.Report) {
	data, _ := core.EncodeJSON(r)
	os.Stdout.Write(data)
	fmt.Println()
}

var marks = map[core.Verdict]string{core.Safe: "放心删", core.Confirm: "要确认", core.Info: "仅供参考"}

func printFindings(r core.Report) {
	for _, f := range r.Findings {
		fmt.Printf("[%s] %s\n", marks[f.Verdict], f.Title)
		if f.Path != "" {
			fmt.Println("    " + f.Path)
		}
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if f.Evidence[k] != "" {
				fmt.Printf("    %s: %s\n", k, f.Evidence[k])
			}
		}
	}
	for _, s := range r.Skipped {
		fmt.Printf("[没扫描] %s：%s\n", s.Rule, s.Reason)
	}
}

func printStatus(r core.Report) {
	by := map[core.Verdict]int{}
	var reclaim int64
	for _, f := range r.Findings {
		by[f.Verdict]++
		if f.Verdict == core.Safe && f.Bytes != nil {
			reclaim += *f.Bytes
		}
	}
	fmt.Printf("上一轮：%s，用了 %d 秒\n", core.ISOTime(r.StartedAt.Time), int(r.FinishedAt.Sub(r.StartedAt.Time).Seconds()))
	fmt.Printf("发现：放心删 %d、要确认 %d、仅供参考 %d\n", by[core.Safe], by[core.Confirm], by[core.Info])
	if reclaim > 0 {
		fmt.Println("放心删的能腾出：" + core.FormatBytes(reclaim))
	}
	keys := make([]string, 0, len(r.Versions))
	for k := range r.Versions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s：%s\n", k, r.Versions[k])
	}
	for _, s := range r.Skipped {
		fmt.Printf("没扫描：%s（%s）\n", s.Rule, s.Reason)
	}
}

// gotTerm is set by SIGTERM (luoke-core sends it when the user comes back): stop after the current step.
var gotTerm atomic.Bool

func stopOnTerm() func() bool {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
		gotTerm.Store(true)
	}()
	return gotTerm.Load
}

// fixtureMode is how a fake home is looked at besides its files: its clock (running on from start, or standing at
// at) and whether 螺壳 has Full Disk Access.
type fixtureMode struct {
	start *float64
	at    *time.Time
	noFDA bool
}

func takeFixtureMode(fixture string) fixtureMode {
	var m fixtureMode
	if s, ok := last(take("--clock-start")); ok {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			m.start = &f
		}
	}
	if s, ok := last(take("--clock")); ok {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			fail("--clock 要一个 ISO 8601 时间，例如 2026-10-20T12:00:00Z")
		}
		m.at = &t
	}
	m.noFDA = flag("--no-full-disk-access")
	if fixture == "" && (m.start != nil || m.at != nil || m.noFDA) {
		fail("--clock-start、--clock、--no-full-disk-access 只和 --fixture 一起用")
	}
	if m.start != nil && m.at != nil {
		fail("--clock-start 和 --clock 只给一个")
	}
	return m
}

func (m fixtureMode) args() []string {
	var out []string
	if m.start != nil {
		out = append(out, "--clock-start", strconv.FormatFloat(*m.start, 'f', -1, 64))
	}
	if m.at != nil {
		out = append(out, "--clock", core.ISOTime(*m.at))
	}
	if m.noFDA {
		out = append(out, "--no-full-disk-access")
	}
	return out
}

var thisMac bool

func realHome() string {
	h, _ := os.UserHomeDir()
	return h
}

// setup is the store and the service's settings for a round or a request: this Mac, or a fake home.
func setup(fixture string, fx fixtureMode, data string, haveData bool, toolDir string, haveTools bool) (*core.Store, service.Config) {
	if fixture != "" {
		if thisMac {
			fail("--fixture 不和 --this-mac 一起用")
		}
		l := core.Layout{Root: fixture}
		if !core.Exists(l.Home()) {
			fail(fixture + " 不是假用户目录（假目录由 blackbox/fx.py 造，见 blackbox/README.md）")
		}
		fakes, _, err := l.LoadFakes()
		if err != nil {
			fail("fakes.json 读不了：" + err.Error())
		}
		s := openStore(l.Data(), true)
		cfg := service.FixtureConfig(l, fakes)
		if fx.at != nil {
			at := *fx.at
			cfg.Clock = func() time.Time { return at }
		} else {
			started := time.Now()
			if fx.start != nil {
				started = time.Unix(0, int64(*fx.start*1e9))
			}
			cfg.Clock = func() time.Time { return core.FixtureNow.Add(time.Since(started)) }
		}
		if fx.noFDA {
			no := false
			cfg.Context.FullDiskAccess = &no
			cfg.FullDiskAccess = func() *bool { return &no }
		}
		// A development luoke-core's socket given by hand (the black-box tests' fake one): a round asks its model as
		// on a real Mac. Nothing of a fixture goes into memory.
		if socket, ok := os.LookupEnv("LUOKE_HUB_SOCKET"); ok && !core.Packed() {
			if prompts, ok := service.Prompts(false); ok {
				cfg.Model = service.NewModelLink(socket, "luoke-scan/"+service.ToolVersion, prompts)
			}
		}
		return s, cfg
	}
	if !thisMac {
		fail("要给 --this-mac，或者 --fixture <假目录>\n\n" + usage)
	}
	otherData := haveData // a data directory given by hand: a test, never this Mac's luoke-core
	if !haveData {
		data, haveData = filepath.Join(realHome(), ".luoke-scan"), true
	}
	s := openStore(data, haveData)
	cfg := service.ThisMacConfig(s, toolsIn(toolDir, haveTools), data != filepath.Join(realHome(), ".luoke-scan"))
	// What happened goes into the user's memory through luoke-core's Python (luoke-mem#7), and the generate tasks go
	// to the same luoke-core: from the installed app, or a development build pointed at a luoke-core of its own
	// (LUOKE_HUB_SOCKET); never from a fixture or another data directory (development never talks to the one in use).
	// The environment is read here and kept with them.
	env := service.Environ()
	cfg.Remember = service.MemoryRecorder(core.Packed(), otherData, service.ToolVersion, env)
	cfg.Model = service.ModelForRun(core.Packed(), otherData, service.ToolVersion, true, env)
	return s, cfg
}

func main() {
	all := os.Args[1:]
	if len(all) == 0 {
		fail(usage)
	}
	command := all[0]
	args = append([]string{}, all[1:]...)
	devFlags := []string{"--home", "--data", "--tmp", "--projects", "--tool-dir", "--fixture", "--clock-start", "--clock", "--no-full-disk-access"}
	if core.Packed() {
		for _, a := range args {
			if indexOf(devFlags, a) >= 0 {
				fail(a + " 只给开发版用；装好的螺壳扫描只认 --this-mac")
			}
		}
		switch command {
		case "eval-cleanup", "eval-skills", "eval-agentfiles", "make-skill-evalset":
			fail(command + " 只给开发版用")
		}
		// Everything else reads this Mac under 螺壳's Full Disk Access or changes something: only 螺壳 starts it
		// (service/fromapp_darwin.go). A round the agent asked for is started by `luoke-scan mcp`.
		if !freeToRun[command] {
			if why := service.FromApp(command == "scan" && indexOf(args, "--for-agent") >= 0); why != "" {
				fail("螺壳扫描："+why+"。\n装好的螺壳扫描只由螺壳起，请在螺壳里用；终端里能看的是 report、findings、status、version。", 77)
			}
		}
	}
	thisMac = flag("--this-mac")
	defaultData := func() (string, bool) {
		if thisMac {
			return filepath.Join(realHome(), ".luoke-scan"), true
		}
		return "", false
	}

	switch command {
	case "version":
		fmt.Printf("luoke-scan %s · rules %s\n", service.ToolVersion, core.RulePackVersion)

	case "scan":
		homeArg, haveHome := last(take("--home"))
		fixture := ""
		if f, ok := last(take("--fixture")); ok {
			fixture = dir(f)
		}
		fx := takeFixtureMode(fixture)
		tmp, haveTmp := last(take("--tmp"))
		projects := take("--projects")
		jsonOut := flag("--json")
		forAgent := flag("--for-agent")
		autoclean := flag("--autoclean")
		ifNone := flag("--if-none")
		quick := flag("--quick")
		updateFirst := flag("--update-first")
		var s *core.Store
		var cfg service.Config
		if thisMac && (haveHome || haveTmp) {
			fail("--this-mac 不和 --home、--tmp 一起用")
		}
		if autoclean && (haveHome || forAgent || quick) {
			fail("--autoclean 只和 --this-mac、--fixture 一起用，不和 --for-agent、--quick 一起用")
		}
		if fixture != "" || !haveHome {
			if haveHome || haveTmp {
				fail("--this-mac、--fixture 不和 --home、--tmp 一起用")
			}
			data, haveData := last(take("--data"))
			toolDir, haveTools := last(take("--tool-dir"))
			if autoclean && fixture == "" && haveData {
				fail("--autoclean 只用这台 Mac 自己的数据目录，不和 --data 一起用")
			}
			s, cfg = setup(fixture, fx, data, haveData, toolDir, haveTools)
			if fixture == "" && len(projects) > 0 {
				cfg.Context.ProjectRoots = nil
				for _, p := range projects {
					cfg.Context.ProjectRoots = append(cfg.Context.ProjectRoots, dir(p))
				}
			}
			if forAgent && cfg.Model != nil {
				cfg.Model.AskNew = false
			}
		} else {
			data, haveData := last(take("--data"))
			if !haveData {
				data, haveData = defaultData()
			}
			s = openStore(data, haveData)
			toolDir, haveTools := last(take("--tool-dir"))
			ctx := core.NewContext(dir(homeArg))
			if haveTmp {
				ctx.Tmp = dir(tmp)
			}
			for _, p := range projects {
				ctx.ProjectRoots = append(ctx.ProjectRoots, dir(p))
			}
			ctx.Tools = toolsIn(toolDir, haveTools)
			cfg = service.NewConfig(ctx)
		}
		noExtra()
		if ifNone && s.LastReport() != nil {
			os.Exit(0)
		}
		// Nobody waits on a round (luoke-core's idle job, the one scan_now starts) or the quick look: the user's apps first.
		core.LowerPriority()
		if quick {
			if why := cfg.QuickWaits(); why != "" {
				fmt.Println("先不看新下载的：" + why)
				os.Exit(0)
			}
			// One quick look at a time; it keeps out of a full round's way itself (RunQuick).
			lock := core.TakeLock(s.Dir, "quick.lock", 0)
			if lock == nil {
				os.Exit(0)
			}
			cfg.Context.Cancelled = stopOnTerm()
			report := service.New(s, cfg).RunQuick(core.NewJournalSource())
			lock.Release()
			if report != nil {
				hits := 0
				for _, f := range report.Findings {
					if strings.HasPrefix(f.Rule, "malware.clamav") || strings.HasPrefix(f.Rule, "malware.yara.") {
						hits++
					}
				}
				fmt.Printf("看了新下载的：病毒发现 %d 条\n", hits)
			} else {
				fmt.Println("没有新下载的")
			}
			os.Exit(0)
		}
		lock := core.TakeLock(s.Dir, "round.lock", 3*time.Second)
		if lock == nil {
			os.Stderr.WriteString("已经在查了\n")
			os.Exit(0)
		}
		cfg.Context.Cancelled = stopOnTerm()
		// No virus database yet (the first round, which luoke-core starts as soon as the user turns the app on, while the
		// daily update waits for its next quiet moment): download it first, so that the round checks for viruses too
		// (luoke-scan#122). Once a day at most, as the update job; a failure leaves the check to say why it did not run.
		if thisMac || updateFirst {
			if db := core.NewVirusDB(s, cfg.Context.Tools); len(db.Files()) == 0 {
				db.Update(s, cfg.Clock(), false, 10*time.Minute)
			}
		}
		report := service.New(s, cfg).RunRound(autoclean)
		lock.Release()
		if jsonOut {
			emit(report)
		} else {
			printFindings(report)
			fmt.Printf("共 %d 条发现，%d 项没扫描（规则 %s）\n", len(report.Findings), len(report.Skipped), report.RulePack)
		}

	case "report":
		data, ok := last(take("--data"))
		if !ok {
			data = filepath.Join(realHome(), ".luoke-scan")
		}
		s := openStore(data, true)
		noExtra()
		r := s.LastReport()
		if r == nil {
			fail("还没查过（先跑 luoke-scan scan --this-mac）", 1)
		}
		fmt.Print(core.ReportText(*r, realHome()))

	case "findings", "status":
		data, ok := last(take("--data"))
		if !ok {
			data, ok = defaultData()
		}
		s := openStore(data, ok)
		jsonOut := flag("--json")
		noExtra()
		r := s.LastReport()
		if r == nil {
			fail("还没查过（先跑 luoke-scan scan）", 1)
		}
		if jsonOut {
			emit(*r)
		} else if command == "findings" {
			printFindings(*r)
		} else {
			printStatus(*r)
		}

	case "update":
		data, ok := last(take("--data"))
		if !ok {
			data, ok = defaultData()
		}
		s := openStore(data, ok)
		toolDir, haveTools := last(take("--tool-dir"))
		t := toolsIn(toolDir, haveTools)
		force := flag("--force")
		core.LowerPriority() // luoke-core's idle job: freshclam and sigtool inherit it
		noExtra()
		db := core.NewVirusDB(s, t)
		o := db.Update(s, time.Now(), force, 1200*time.Second)
		switch o.Kind {
		case "updated":
			v := o.Version
			if v == "" {
				v = "?"
			}
			fmt.Printf("病毒库更新好了（daily %s）\n", v)
		case "upToDate":
			fmt.Println("病毒库已经是最新的")
		case "notDue":
			fmt.Printf("今天已经检查过，下次：%s（要现在查就加 --force）\n", core.ISOTime(o.Next))
		default:
			if len(db.Files()) == 0 { // 一个旧库都没有时不说「旧库保留」（luoke-scan#103）
				fail("病毒库没下载成："+o.Why, 1)
			}
			fail("病毒库没更新，旧库保留："+o.Why, 1)
		}

	case "malicious-import":
		// The list of known malicious packages, from OSV records already on this Mac: nothing is downloaded.
		data, ok := last(take("--data"))
		if !ok {
			data, ok = defaultData()
		}
		s := openStore(data, ok)
		if len(args) != 1 || strings.HasPrefix(args[0], "--") {
			fail("要给一个 OSV 的 JSON 文件、放着它们的文件夹或 .zip\n\n" + usage)
		}
		src := dir(args[0])
		args = nil
		res, err := core.ImportMalicious(src, s.Dir, time.Now())
		if err != nil {
			fail("恶意包名单没导入，原来的名单保留："+err.Error(), 1)
		}
		// The import adds to the list: what it gave, what of the list before it replaced, and what the list holds now.
		fmt.Printf("恶意包名单导入好了：这次 %d 条（换掉原有的 %d 条），名单里现在共 %d 条，日期 %s（读了 %d 份 OSV 记录）\n",
			res.Kept, res.Replaced, res.Total, res.Date, res.Files)
		// The ecosystems' days, when they differ (the list's is the oldest).
		days := map[string]bool{}
		for _, d := range res.EcoDates {
			days[d] = true
		}
		if len(days) > 1 {
			var ecos []string
			for _, eco := range core.MalEcosystems {
				if d, ok := res.EcoDates[eco]; ok {
					ecos = append(ecos, eco+" "+d)
				}
			}
			fmt.Printf("各生态的日期：%s（名单的日期取最旧的那个）\n", strings.Join(ecos, "、"))
		}
		if res.NotMal+res.Withdrawn+res.OtherEco+res.Unusable+res.Bad > 0 {
			fmt.Printf("没留：不是 MAL- 的 %d 条、撤回的 %d 条、别的生态的 %d 个包、没法比对版本的 %d 个包、读不了的 %d 份\n",
				res.NotMal, res.Withdrawn, res.OtherEco, res.Unusable, res.Bad)
		}

	case "mcp":
		// MCP on standard input and output: one request read to the end, or a session of one message per line (螺壳
		// hands the agent this pipe). Reads the disk under 螺壳's Full Disk Access; never listens on a socket.
		fixture := ""
		if f, ok := last(take("--fixture")); ok {
			fixture = dir(f)
		}
		fx := takeFixtureMode(fixture)
		data, haveData := last(take("--data"))
		toolDir, haveTools := last(take("--tool-dir"))
		noExtra()
		s, cfg := setup(fixture, fx, data, haveData, toolDir, haveTools)
		mode := []string{"--this-mac"}
		if fixture != "" {
			mode = append([]string{"--fixture", fixture}, fx.args()...)
		}
		if haveData {
			mode = append(mode, "--data", data) // the round checks and takes the lock of this same data directory
		}
		if haveTools {
			mode = append(mode, "--tool-dir", toolDir)
		}
		// A round the agent asks for runs as a process of its own.
		cfg.StartScan = func() bool { return service.StartDetached(append([]string{"scan", "--for-agent"}, mode...)) }
		os.Exit(service.New(s, cfg).Server.Serve(os.Stdin, os.Stdout))

	case "system":
		// What needs the password, done from a terminal. Run as the user, never with sudo: this program hands only the
		// one step to sudo, which asks for the password here every time; root checks that step's signature first.
		if os.Geteuid() == 0 {
			fail("不要加 sudo：直接跑，要密码的那一步本程序会交给 sudo，在这个终端里问你")
		}
		fixture := ""
		if f, ok := last(take("--fixture")); ok {
			fixture = dir(f)
		}
		data, haveData := last(take("--data"))
		trashArg, haveKeys := last(take("--trash"))
		var keys []string
		for _, k := range strings.Split(trashArg, ",") {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
		noExtra()
		s, cfg := setup(fixture, fixtureMode{}, data, haveData, "", false)
		var outcome *service.Elevated
		if fixture == "" && !haveData {
			cfg.Elevate = func(a []string, prompt string, wait time.Duration) service.Elevated {
				r := service.SudoElevate(a, prompt, wait)
				outcome = &r
				return r
			}
		}
		svc := service.New(s, cfg)
		found := svc.SystemLeftovers()
		if found == nil {
			if s.LastReport() == nil {
				fmt.Println("还没查过这台 Mac。")
			} else {
				fmt.Println("上一轮没查到要密码才能删的东西。")
			}
			if haveKeys {
				os.Exit(1) // asked to move something that is not there
			}
			os.Exit(0)
		}
		if !haveKeys {
			done := "："
			if found.Done {
				done = "，已经处理过了："
			}
			l := found.Scanned.Local()
			fmt.Printf("上一轮（%d月%d日 %02d:%02d）查到的要密码才能删的%s\n", int(l.Month()), l.Day(), l.Hour(), l.Minute(), done)
			var left []string
			for _, it := range found.Items {
				size, gone := "", ""
				if it.Bytes != nil {
					size = "（" + core.FormatBytes(*it.Bytes) + "）"
				}
				if it.Gone {
					gone = "  已经移走了"
				} else {
					left = append(left, it.Key)
				}
				fmt.Printf("  %s  %s%s%s\n", it.Key, it.Title, size, gone)
				for _, p := range it.Paths {
					fmt.Println("      " + p)
				}
			}
			if !found.Done && len(left) > 0 {
				word := func(x string) string {
					if strings.ContainsAny(x, " \t'\"\\$`!*?[]{}()<>|&;#~") {
						return service.ShellQuote(x)
					}
					return x
				}
				place := "--this-mac"
				if fixture != "" {
					place = "--fixture " + word(fixture)
				} else if haveData {
					place += " --data " + word(data)
				}
				fmt.Printf("要移到废纸篓：%s system %s --trash %s\n", word(os.Args[0]), place, strings.Join(left, ","))
				fmt.Println("（sudo 会在这个终端里问这台 Mac 的登录密码，每次都问。）")
			}
			os.Exit(0)
		}
		if len(keys) == 0 {
			fail("--trash 后面写编号，例如 a0,a1（编号见 luoke-scan system --this-mac）")
		}
		lines, ok := svc.TrashSystemLeftovers(keys)
		if outcome != nil && outcome.Kind == "cancelled" {
			fmt.Println("没有删：sudo 没有执行（见上面 sudo 说的：没输密码、密码不对，或者这个账户不能用 sudo）。")
			os.Exit(1)
		}
		for _, l := range lines {
			fmt.Println(l)
		}
		if !ok {
			os.Exit(1)
		}

	case "cleaned", "restore":
		fixture := ""
		if f, ok := last(take("--fixture")); ok {
			fixture = dir(f)
		}
		data, haveData := last(take("--data"))
		jsonOut := flag("--json")
		ids := args
		args = nil
		s, cfg := setup(fixture, fixtureMode{}, data, haveData, "", false)
		svc := service.New(s, cfg)
		if command == "cleaned" {
			all := svc.Cleaned()
			for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
				all[i], all[j] = all[j], all[i]
			}
			if jsonOut {
				if all == nil {
					all = []service.Cleaned{}
				}
				b, _ := core.EncodeJSON(all)
				os.Stdout.Write(append(b, '\n'))
				os.Exit(0)
			}
			if len(all) == 0 {
				fmt.Println("还没清理过。")
			}
			for _, e := range all {
				state := "废纸篓里没了"
				switch {
				case e.Restored != nil:
					state = "已放回"
				case e.Trashed == nil:
					state = "直接删的"
				case core.Exists(*e.Trashed):
					state = "能放回"
				}
				size := ""
				if e.Bytes != nil {
					size = "（" + core.FormatBytes(*e.Bytes) + "）"
				}
				fmt.Printf("%s  %s  [%s]  %s%s\n", e.ID, core.ISOTime(e.At.Time), state, e.Title, size)
				auto := ""
				if e.Auto != nil {
					auto = "，自动清的（" + *e.Auto + "）"
				}
				fmt.Printf("    %s    批：%s%s\n", e.Original, e.Batch, auto)
			}
		} else {
			if len(ids) == 0 {
				fail("用法：luoke-scan restore --this-mac <编号>…（编号见 luoke-scan cleaned）")
			}
			done := svc.PutBackIDs(ids)
			if len(done) == 0 {
				fail("记录里没有这些编号："+strings.Join(ids, " "), 1)
			}
			allOK := true
			for _, d := range done {
				if d.To == "" && d.Note == service.AlreadyBack {
					fmt.Println("之前已经放回过了：" + d.Title)
					continue
				}
				head := "没放回："
				if d.To != "" {
					head = "放回了："
				} else {
					allOK = false
				}
				note := ""
				if d.Note != "" {
					note = "（" + d.Note + "）"
				}
				fmt.Println(head + d.Title + note)
			}
			if !allOK {
				os.Exit(1)
			}
		}

	default:
		if runMore(command) {
			return
		}
		fail(usage)
	}
}
