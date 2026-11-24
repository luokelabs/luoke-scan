package core

import (
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() { Register("space.system", NewSystemSpaceRule) }

// SystemSpaceRule finds where large amounts of space go that the home folder sizes do not explain well: Time
// Machine's local snapshots, the disk images of container and VM tools, the models AI tools download, the restore
// images of macOS and iOS left after an install, and what Xcode keeps (device support for each OS a device ran,
// archives, simulators).
type SystemSpaceRule struct {
	// Time Machine deletes its local snapshots within a day once a backup is done; older ones are held for a reason.
	SnapshotAge           time.Duration
	MinVMBytes            int64
	MinModelBytes         int64
	MinModelsTotal        int64
	MaxModels             int
	MinDeviceSupportBytes int64
	MinArchivesBytes      int64
	MinSimulatorBytes     int64
	// A restore image this big, not written to for IpswQuiet (one being downloaded or installed is in use).
	MinIpswBytes int64
	IpswQuiet    time.Duration
	// Device support written to within this long is in use (a device on that OS is being debugged).
	DeviceSupportQuiet time.Duration
	// The user's Spotlight index (what apps hand to Spotlight) from this size up is out of the ordinary.
	MinSpotlightBytes int64
	// Snapshots are the dates of Time Machine's local snapshots on the startup disk; ok false when tmutil does not
	// answer. nil: this Mac's.
	Snapshots func() ([]time.Time, bool)
}

// NewSystemSpaceRule makes the rule; for a fake home the snapshots are its fakes' and restore images count from 1 MiB.
func NewSystemSpaceRule(l *Layout, f *Fakes) Rule {
	r := &SystemSpaceRule{SnapshotAge: 2 * 24 * time.Hour, MinVMBytes: 5 << 30, MinModelBytes: 2 << 30, MinModelsTotal: 5 << 30,
		MaxModels: 20, MinDeviceSupportBytes: 100 << 20, MinArchivesBytes: 1 << 30, MinSimulatorBytes: 5 << 30,
		MinIpswBytes: 1 << 30, IpswQuiet: 24 * time.Hour, DeviceSupportQuiet: 30 * 24 * time.Hour,
		MinSpotlightBytes: 10 << 30}
	if l != nil {
		snaps := f.Snapshots
		r.Snapshots = func() ([]time.Time, bool) {
			if snaps == nil {
				return nil, false
			}
			return *snaps, true
		}
		r.MinIpswBytes = 1 << 20
	}
	return r
}

func (r *SystemSpaceRule) ID() string { return "space.system" }
func (r *SystemSpaceRule) Emits() []string {
	return []string{"space.tm-snapshots", "space.vm-disk", "space.ai-model", "space.ai-models", "space.ipsw",
		"space.xcode-device-support", "space.xcode-archives", "space.simulators", "space.spotlight-index"}
}

// thisMacSnapshots asks tmutil for the local snapshots.
func thisMacSnapshots() ([]time.Time, bool) {
	r := Run("/usr/bin/tmutil", []string{"listlocalsnapshots", "/"}, RunOpts{Timeout: 20 * time.Second})
	if r.Status != 0 {
		return nil, false
	}
	return SnapshotDates(r.Stdout), true
}

var snapshotName = regexp.MustCompile(`com\.apple\.TimeMachine\.(\d{4}-\d{2}-\d{2}-\d{6})`)

// SnapshotDates are the dates of Time Machine's snapshots (com.apple.TimeMachine.<date>.local) in tmutil's list.
// Other snapshots (a prepared macOS update) are not Time Machine's and not counted.
func SnapshotDates(text string) []time.Time {
	var out []time.Time
	for _, line := range strings.Split(text, "\n") {
		m := snapshotName.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if d, err := time.ParseInLocation("2006-01-02-150405", m[1], time.Local); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// vmTools are the container and VM tools whose disk images are measured, vmMarkers the signs that one whose disk is in
// its container is installed, and aiTools the folders of AI tools' downloaded models (rules/space-tools.json).
var (
	vmTools   []vmTool
	vmMarkers map[string]vmSign
	aiTools   []aiTool
)

func (r *SystemSpaceRule) Run(ctx *Context) ([]Finding, error) {
	if spaceErr != nil {
		return nil, rulesMissing("space-tools.json")
	}
	var out []Finding
	snapshots := r.Snapshots
	if snapshots == nil {
		snapshots = thisMacSnapshots
	}
	if dates, ok := snapshots(); ok {
		var oldest time.Time
		old := 0
		for _, d := range dates {
			if ctx.Now.Sub(d).Seconds() > r.SnapshotAge.Seconds() {
				old++
				if oldest.IsZero() || d.Before(oldest) {
					oldest = d
				}
			}
		}
		if old > 0 {
			out = append(out, Finding{Rule: "space.tm-snapshots", Category: CatSpace, Severity: Low, Verdict: Info,
				Title: fmt.Sprintf("%d 个 Time Machine 本地快照留了 %d 天还没删", old, int(ctx.Now.Sub(oldest).Seconds()/86400)),
				Evidence: map[string]string{"count": strconv.Itoa(len(dates)), "oldest": ISODay(oldest),
					"why": "备份成功后系统一天内会自己删掉本地快照；留得久了多半是最近的备份没成功，它们占着的空间要等删了才回来",
					"how": "打开 系统设置 → 通用 → 时间机器，看最近一次备份是不是失败了"}})
		}
	}
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted, out...)
	}

	var vmLeft, leftOut []string
	for _, vm := range vmTools {
		var dirs []string
		guarded := false
		for _, p := range vm.paths {
			d := filepath.Join(ctx.Home, p)
			if !ctx.MayLook(d) {
				guarded = true
				continue
			}
			if Exists(d) {
				dirs = append(dirs, d)
			}
		}
		// Said only of a tool that is there (its own folder in the home, or its app) and was not measured otherwise.
		if len(dirs) == 0 && guarded {
			if m, ok := vmMarkers[vm.tool]; ok {
				there := Exists(filepath.Join(ctx.Home, m.folder))
				for _, a := range ctx.AppDirs {
					there = there || Exists(filepath.Join(a, m.app))
				}
				if there {
					vmLeft = append(vmLeft, vm.tool)
				}
			}
		}
		if len(dirs) == 0 {
			continue
		}
		var bytes int64
		for _, d := range dirs {
			bytes += AllocatedSize(d)
		}
		if bytes < r.MinVMBytes {
			continue
		}
		out = append(out, Finding{Rule: "space.vm-disk", Category: CatSpace, Severity: Low, Verdict: Info, Path: dirs[0], Bytes: Size(bytes),
			Title:    vm.tool + " 的虚拟磁盘占了 " + FormatBytes(bytes),
			Evidence: map[string]string{"tool": vm.tool, "why": vm.explain, "how": vm.how}})
	}
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted, out...)
	}

	if len(vmLeft) > 0 {
		leftOut = append(leftOut, strings.Join(vmLeft, "、")+" 的虚拟磁盘（在它的容器里）")
	}
	type total struct {
		text  string
		bytes int64
	}
	var totals []total
	var models []Finding
	var unusedShared []string
	for _, ai := range aiTools {
		root := filepath.Join(ctx.Home, ai.path)
		if !ctx.MayLook(root) || !Exists(root) {
			continue
		}
		var sum int64
		if ai.models != "" {
			// What each model's files really take: its own, and those its links point to inside the cache (Hugging
			// Face's shared store keeps each file once in hub/blobs and links it from every repository using it).
			rootReal, err := filepath.EvalSymlinks(root) // spelled as realpath spells the links' targets
			if err != nil {
				rootReal = root
			}
			used := map[string]int64{}
			for _, m := range modelFolders(root, ai.models) {
				own := map[string]int64{}
				shared := reachable(m.dir, rootReal, own)
				for k, v := range own {
					if _, ok := used[k]; !ok {
						used[k] = v
					}
				}
				var bytes int64
				for _, v := range own {
					bytes += v
				}
				if bytes < r.MinModelBytes {
					continue
				}
				came, haveCame := Modified(m.dir)
				ev := map[string]string{"tool": ai.tool, "model": m.name, "how": ai.how}
				if haveCame {
					ev["downloaded"] = ISODay(came)
				}
				// Deleting the folder of one in the shared store frees nothing (its files stay in hub/blobs, used by
				// nobody): only told, with the tool's own commands; never in a plan.
				verdict := Confirm
				if shared {
					ev["how"] = "在终端里用 `hf cache rm " + m.name + "` 删掉它，再 `hf cache prune` 清掉没人用的共用文件；再用时会重新下载。别直接删这个文件夹：文件在共用存储（hub/blobs）里，删了文件夹腾不出空间"
					ev["store"] = "shared"
					verdict = Info
				}
				title := ai.tool + " 的模型 " + m.name + "（" + FormatBytes(bytes) + "）"
				if haveCame {
					title += fmt.Sprintf("，%d 天前下载", int(math.Max(0, ctx.Now.Sub(came).Seconds())/86400))
				}
				models = append(models, Finding{Rule: "space.ai-model", Category: CatCache, Severity: Low, Verdict: verdict, Path: m.dir,
					Bytes: Size(bytes), Title: title, Evidence: ev})
			}
			// The shared store's files no repository uses any more (what `hf cache prune` removes) count too.
			store := map[string]int64{}
			reachable(filepath.Join(root, "blobs"), rootReal, store)
			var unused int64
			for k, v := range store {
				if _, ok := used[k]; !ok {
					unused += v
					used[k] = v
				}
			}
			for _, v := range used {
				sum += v
			}
			if unused >= r.MinModelBytes {
				unusedShared = append(unusedShared, ai.tool+" 的共用存储里有 "+FormatBytes(unused)+" 没有模型在用（`hf cache prune` 清掉）")
			}
		} else {
			sum = AllocatedSize(root)
		}
		if sum > 0 {
			totals = append(totals, total{ai.tool + " " + FormatBytes(sum), sum})
		}
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, out...)
		}
	}
	sort.SliceStable(models, func(i, j int) bool { return bytesOf(models[i]) > bytesOf(models[j]) })
	if len(models) > r.MaxModels {
		models = models[:r.MaxModels]
	}
	out = append(out, models...)
	var all int64
	for _, t := range totals {
		all += t.bytes
	}
	if all >= r.MinModelsTotal {
		sort.SliceStable(totals, func(i, j int) bool { return totals[i].bytes > totals[j].bytes })
		names := make([]string, len(totals))
		for i, t := range totals {
			names[i] = t.text
		}
		ev := map[string]string{"tools": strings.Join(names, "；"), "how": "大的模型单独列出来了；用不到的删掉，再用时会重新下载"}
		if len(unusedShared) > 0 {
			ev["unused"] = strings.Join(unusedShared, "；")
		}
		out = append(out, Finding{Rule: "space.ai-models", Category: CatSpace, Severity: Low, Verdict: Info, Bytes: Size(all),
			Title: "AI 工具下载的模型一共占了 " + FormatBytes(all), Evidence: ev})
	}
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted, out...)
	}
	images, imagesLeft := r.ipsw(ctx)
	out = append(out, images...)
	if imagesLeft {
		leftOut = append(leftOut, "下载、桌面、文稿里的系统恢复镜像")
	}
	out = append(out, r.xcode(ctx)...)
	out = append(out, r.spotlight(ctx)...)
	if len(leftOut) > 0 {
		return nil, Skip(NotLooked(strings.Join(leftOut, "、")), out...)
	}
	return out, nil
}

// ipswPlaces are where restore images (.ipsw) are looked for besides the home and its folders (and one level down):
// the folders iTunes and Apple Configurator keep firmware in, and lume's.
var ipswPlaces = []string{"Library/iTunes/iPhone Software Updates", "Library/iTunes/iPad Software Updates",
	"Library/Group Containers/K36BKF7T3D.group.com.apple.configurator/Library/Caches/Firmware", ".lume"}

// ipsw finds macOS and iOS restore images: once the system is installed (a VM made, a device restored) nothing reads
// them again, and Apple serves them again when needed. Each its own finding. left: some place was not looked at for
// want of Full Disk Access.
func (r *SystemSpaceRule) ipsw(ctx *Context) ([]Finding, bool) {
	dirs := []string{ctx.Home}
	for _, p := range ipswPlaces {
		dirs = append(dirs, filepath.Join(ctx.Home, p))
	}
	for _, d := range Children(ctx.Home) {
		name := filepath.Base(d)
		if strings.HasPrefix(name, ".") || name == "Library" || !spaceIsDir(d) {
			continue
		}
		dirs = append(dirs, d)
		if ctx.MayLook(d) {
			for _, c := range Children(d) {
				if spaceIsDir(c) {
					dirs = append(dirs, c)
				}
			}
		}
	}
	var out []Finding
	left := false
	seen := map[string]bool{}
	for _, d := range dirs {
		if !ctx.MayLook(d) {
			left = left || Exists(d)
			continue
		}
		for _, f := range Children(d) {
			if strings.ToLower(spaceExt(f)) != "ipsw" || seen[f] {
				continue
			}
			seen[f] = true
			var st syscall.Stat_t
			if syscall.Lstat(f, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
				continue
			}
			bytes := st.Blocks * 512
			changed := time.Unix(st.Mtimespec.Sec, 0)
			age := ctx.Now.Sub(changed).Seconds()
			if bytes < r.MinIpswBytes || age < r.IpswQuiet.Seconds() {
				continue
			}
			name := DisplayName(f)
			out = append(out, Finding{Rule: "space.ipsw", Category: CatCache, Severity: Low, Verdict: Confirm, Path: f, Bytes: Size(bytes),
				Title: fmt.Sprintf("系统恢复镜像 %s（%s），%d 天前下载", name, FormatBytes(bytes), int(math.Max(0, age)/86400)),
				Evidence: map[string]string{"file": name, "downloaded": ISODay(changed),
					"why": "装 macOS 虚拟机、恢复或升级设备时下载的整套系统；装好以后就用不到了",
					"how": "用不到就移到废纸篓；要再用时 lume、UTM、Apple Configurator 会从 Apple 重新下载"}})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return bytesOf(out[i]) > bytesOf(out[j]) })
	return out, left
}

// deviceSupport are Xcode's folders for each platform: the copy of a device OS's files it makes the first time a
// device on it is debugged ("17.5 (21F79)", "iPhone16,2 18.1 (22B83)").
var deviceSupport = []string{"iOS DeviceSupport", "watchOS DeviceSupport", "tvOS DeviceSupport", "visionOS DeviceSupport",
	"xrOS DeviceSupport", "macOS DeviceSupport"}

var dottedVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+`)

// DeviceVersion is the OS version a device support folder is for: the first dotted number in its name not right after
// a digit, a dot or a comma ("iPhone16,2 18.1 (22B83)" → 18.1); "" none.
func DeviceVersion(name string) string {
	for i := 0; i < len(name); i++ {
		if i > 0 {
			if p := name[i-1]; (p >= '0' && p <= '9') || p == '.' || p == ',' {
				continue
			}
		}
		if m := dottedVersion.FindString(name[i:]); m != "" {
			return m
		}
	}
	return ""
}

var isoDayName = regexp.MustCompile(`^\p{Nd}{4}-\p{Nd}{2}-\p{Nd}{2}$`)

// xcode: device support for older OS versions than the newest of its platform, not used for a month, each its own
// finding (Xcode copies it again from a device on that OS). Archives and simulators are only told: an archive of a
// release is what makes its crash reports readable, and a simulator holds the apps' data put in it.
func (r *SystemSpaceRule) xcode(ctx *Context) []Finding {
	dev := filepath.Join(ctx.Home, "Library/Developer")
	var out []Finding
	since := ctx.Now.Add(-r.DeviceSupportQuiet)
	for _, platform := range deviceSupport {
		type version struct{ dir, v string }
		var versions []version
		for _, u := range Children(filepath.Join(dev, "Xcode", platform)) {
			if !spaceIsDir(u) {
				continue
			}
			if v := DeviceVersion(filepath.Base(u)); v != "" {
				versions = append(versions, version{u, v})
			}
		}
		if len(versions) == 0 {
			continue
		}
		newest := versions[0]
		for _, v := range versions[1:] {
			if c, ok := spaceCompareVersions(newest.v, v.v); ok && c == -1 {
				newest = v
			}
		}
		name := strings.TrimSuffix(platform, " DeviceSupport")
		for _, v := range versions {
			if c, ok := spaceCompareVersions(v.v, newest.v); !ok || c != -1 {
				continue
			}
			bytes, unchanged := SizeUnlessChanged(v.dir, since, ctx.Now)
			if !unchanged || bytes < r.MinDeviceSupportBytes {
				continue
			}
			out = append(out, Finding{Rule: "space.xcode-device-support", Category: CatCache, Severity: Low, Verdict: Confirm, Path: v.dir,
				Bytes: Size(bytes),
				Title: fmt.Sprintf("Xcode 为 %s %s 留的设备支持文件（%s），已经有 %s 的了", name, v.v, FormatBytes(bytes), newest.v),
				Evidence: map[string]string{"platform": name, "version": v.v, "newest": newest.v,
					"why": "Xcode 第一次调试这个系统版本的设备时从设备上拷来的；只有还要调试这个版本的设备才用得到",
					"how": "删了以后，再接上这个版本的设备，Xcode 会重新拷一次（几分钟）"}})
		}
	}
	archives := filepath.Join(dev, "Xcode/Archives")
	if Exists(archives) {
		bytes := AllocatedSize(archives)
		var days []string
		count := 0
		for _, d := range Children(archives) {
			if !spaceIsDir(d) {
				continue
			}
			days = append(days, filepath.Base(d))
			for _, a := range Children(d) {
				if spaceExt(a) == "xcarchive" {
					count++
				}
			}
		}
		if bytes >= r.MinArchivesBytes {
			ev := map[string]string{"count": strconv.Itoa(count), "how": "在 Xcode 的 Organizer 里删掉不再需要的归档；发布过的版本留着它的归档，才能看懂那个版本的崩溃报告"}
			oldest := ""
			for _, d := range days {
				if isoDayName.MatchString(d) && (oldest == "" || d < oldest) {
					oldest = d
				}
			}
			if oldest != "" {
				ev["oldest"] = oldest
			}
			out = append(out, Finding{Rule: "space.xcode-archives", Category: CatSpace, Severity: Low, Verdict: Info, Path: archives,
				Bytes: Size(bytes), Title: fmt.Sprintf("Xcode 的归档有 %d 个，占了 %s", count, FormatBytes(bytes)), Evidence: ev})
		}
	}
	devices := filepath.Join(dev, "CoreSimulator/Devices")
	if Exists(devices) {
		bytes := AllocatedSize(devices)
		if bytes >= r.MinSimulatorBytes {
			count := 0
			for _, d := range Children(devices) {
				if spaceIsDir(d) {
					count++
				}
			}
			out = append(out, Finding{Rule: "space.simulators", Category: CatSpace, Severity: Low, Verdict: Info, Path: devices, Bytes: Size(bytes),
				Title: fmt.Sprintf("%d 个模拟器占了 %s", count, FormatBytes(bytes)),
				Evidence: map[string]string{"count": strconv.Itoa(count), "why": "每个模拟器里有装进去的应用和它们的数据",
					"how": "在终端运行 xcrun simctl delete unavailable，删掉系统已经不在了的模拟器；用不到的模拟器系统在 Xcode 的设置里「Components」（旧版叫 Platforms）删"}})
		}
	}
	return out
}

// userSpotlight is the user's part of the Spotlight index: what apps (Mail, Notes, Messages…) hand to Spotlight to
// be found by. The system's own index (/.Spotlight-V100) is read by root only: space.reconcile names it.
const userSpotlight = "Library/Metadata/CoreSpotlight"

// spotlight tells when the user's Spotlight index is far larger than it ordinarily is. Only told: rebuilding it is
// the system's to do, on the user's say. Without Full Disk Access macOS does not let it be listed (nothing is
// measured, nothing told).
func (r *SystemSpaceRule) spotlight(ctx *Context) []Finding {
	dir := filepath.Join(ctx.Home, userSpotlight)
	if !ctx.MayLook(dir) || !Exists(dir) {
		return nil
	}
	bytes := AllocatedSize(dir)
	if bytes < r.MinSpotlightBytes {
		return nil
	}
	return []Finding{{Rule: "space.spotlight-index", Category: CatSpace, Severity: Low, Verdict: Info, Path: dir, Bytes: Size(bytes),
		Title: "Spotlight 的索引占了 " + FormatBytes(bytes),
		Evidence: map[string]string{"threshold": FormatBytes(r.MinSpotlightBytes),
			"why": "这是邮件、备忘录、信息等应用交给 Spotlight 用来搜索的索引，平常不会这么大；大成这样可能是索引出了问题",
			"how": "让系统重建索引：系统设置 → Spotlight → 搜索隐私，把这块硬盘加进去再移除；或者在终端运行 sudo mdutil -E /（要管理员密码）。" +
				"重建要一段时间，这期间搜索不全。别直接删这个文件夹；扫描不会自己做这件事"}}}
}

type modelFolder struct{ dir, name string }

// modelFolders are one folder per model, as layout says (aiTool.models): Hugging Face's models--org--name and
// datasets--org--name, or <publisher>/<model> (LM Studio's).
func modelFolders(root, layout string) []modelFolder {
	var out []modelFolder
	if layout == modelsHuggingFace {
		for _, u := range Children(root) {
			n := filepath.Base(u)
			for _, kind := range []string{"models--", "datasets--"} {
				if strings.HasPrefix(n, kind) {
					out = append(out, modelFolder{u, strings.ReplaceAll(n[len(kind):], "--", "/")})
					break
				}
			}
		}
		return out
	}
	for _, publisher := range Children(root) {
		for _, u := range Children(publisher) {
			if spaceIsDir(u) {
				out = append(out, modelFolder{u, filepath.Base(publisher) + "/" + filepath.Base(u)})
			}
		}
	}
	return out
}

// reachable adds the regular files under dir (links not followed into folders) and those a link under it points to
// inside root (a resolved path), by device and inode with their allocated size: one file several reach counts once.
// Says whether any of it was reached through a link into the shared store (<root>/blobs).
func reachable(dir, root string, seen map[string]int64) bool {
	shared := false
	add := func(st *syscall.Stat_t) { seen[fmt.Sprintf("%d:%d", st.Dev, st.Ino)] = st.Blocks * 512 }
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil {
			return nil
		}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			add(&st)
		case syscall.S_IFLNK:
			target, err := filepath.EvalSymlinks(p)
			if err != nil || !strings.HasPrefix(target, root+"/") {
				return nil
			}
			var t syscall.Stat_t
			if syscall.Stat(target, &t) != nil || t.Mode&syscall.S_IFMT != syscall.S_IFREG {
				return nil
			}
			add(&t)
			if strings.HasPrefix(target, root+"/blobs/") {
				shared = true
			}
		}
		return nil
	})
	return shared
}
