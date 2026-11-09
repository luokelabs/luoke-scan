package service

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// AdminApply is the password step (luoke-scan-admin, run as root once root has checked its signature). It trusts
// nothing it reads from the user's folders: the plan names the items, but each is judged again here by the same rule
// as the round (LeftoverRule.SystemLeftovers), as the user (the files are read with the user's rights, as the round
// read them; root only for the moves), and must still be the same root-owned file or folder, reached through no link.
// It moves them into the user's Trash and writes nothing else: what it did goes to standard output, one JSON line per
// item, and the user's own process writes the record (no file of the user's becomes root's).
type AdminApply struct {
	Home string
	UID  uint32
	// Apps whose data may go: what the user's process judged again and gave as arguments. A plan's bundle id outside
	// these is not looked at.
	Apps     map[string]bool
	Library  string
	Receipts string
	AppDirs  []string
	Trash    string // the user's Trash
	Now      time.Time
	Rule     *core.LeftoverRule
	// Homebrew is the Intel Homebrew whose folders may go: set only when the user's process judged it again and asked
	// for it (--homebrew); nil: a plan's Homebrew item is not looked at.
	Homebrew *core.IntelHomebrew
	// Running are the programs running now (as root: every account's).
	Running func() []string
}

// asUser runs body with the user's rights when this is root (their groups, their group, their id); root again after.
// ok false when switching failed: then nothing is judged, nothing moves. (seteuid on macOS is the whole process's;
// this program does one thing at a time.)
func (a AdminApply) asUser(body func()) bool {
	if os.Geteuid() != 0 {
		body()
		return true
	}
	u, err := user.LookupId(strconv.Itoa(int(a.UID)))
	if err != nil {
		return false
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return false
	}
	egid := os.Getegid()
	saved, err := syscall.Getgroups()
	if err != nil {
		return false
	}
	// As many as the user is in (setgroups takes at most NGROUPS_MAX, 16).
	ids, err := u.GroupIds()
	if err != nil {
		return false
	}
	var mine []int
	for _, g := range ids {
		if n, err := strconv.Atoi(g); err == nil {
			mine = append(mine, n)
		}
		if len(mine) == 16 {
			break
		}
	}
	if len(saved) > 16 {
		saved = saved[:16]
	}
	back := func() {
		syscall.Seteuid(0)
		syscall.Setegid(egid)
		syscall.Setgroups(saved)
	}
	if syscall.Setgroups(mine) != nil || syscall.Setegid(gid) != nil || syscall.Seteuid(int(a.UID)) != nil {
		back()
		return false
	}
	defer back()
	body()
	return true
}

// Run moves what the plan's items keys name, each only if the rule still takes it now.
func (a AdminApply) Run(plan Plan, keys map[string]bool) []AdminLine {
	if !plan.Admin {
		return nil
	}
	paths, pathsOK := core.LaunchdPaths(a.Library, a.Home, true) // as root: some job files are root's only
	var components []string
	viewOK := pathsOK && a.asUser(func() { components = core.InstalledComponents(a.Library, a.Receipts, a.Home) })
	var out []AdminLine
	for _, item := range plan.Items {
		if !keys[item.Key] {
			continue
		}
		if item.Rule == homebrewRule {
			var programs []string
			if pathsOK {
				programs = paths
			}
			out = append(out, a.moveHomebrew(item, programs, pathsOK)...)
			continue
		}
		var current []string
		judged := false
		if item.Rule == "leftover.app-data" && item.BundleID != "" && a.Apps[item.BundleID] && viewOK {
			var got []string
			if a.asUser(func() {
				got = a.Rule.SystemLeftovers(item.BundleID, a.Library, a.AppDirs, components, paths, a.Now)
			}) && got != nil {
				current, judged = got, true
			}
		}
		allowed := map[string]bool{}
		for _, p := range current {
			allowed[adminReal(p)] = true
		}
		for _, t := range item.Targets {
			var st syscall.Stat_t
			if err := syscall.Lstat(adminReal(t.Path), &st); err == syscall.ENOENT {
				out = append(out, AdminLine{Key: item.Key, Path: t.Path, Gone: Bool(true)})
				continue
			}
			if !judged {
				out = append(out, AdminLine{Key: item.Key, Path: t.Path, Error: strPtr("现在不算卸载残留了")})
				continue
			}
			if !allowed[adminReal(t.Path)] {
				out = append(out, AdminLine{Key: item.Key, Path: t.Path, Error: strPtr("不在这个应用的残留里")})
				continue
			}
			out = append(out, a.move(t, item.Key, nil))
		}
	}
	return out
}

// moveHomebrew: the Intel Homebrew's folders the item names, only if IntelHomebrew still lets them go now: judged as
// the user, with the launchd jobs and running programs root sees. All of them or none: each is checked through to the
// end (prepare) before any moves. They are the user's (only /usr/local is root's).
func (a AdminApply) moveHomebrew(item PlanItem, programs []string, programsOK bool) []AdminLine {
	var current []string
	judged := false
	if a.Homebrew != nil && programsOK {
		var running []string
		if a.Running != nil {
			running = a.Running()
		}
		var folders []string
		var ok bool
		if a.asUser(func() { folders, _, ok = a.Homebrew.Removable(programs, running, a.UID, a.Now) }) && ok {
			current, judged = folders, true
		}
	}
	allowed := map[string]bool{}
	for _, p := range current {
		allowed[adminReal(p)] = true
	}
	// Every folder that goes must be in this item: a plan naming only some would leave a Homebrew without the rest.
	if judged {
		inItem := map[string]bool{}
		for _, t := range item.Targets {
			inItem[adminReal(t.Path)] = true
		}
		for p := range allowed {
			if !inItem[p] {
				var lines []AdminLine
				for _, t := range item.Targets {
					lines = append(lines, AdminLine{Key: item.Key, Path: t.Path, Error: strPtr("方案里少了这套 Homebrew 的文件夹，重新查一下再来")})
				}
				return lines
			}
		}
	}
	var lines []AdminLine
	var ready []adminReady
	defer func() {
		for _, r := range ready {
			syscall.Close(r.dfd)
		}
	}()
	owner := a.UID
	failed := false
	for _, t := range item.Targets {
		var st syscall.Stat_t
		if err := syscall.Lstat(adminReal(t.Path), &st); err == syscall.ENOENT {
			lines = append(lines, AdminLine{Key: item.Key, Path: t.Path, Gone: Bool(true)})
			continue
		}
		if !judged {
			lines = append(lines, AdminLine{Key: item.Key, Path: t.Path, Error: strPtr("现在不能删：有程序或开机任务在用它，或者最近还在用")})
			failed = true
			continue
		}
		if !allowed[adminReal(t.Path)] {
			lines = append(lines, AdminLine{Key: item.Key, Path: t.Path, Error: strPtr("不是这套 Homebrew 的文件夹")})
			failed = true
			continue
		}
		r, line, ok := a.prepare(t, item.Key, &owner)
		if !ok {
			lines = append(lines, line)
			if line.Error != nil {
				failed = true
			}
			continue
		}
		ready = append(ready, r)
	}
	if failed {
		for _, r := range ready {
			lines = append(lines, AdminLine{Key: item.Key, Path: r.line.Path, Error: strPtr("同一套里有别的文件夹这次动不了，都先不动")})
		}
		return lines
	}
	for _, r := range ready {
		lines = append(lines, a.commit(r))
	}
	return lines
}

// adminReal is a path with its folders' links resolved and the last name left as it is (that one is opened without
// following). realpath(3)'s spelling: /private/var stays /private/var.
func adminReal(path string) string {
	up := filepath.Dir(path)
	if r, ok := realPath(up); ok {
		up = r
	}
	return up + "/" + filepath.Base(path)
}

// numbered: "名字 2", the way Finder names a second item of the same name in the Trash.
func numbered(name string, n int) string {
	base, ext := name, ""
	if i := lastDot(name); i > 0 && i < len(name)-1 {
		base, ext = name[:i], name[i+1:]
	}
	if ext == "" {
		return base + " " + strconv.Itoa(n)
	}
	return base + " " + strconv.Itoa(n) + "." + ext
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

// adminReady is an item checked and ready to go: its folder open (closed by whoever holds it), what it is.
type adminReady struct {
	line  AdminLine
	dfd   int
	name  string
	st    syscall.Stat_t
	bytes int64
}

// move puts one item into the Trash: its folder opened from "/" without following a link, the item itself the one the
// plan saw and owner's (root's unless said), then renamed into the Trash under a name not taken there.
func (a AdminApply) move(t Target, key string, owner *uint32) AdminLine {
	r, line, ok := a.prepare(t, key, owner)
	if !ok {
		return line
	}
	defer syscall.Close(r.dfd)
	return a.commit(r)
}

// prepare is everything move checks before it renames; not ok: the line says why (or that it is gone).
func (a AdminApply) prepare(t Target, key string, owner *uint32) (adminReady, AdminLine, bool) {
	line := AdminLine{Key: key, Path: t.Path}
	no := func(why string) (adminReady, AdminLine, bool) {
		line.Error = strPtr(why)
		return adminReady{}, line, false
	}
	real := adminReal(t.Path)
	name := filepath.Base(real)
	if name == "" || name == "." || name == ".." || name == "/" {
		return no("名字不对")
	}
	dfd := core.OpenNoFollow(filepath.Dir(real))
	if dfd < 0 {
		return no("所在的文件夹打不开，或路上有链接")
	}
	keep := false
	defer func() {
		if !keep {
			syscall.Close(dfd)
		}
	}()
	var st syscall.Stat_t
	if core.Fstatat(dfd, name, &st, core.AtSymlinkNoFollow) != nil {
		line.Gone = Bool(true)
		return adminReady{}, line, false
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return no("现在是一个链接")
	}
	want := a.Rule.SystemOwner
	if owner != nil {
		want = *owner
	}
	if st.Uid != want {
		if owner == nil {
			return no("不是系统的（别的账户的东西不碰）")
		}
		return no("不是你的")
	}
	if int64(st.Dev) != t.Device || st.Ino != t.Inode {
		return no("已经换成了别的东西")
	}
	if _, mounted := core.MountInside(real); mounted {
		return no("里面挂着另一个磁盘")
	}
	// Root's own look at what the user could not see into: written to lately, or another account's things inside, and
	// it stays. Homebrew's packages run to hundreds of thousands of files; an app's data, far fewer.
	limit := 200_000
	if owner != nil {
		limit = 2_000_000
	}
	if why := rootCheck(real, a.UID, a.Now.Add(-a.Rule.Quiet), a.Now, limit); why != "" {
		return no(why)
	}
	keep = true
	return adminReady{line: line, dfd: dfd, name: name, st: st, bytes: core.AllocatedSize(real)}, line, true
}

// commit renames an item prepare checked into the Trash.
func (a AdminApply) commit(r adminReady) AdminLine {
	line := r.line
	trash := adminRealDir(a.Trash)
	tfd := core.OpenNoFollow(trash)
	if tfd < 0 {
		line.Error = strPtr("打不开你的废纸篓")
		return line
	}
	defer syscall.Close(tfd)
	var ts syscall.Stat_t
	if syscall.Fstat(tfd, &ts) != nil || ts.Uid != a.UID {
		line.Error = strPtr("废纸篓不是你的")
		return line
	}
	for n := 0; n < 100; n++ {
		to := r.name
		if n > 0 {
			to = numbered(r.name, n+1)
		}
		err := core.RenameatxNp(r.dfd, r.name, tfd, to, core.RenameExcl)
		if err == nil {
			dev, ino, bytes := int64(r.st.Dev), r.st.Ino, r.bytes
			line.Trashed = strPtr(trash + "/" + to)
			line.Device, line.Inode, line.Bytes = &dev, &ino, &bytes
			return line
		}
		if err == syscall.EEXIST {
			continue
		}
		if err == syscall.EXDEV {
			line.Error = strPtr("和废纸篓不在一个磁盘上")
		} else {
			line.Error = strPtr("没能移进废纸篓（" + errText(err) + "）")
		}
		return line
	}
	line.Error = strPtr("废纸篓里同名的太多了")
	return line
}

// adminRealDir is the Trash folder as adminReal spells a path: its parent resolved.
func adminRealDir(p string) string { return adminReal(p) }

// rootCheck is why root must leave a folder alone after looking into all of it: something in it written to since
// since, or owned by an account other than root and this user, or too much to look through; "" when it may go.
// Anything that cannot be opened or looked at counts against it ("看不进去").
func rootCheck(path string, uid uint32, since, now time.Time, limit int) string {
	recent := func(t syscall.Timespec) bool {
		d := time.Unix(t.Sec, t.Nsec)
		return !d.Before(since) && !d.After(now)
	}
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil {
		return absent
	}
	if recent(st.Mtimespec) {
		return "最近还在用"
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return ""
	}
	n := 0
	why := ""
	var walk func(dir string) bool
	walk = func(dir string) bool {
		f, err := os.Open(dir)
		if err != nil {
			why = "看不进去"
			return false
		}
		names, err := f.Readdirnames(-1)
		f.Close()
		if err != nil && err != io.EOF {
			why = "看不进去"
			return false
		}
		for _, name := range names {
			p := dir + "/" + name
			n++
			if n > limit {
				why = "太大了，核对不完"
				return false
			}
			var s syscall.Stat_t
			if syscall.Lstat(p, &s) != nil {
				why = "看不进去"
				return false
			}
			if s.Uid != 0 && s.Uid != uid {
				why = "里面有别的账户的东西"
				return false
			}
			if recent(s.Mtimespec) {
				why = "最近还在用"
				return false
			}
			if s.Mode&syscall.S_IFMT == syscall.S_IFDIR {
				if syscall.Access(p, 4|1) != nil { // R_OK | X_OK
					why = "看不进去"
					return false
				}
				if !walk(p) {
					return false
				}
			}
		}
		return true
	}
	walk(path)
	return why
}

var adminPlanID = regexp.MustCompile(`^p-[0-9a-f]{12}$`)

// ReadPlan is the user's plan, read as the user: a regular file of theirs, not through a link, not a pipe, not too big.
func (a AdminApply) ReadPlan(id string) (Plan, bool) {
	if !adminPlanID.MatchString(id) {
		return Plan{}, false
	}
	path := filepath.Join(a.Home, ".luoke-scan/plans", id+".json")
	var plan Plan
	ok := false
	a.asUser(func() {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer syscall.Close(fd)
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != a.UID || st.Size >= 4<<20 {
			return
		}
		data := make([]byte, st.Size)
		if n, err := syscall.Read(fd, data); err != nil || int64(n) != st.Size {
			return
		}
		ok = json.Unmarshal(data, &plan) == nil
	})
	return plan, ok
}

// RunAdmin is luoke-scan-admin: root, a real user, their plan; moves; prints. The exit status.
func RunAdmin(planID string, uid uint32, keys, apps []string, homebrew bool) int {
	fail := func(why string) int {
		fmt.Fprintln(os.Stderr, why)
		return 1
	}
	if os.Geteuid() != 0 {
		return fail("要用管理员权限运行（扫描在你点了以后经密码框起它）")
	}
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if uid < 501 || err != nil || u.HomeDir == "" {
		return fail("用户不对")
	}
	// As much room for files as root may have (a low limit set by whoever started it would make the checks skip what
	// they could not open). Nothing inherited beyond the standard three: CloseInherited, first thing in main.
	var lim syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim) == nil {
		if lim.Cur = lim.Max; lim.Cur > 1<<20 {
			lim.Cur = 1 << 20
		}
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
	home := u.HomeDir
	allowed := map[string]bool{}
	for _, a := range apps {
		allowed[a] = true
	}
	step := AdminApply{Home: home, UID: uid, Apps: allowed, Library: "/Library", Receipts: "/var/db/receipts",
		AppDirs: []string{"/Applications", filepath.Join(home, "Applications")}, Trash: filepath.Join(home, ".Trash"),
		Now: time.Now(), Rule: core.NewLeftoverRule(nil, nil).(*core.LeftoverRule),
		Running: func() []string {
			var out []string
			for _, p := range core.ProcSnapshot() {
				out = append(out, p.Path)
			}
			return out
		}}
	if homebrew {
		b := core.NewIntelHomebrew(home)
		step.Homebrew = &b
	}
	if !step.asUser(func() {}) {
		return fail("换不成你的身份，没有动任何东西")
	}
	plan, ok := step.ReadPlan(planID)
	if !ok {
		return fail("找不到这份方案")
	}
	wanted := map[string]bool{}
	for _, k := range keys {
		wanted[k] = true
	}
	for _, line := range step.Run(plan, wanted) {
		if b, err := json.Marshal(line); err == nil {
			os.Stdout.Write(append(b, '\n'))
		}
	}
	return 0
}

// CloseInherited closes every descriptor above the standard three: called first thing, before this program opens any.
func CloseInherited() {
	var lim syscall.Rlimit
	max := 256
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim) == nil && lim.Cur < 1<<16 {
		max = int(lim.Cur)
	} else if lim.Cur >= 1<<16 {
		max = 1 << 16
	}
	for fd := 3; fd < max; fd++ {
		syscall.Close(fd)
	}
}
