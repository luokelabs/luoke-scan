package service

import (
	"path/filepath"
	"syscall"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// 改成不跑 (luoke-scan#107): one line appended to a package manager's user config so dependencies no longer run
// scripts while installing. Only the user's own config at its known place under the home (never a project's), opened
// one folder at a time without following a link, only while it is still the file the plan saw. The new file is
// written beside it first and swapped in (RENAME_SWAP): a whole config is at its name at every moment. The old one
// then goes to the Trash and is written down with what was written in its place (when it cannot go, the two are
// swapped back and nothing is changed); 「放回」 swaps it back the same way.

// Wrote is the file this tool wrote in place of a config: what it was when written, so putting back moves it only
// while nobody changed it since.
type Wrote struct {
	Device   int64  `json:"device"`
	Inode    uint64 `json:"inode"`
	Modified int64  `json:"modifiedNs"`
	Size     int64  `json:"size"`
}

func wroteOf(st syscall.Stat_t) Wrote {
	return Wrote{Device: int64(st.Dev), Inode: st.Ino, Modified: st.Mtimespec.Nano(), Size: st.Size}
}

// newConfig: an entry of 改成不跑 that made the config where there was none (putting back takes it away again).
func newConfig(e Cleaned) bool {
	return e.Wrote != nil && e.Inode == 0 && e.Trashed == nil
}

// newConfigThere: such an entry not put back, its file still as written (so 「放回」 has something to do).
func newConfigThere(e Cleaned) bool {
	if !newConfig(e) || e.Restored != nil {
		return false
	}
	var st syscall.Stat_t
	return syscall.Lstat(e.Original, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Nlink == 1 &&
		wroteOf(st) == *e.Wrote
}

// scriptsOffItem is the plan item for a finding of the install-scripts rule: its tool's user config (there or not
// yet), only when one appended line does it.
func (s *Service) scriptsOffItem(f core.Finding, key string) *PlanItem {
	tool := f.Evidence["tool"]
	path := core.ScriptsConfigPath(tool, s.Config.Context.Home)
	// Its place is fixed under the home (core.ScriptsConfigPath); the folders on the way are opened without following a
	// link when it is written (openFolder), so a folder not there yet is fine.
	if path == "" || f.Path != path || f.Evidence["append"] == "" || !s.Config.Context.MayLook(path) {
		return nil
	}
	t := Target{Path: path}
	var st syscall.Stat_t
	switch err := syscall.Lstat(path, &st); {
	case core.LinkOnPath(s.Config.Context.Home, path):
		return nil // a folder on the way is a link: not written through
	case err == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Nlink == 1:
		t.Device, t.Inode = int64(st.Dev), st.Ino
	case err == syscall.ENOENT:
		// written new; the plan remembers there was none
	default:
		return nil // a link (symbolic or hard), a folder, unreadable: not changed from here
	}
	return &PlanItem{Key: key, FindingID: s.fid(f), Rule: f.Rule, Category: string(f.Category), Title: f.Title,
		Targets: []Target{t}, Suggested: ChoiceKeep, Options: []string{ChoiceScriptsOff, ChoiceKeep, ChoiceIgnore}, Tool: tool}
}

// scriptsOffPlaces are the user configs this fix may write (and putting back may touch), as this home spells them.
func (s *Service) scriptsOffPlaces() map[string]bool {
	home := s.Config.Context.Home
	out := map[string]bool{}
	for _, p := range []string{filepath.Join(home, ".npmrc"), filepath.Join(home, ".yarnrc.yml"), filepath.Join(home, ".config/uv/uv.toml"),
		filepath.Join(home, ".config/pip/pip.conf"), filepath.Join(home, "Library/Application Support/pip/pip.conf")} {
		out[p] = true
		out[core.Canonical(filepath.Dir(p))+"/"+filepath.Base(p)] = true
	}
	return out
}

// beforeSwap runs just before the new config is swapped in (tests write to the old one there).
var beforeSwap = func() {}

// scriptsOff carries out 改成不跑 for one item; ok, or why not.
func (s *Service) scriptsOff(it PlanItem, plan Plan) (bool, string) {
	home := s.Config.Context.Home
	if len(it.Targets) != 1 {
		return false, "方案不对"
	}
	t := it.Targets[0]
	if want := core.ScriptsConfigPath(it.Tool, home); want == "" || t.Path != want {
		return false, "不是它的用户配置"
	}
	if core.LinkOnPath(home, t.Path) {
		return false, "放它的文件夹路上有链接，不改"
	}
	dir, name := filepath.Dir(t.Path), filepath.Base(t.Path)
	// Opened without making anything: a folder not there yet is made only once the change is judged again.
	dfd, why, missing := s.openFolderAt(dir, false)
	if dfd < 0 && !missing {
		return false, why
	}
	var st syscall.Stat_t
	there := false
	if dfd >= 0 {
		defer syscall.Close(dfd)
		err := core.Fstatat(dfd, name, &st, core.AtSymlinkNoFollow)
		if err != nil && err != syscall.ENOENT {
			return false, "读不了（" + errText(err) + "）"
		}
		there = err == nil
	}
	switch {
	case !there && t.Inode != 0:
		return false, "查过以后被删了，重新查一下再改"
	case there && t.Inode == 0:
		return false, "查过以后有了这个文件，重新查一下再改"
	case there && (st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1):
		return false, "现在是个链接或不是普通文件，不改"
	case there && (int64(st.Dev) != t.Device || st.Ino != t.Inode):
		return false, "已经换成了别的文件，重新查一下再改"
	}
	// What is in it now, and how it was when read: anything written to it after this is not lost (checked below).
	var old []byte
	var read syscall.Stat_t
	mode := uint32(0o600)
	if there {
		if st.Size > 256<<10 {
			return false, "文件太大，不改"
		}
		fd, err := core.Openat(dfd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return false, "打不开（" + errText(err) + "）"
		}
		if syscall.Fstat(fd, &read) != nil || read.Ino != t.Inode || int64(read.Dev) != t.Device {
			syscall.Close(fd)
			return false, "已经换成了别的文件，重新查一下再改"
		}
		old = make([]byte, read.Size+1)
		n, rerr := syscall.Read(fd, old)
		syscall.Close(fd)
		if rerr != nil || int64(n) != read.Size {
			return false, "没读全"
		}
		old = old[:n]
		mode = uint32(read.Mode) & 0o777
	}
	content, ok, why := core.ScriptsOffContent(it.Tool, old, there)
	if !ok {
		return false, why
	}
	if dfd < 0 {
		if dfd, why = s.openFolder(dir); dfd < 0 {
			return false, why
		}
		defer syscall.Close(dfd)
	}
	// The new file, beside the old one under a name of its own.
	tmp := "." + name + ".luoke-scan-" + randomID()[:8]
	written, why := s.writeNew(dfd, tmp, content, mode)
	if why != "" {
		return false, why
	}
	e := Cleaned{ID: s.entryID(plan.ID, t.Path), Batch: plan.ID, At: core.Time{Time: s.now()}, Rule: it.Rule, Title: it.Title}
	note := "" // changed, but something to say
	if !there {
		if err := core.RenameatxNp(dfd, tmp, dfd, name, core.RenameExcl); err != nil {
			core.Unlinkat(dfd, tmp, 0)
			return false, "改的时候有了这个文件，没动它"
		}
	} else {
		// Swapped: the new one at the name, the old one at tmp. Not the file read, or written to since: swapped back.
		beforeSwap()
		if err := core.RenameatxNp(dfd, tmp, dfd, name, core.RenameSwap); err != nil {
			core.Unlinkat(dfd, tmp, 0)
			return false, "没换成（" + errText(err) + "）"
		}
		var was syscall.Stat_t
		if core.Fstatat(dfd, tmp, &was, core.AtSymlinkNoFollow) != nil || was.Ino != t.Inode || int64(was.Dev) != t.Device ||
			was.Size != read.Size || was.Mtimespec != read.Mtimespec || was.Nlink != 1 {
			var back syscall.Stat_t
			if core.RenameatxNp(dfd, tmp, dfd, name, core.RenameSwap) == nil &&
				core.Fstatat(dfd, tmp, &back, core.AtSymlinkNoFollow) == nil && back.Ino == written.Ino {
				core.Unlinkat(dfd, tmp, 0)
			}
			return false, "刚好有程序在改它，没动；重新查一下再改"
		}
		e.Device, e.Inode = t.Device, t.Inode
		moved, back, why := s.trashAside(dfd, dir, tmp, name)
		switch {
		case why == "":
			e.Trashed = strPtr(moved)
			core.SetXattrNoFollow(moved, markName, []byte(e.ID))
		case back:
			// The old one did not go to the Trash and is beside it again: swapped back, so nothing is changed and
			// there is nothing to put back.
			var now syscall.Stat_t
			if core.RenameatxNp(dfd, tmp, dfd, name, core.RenameSwap) == nil &&
				core.Fstatat(dfd, tmp, &now, core.AtSymlinkNoFollow) == nil && now.Ino == written.Ino {
				core.Unlinkat(dfd, tmp, 0)
				return false, why + "，换回了原来那份，没改"
			}
			// Not swapped back (cannot happen short of the disk failing): changed, and written down as such.
			note = "原来那份没能移进废纸篓，留在 " + s.display(filepath.Join(dir, tmp))
		default:
			note = why
		}
	}
	e.Original = core.Canonical(dir) + "/" + name // its folders all there now
	w := wroteOf(written)
	e.Wrote = &w
	if s.cleanLog().append([]cleanLine{{Op: "trashed", Entry: &e}}, s.now()) != nil {
		return true, "改好了，但没记进清理记录：要放回得在访达里打开废纸篓"
	}
	if note != "" {
		return true, "改好了，但" + note
	}
	return true, ""
}

// writeNew writes content as a new file name in the folder open as dfd (mode, dated by this tool's clock: a fake
// home's fixed clock gives the same file every time); what it is, or why not.
func (s *Service) writeNew(dfd int, name string, content []byte, mode uint32) (syscall.Stat_t, string) {
	var st syscall.Stat_t
	fd, err := core.Openat(dfd, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return st, "写不了（" + errText(err) + "）"
	}
	n, werr := syscall.Write(fd, content)
	if werr == nil && n != len(content) {
		werr = syscall.EIO
	}
	if werr == nil {
		werr = syscall.Fchmod(fd, mode)
	}
	if werr == nil {
		tv := syscall.NsecToTimeval(s.now().UnixNano())
		werr = syscall.Futimes(fd, []syscall.Timeval{tv, tv})
	}
	if werr == nil {
		werr = syscall.Fsync(fd)
	}
	if werr == nil {
		werr = syscall.Fstat(fd, &st)
	}
	syscall.Close(fd)
	if werr != nil {
		core.Unlinkat(dfd, name, 0)
		return st, "没写成"
	}
	return st, ""
}

// trashAside moves from (in the folder open as dfd, spelled dir) to the Trash under the name as: through a folder of
// its own beside it, so the Trash shows the config's own name. Where it went; or why not, and whether it is back at
// from (only when even that failed is it left where the reason says).
func (s *Service) trashAside(dfd int, dir, from, as string) (string, bool, string) {
	const failed = "原来那份没能移进废纸篓"
	stage := ".luoke-scan-" + randomID()[:8]
	if err := core.Mkdirat(dfd, stage, 0o700); err != nil {
		return "", true, failed
	}
	sfd, err := core.Openat(dfd, stage, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		core.Unlinkat(dfd, stage, core.AtRemoveDir)
		return "", true, failed
	}
	defer syscall.Close(sfd)
	if err := core.RenameatxNp(dfd, from, sfd, as, core.RenameExcl); err != nil {
		core.Unlinkat(dfd, stage, core.AtRemoveDir)
		return "", true, failed
	}
	held := filepath.Join(dir, stage, as)
	moved, err := s.Config.Trash(held)
	var st syscall.Stat_t
	if err != nil || (moved == "" && syscall.Lstat(held, &st) == nil) {
		// Still in the folder of its own: back beside the config, and that folder gone.
		if core.RenameatxNp(sfd, as, dfd, from, core.RenameExcl) != nil {
			return "", false, failed + "，留在 " + s.display(held)
		}
		core.Unlinkat(dfd, stage, core.AtRemoveDir)
		return "", true, failed
	}
	core.Unlinkat(dfd, stage, core.AtRemoveDir)
	if moved == "" {
		return "", false, "原来那份移进了废纸篓，但不知道在哪"
	}
	return moved, false, ""
}

// putBackWrote: an entry of 改成不跑. The old file is found and checked in the Trash before anything is touched; then,
// while the written one is still as written, the two are swapped (the written one goes to the Trash in its place).
// Written to since: that one stays and the old one comes back beside it. No old one to be found: nothing is touched.
func (s *Service) putBackWrote(e Cleaned, place string) (string, string) {
	if e.Rule != core.InstallScriptsRuleID || place != "" || !s.scriptsOffPlaces()[e.Original] {
		return "", "记录里说的位置不是包管理器的用户配置，不动它"
	}
	name := filepath.Base(e.Original)
	dfd, why := s.openFolder(filepath.Dir(e.Original))
	if dfd < 0 {
		return "", why
	}
	defer syscall.Close(dfd)
	var st syscall.Stat_t
	err := core.Fstatat(dfd, name, &st, core.AtSymlinkNoFollow)
	switch {
	case err != nil && err != syscall.ENOENT:
		return "", "读不了（" + errText(err) + "）"
	}
	present := err == nil
	ours := present && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Nlink == 1 && wroteOf(st) == *e.Wrote
	if e.Inode == 0 && e.Trashed == nil {
		// There was none before: the written one goes, while it is as written.
		switch {
		case ours:
			if _, err := s.Config.Trash(e.Original); err != nil {
				return "", "加的那份没能移进废纸篓（" + err.Error() + "）"
			}
			return e.Original, "改之前没有这个文件，加的那份移到了废纸篓"
		case present:
			return "", "改了以后你又动过这个文件，没动它"
		}
		return "", absent
	}
	if e.Trashed == nil {
		return "", "改之前那份不知道在废纸篓的哪里，改过的那份留着没动；要放回请在访达里找"
	}
	if !ours {
		// Gone, or the user's now: the old one comes back in place, or beside it (never over it).
		to, why := s.putBackTrashed(e, "")
		if to != "" && present {
			return to, "改了以后你又动过这个文件，没换掉它；原来那份放在旁边：" + filepath.Base(to)
		}
		return to, why
	}
	// The old one, checked where it is before anything moves.
	folder, tname, volume, ok := s.trashFolder(*e.Trashed)
	if !ok {
		return "", "记录里说的位置不在废纸篓里，改过的那份留着没动"
	}
	keep := "原来那份已经不在废纸篓里了（废纸篓倒过，或被挪走了），改过的那份留着没动"
	sfd := core.OpenNoFollow(folder)
	if sfd < 0 {
		return "", keep
	}
	defer syscall.Close(sfd)
	ifd, err := core.Openat(sfd, tname, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", keep
	}
	defer syscall.Close(ifd)
	var ist syscall.Stat_t
	if syscall.Fstat(ifd, &ist) != nil || ist.Ino != e.Inode || (!volume && int64(ist.Dev) != e.Device) ||
		string(core.Fgetxattr(ifd, markName)) != e.ID {
		return "", "废纸篓里那个已经不是它了，改过的那份留着没动"
	}
	if err := core.RenameatxNp(sfd, tname, dfd, name, core.RenameSwap); err != nil {
		if err == syscall.EXDEV {
			return "", "废纸篓和原来的位置不在一个磁盘上，改过的那份留着没动；请在访达里放回"
		}
		return "", "没能换回去（" + errText(err) + "），改过的那份留着没动"
	}
	core.Fremovexattr(ifd, markName)
	return e.Original, ""
}
