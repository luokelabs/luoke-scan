package service

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// Cleaned is one thing a clean-up took: where it was, where it went (the Trash), and whether it was put back. Every
// move to the Trash is written down as it happens, so "放回" works for any of them until the Trash is emptied.
// Fields in key order: the record is written with sorted keys, as the Swift version did.
type Cleaned struct {
	// Admin: moved out of the system's Library with the user's password; root's now, so not put back from here.
	Admin *bool     `json:"admin,omitempty"`
	At    core.Time `json:"at"`
	// Auto is the AutoKind of something cleaned without a click; nil when the user clicked for it.
	Auto *string `json:"auto,omitempty"`
	// Batch is the plan it was in (p-…), or the automatic clean (auto-…): what one "放回" puts back together.
	Batch  string `json:"batch"`
	Bytes  *int64 `json:"bytes,omitempty"`
	Device int64  `json:"device"`
	ID     string `json:"id"`
	Inode  uint64 `json:"inode"`
	// Original is where it was, its folders' links resolved: where it really was, so it goes back through no link.
	Original   string     `json:"original"`
	Restored   *core.Time `json:"restored,omitempty"`
	RestoredTo *string    `json:"restoredTo,omitempty"`
	Rule       string     `json:"rule"`
	Title      string     `json:"title"`
	// Trashed is where it is in the Trash; nil when it was deleted for good (a cache its tool rebuilds), or when there
	// was nothing before a file this tool wrote (Wrote).
	Trashed *string `json:"trashed,omitempty"`
	// Wrote: a config this tool wrote in its place (改成不跑); putting back takes that one away first.
	Wrote *Wrote `json:"wrote,omitempty"`
}

// cleanLine is one line of the clean-up record: something went to the Trash (trashed, the whole entry) or came back.
type cleanLine struct {
	At    *core.Time `json:"at,omitempty"`
	Entry *Cleaned   `json:"entry,omitempty"`
	ID    *string    `json:"id,omitempty"`
	Op    string     `json:"op"`
	To    *string    `json:"to,omitempty"`
}

// notWritten: the record (or the move it records) did not happen, and why.
type notWritten struct{ reason string }

func (e notWritten) Error() string { return e.reason }

const (
	cleanKeepFor   = 90 * 24 * time.Hour
	cleanCompactAt = 1 << 20
	// markName is the extended attribute that says this tool put something in the Trash (its record's id).
	markName = "ai.luoke.scan.cleaned"
	// AlreadyBack is the note on what was put back before.
	AlreadyBack     = "已经放回过了"
	maxRestoreLines = 10
	absent          = "已经不在了"
)

func encodeLine(v any) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// cleanLog is cleaned.jsonl in the data directory: one JSON object per line and only ever appended to, so processes
// writing at once do not undo each other and a line that cannot be read spoils only itself. Past cleanCompactAt it is
// rewritten without what can no longer be put back and is older than cleanKeepFor; anything still in the Trash stays.
type cleanLog struct{ path string }

// append writes the lines under the file's lock (another process may be compacting); an error when not all got written.
func (l cleanLog) append(lines []cleanLine, now time.Time) error {
	var data []byte
	for _, x := range lines {
		b, err := encodeLine(x)
		if err != nil {
			return err
		}
		data = append(append(data, b...), '\n')
	}
	return l.locked(func() error {
		fd, err := syscall.Open(l.path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return notWritten{err.Error()}
		}
		defer syscall.Close(fd)
		var st syscall.Stat_t
		size := int64(0)
		if syscall.Fstat(fd, &st) == nil {
			size = st.Size
		}
		// A line an earlier failed write cut short is closed off here, so it spoils only itself.
		out := data
		if size > 0 {
			last := make([]byte, 1)
			if n, _ := syscall.Pread(fd, last, size-1); n == 1 && last[0] != '\n' {
				out = append([]byte{'\n'}, data...)
			}
		}
		n, err := syscall.Write(fd, out)
		if n != len(out) {
			why := "只写了一部分"
			if err != nil {
				why = err.Error()
			}
			syscall.Ftruncate(fd, size) // nothing half written stays
			return notWritten{why}
		}
		if syscall.Fstat(fd, &st) == nil && st.Size > cleanCompactAt {
			l.compact(now)
		}
		return nil
	})
}

// load is every entry in the order written, with what came back marked.
func (l cleanLog) load() []Cleaned {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil
	}
	var order []string
	byID := map[string]*Cleaned{}
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		var x cleanLine
		if len(raw) == 0 || json.Unmarshal(raw, &x) != nil {
			continue
		}
		switch x.Op {
		case "trashed":
			// The first line of an id is the one: a line added later (by anyone who can write here) cannot take it over.
			if x.Entry == nil || byID[x.Entry.ID] != nil {
				continue
			}
			e := *x.Entry
			order = append(order, e.ID)
			byID[e.ID] = &e
		case "restored":
			if x.ID == nil || byID[*x.ID] == nil {
				continue
			}
			byID[*x.ID].Restored = x.At
			byID[*x.ID].RestoredTo = x.To
		}
	}
	out := make([]Cleaned, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

// compact rewrites the file without what is done with and older than cleanKeepFor. Called with the lock held.
func (l cleanLog) compact(now time.Time) {
	var data []byte
	for _, e := range l.load() {
		if now.Sub(e.At.Time) >= cleanKeepFor && !newConfigThere(e) { // a config made by 改成不跑: kept while it is there
			if e.Restored != nil || e.Trashed == nil {
				continue
			}
			// The Trash of a disk that is not attached now: still there, as far as anyone can tell.
			if core.Exists(filepath.Dir(*e.Trashed)) {
				if _, ino, _, ok := identity(*e.Trashed); !ok || ino != e.Inode { // a disk attached again may get another device number
					continue
				}
			}
		}
		e := e
		b, err := encodeLine(cleanLine{Op: "trashed", Entry: &e})
		if err != nil {
			return // nothing lost: leave it
		}
		data = append(append(data, b...), '\n')
	}
	tmp := filepath.Join(filepath.Dir(l.path), fmt.Sprintf(".%s.%d", filepath.Base(l.path), os.Getpid()))
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	if os.Rename(tmp, l.path) != nil {
		os.Remove(tmp)
	}
}

func (l cleanLog) locked(body func() error) error {
	fd, err := syscall.Open(l.path+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return notWritten{"清理记录的锁拿不到"}
	}
	defer syscall.Close(fd)
	if syscall.Flock(fd, syscall.LOCK_EX) != nil {
		return notWritten{"清理记录的锁拿不到"}
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return body()
}

// identity is what is at path (not following a link): its device, inode, and whether it is a link.
func identity(path string) (device int64, inode uint64, link bool, ok bool) {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil {
		return 0, 0, false, false
	}
	return int64(st.Dev), st.Ino, st.Mode&syscall.S_IFMT == syscall.S_IFLNK, true
}

// realPath is path with every link resolved; ok false when it is not there.
func realPath(p string) (string, bool) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	if !filepath.IsAbs(r) {
		if r, err = filepath.Abs(r); err != nil {
			return "", false
		}
	}
	return r, true
}

func (s *Service) cleanLog() cleanLog { return cleanLog{filepath.Join(s.Store.Dir, "cleaned.jsonl")} }

// Cleaned is the clean-up record, oldest first.
func (s *Service) Cleaned() []Cleaned { return s.cleanLog().load() }

func (s *Service) trashFolders() []string {
	if s.Config.TrashFolders != nil {
		return s.Config.TrashFolders
	}
	return []string{filepath.Join(s.Config.Context.Home, ".Trash")}
}

// trashFolder is the Trash folder a record's trashed is directly in, spelled as this tool knows it, never as the
// record has it: one of trashFolders (the home's .Trash), or another disk's /Volumes/<name>/.Trashes/<uid>. ok false
// when it is in none, or its name is not a plain one. The record sits in a folder any program of this user can write,
// and putting back runs with Full Disk Access: the record's spelling only picks which known folder, never opened.
func (s *Service) trashFolder(trashed string) (folder, name string, volume, ok bool) {
	parts := strings.Split(trashed, "/")
	if !strings.HasPrefix(trashed, "/") || parts[len(parts)-1] == "" {
		return "", "", false, false
	}
	for _, p := range parts[1:] {
		if p == "" || p == "." || p == ".." {
			return "", "", false, false
		}
	}
	name = parts[len(parts)-1]
	parent := strings.Join(parts[:len(parts)-1], "/")
	for _, f := range s.trashFolders() {
		// The folders above it resolved (/var is /private/var), the Trash folder itself not: a link there is refused
		// when it is opened.
		up, has := realPath(filepath.Dir(f))
		if !has {
			continue
		}
		real := up + "/" + filepath.Base(f)
		if parent == filepath.Clean(f) || parent == real {
			return real, name, false, true
		}
	}
	c := strings.Split(parent, "/")
	if len(c) == 5 && c[0] == "" && c[1] == "Volumes" && c[2] != "" && c[3] == ".Trashes" && c[4] == strconv.Itoa(os.Getuid()) {
		return parent, name, true, true
	}
	return "", "", false, false
}

// protectedPlaces are other apps' data and what macOS keeps behind its privacy settings: putting back runs with Full
// Disk Access, so it puts nothing there (a record could name such a place). Put back from Finder instead.
var protectedPlaces = append([]string{"Library/Containers", "Library/Group Containers"}, core.PrivacyPlaces...)

func (s *Service) protectedPlace(path string) bool {
	rel := core.HomeRelative(path, s.Config.Context.Home)
	if !strings.HasPrefix(rel, "~/") {
		return false
	}
	r := rel[2:]
	for _, p := range protectedPlaces {
		if r == p || strings.HasPrefix(r, p+"/") {
			return true
		}
	}
	for _, part := range strings.Split(r, "/") {
		if strings.HasSuffix(part, ".photoslibrary") {
			return true
		}
	}
	return false
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return toUpper(hex.EncodeToString(b))
}

func (s *Service) entryID(batch, path string) string {
	return "c-" + core.ShortHash(batch, path, core.ISOTime(s.now()), randomID())
}

func strPtr(v string) *string { return &v }

// ident is an item as a check saw it.
type ident struct {
	device int64
	inode  uint64
}

// trashAndRecord moves to the Trash and writes it down. An error when the move failed (nothing written then);
// recorded false when the move happened but the record could not be written (in the Trash; "放回" will not know it).
// expect: the item a check saw; something else in its place now is not moved.
func (s *Service) trashAndRecord(path, batch, rule, title string, bytes *int64, auto AutoKind, expect *ident) (Cleaned, bool, error) {
	dev, ino, link, ok := identity(path)
	if !ok {
		return Cleaned{}, false, notWritten{absent}
	}
	if expect != nil && (expect.device != dev || expect.inode != ino || link) {
		return Cleaned{}, false, notWritten{"已经换成了别的东西"}
	}
	// Where it really is: put back there, no link on the way. A folder that was a link when it went stays resolved.
	original := core.Canonical(filepath.Dir(path)) + "/" + filepath.Base(path)
	moved, err := s.Config.Trash(path)
	if err != nil {
		return Cleaned{}, false, err
	}
	// The move may not say where it put it: found again by what it is.
	if moved == "" {
		moved = s.findInTrash(dev, ino)
	}
	e := Cleaned{ID: s.entryID(batch, path), Batch: batch, At: core.Time{Time: s.now()}, Rule: rule, Title: title,
		Original: original, Device: dev, Inode: ino, Bytes: bytes}
	if auto != "" {
		e.Auto = strPtr(string(auto))
	}
	if moved != "" {
		e.Trashed = strPtr(moved)
		// The mark that it was this tool that put it there, written once it is in the Trash: only a program with Full
		// Disk Access can write there, so another program cannot mark something it wants a record to fetch.
		core.SetXattrNoFollow(moved, markName, []byte(e.ID))
	}
	if s.cleanLog().append([]cleanLine{{Op: "trashed", Entry: &e}}, s.now()) != nil {
		return e, false, nil
	}
	return e, true, nil
}

func (s *Service) findInTrash(device int64, inode uint64) string {
	for _, t := range s.trashFolders() {
		for _, p := range core.Children(t) {
			if d, i, _, ok := identity(p); ok && d == device && i == inode {
				return p
			}
		}
	}
	return ""
}

// recordRemoved writes down something deleted for good (a rebuildable cache): shown in the record, not put back.
func (s *Service) recordRemoved(path, batch, rule, title string, bytes *int64, auto AutoKind) {
	e := Cleaned{ID: s.entryID(batch, path), Batch: batch, At: core.Time{Time: s.now()}, Rule: rule, Title: title,
		Original: path, Bytes: bytes}
	if auto != "" {
		e.Auto = strPtr(string(auto))
	}
	s.cleanLog().append([]cleanLine{{Op: "trashed", Entry: &e}}, s.now())
}

// PutBack is how putting one entry back went.
type PutBack struct {
	Title string
	To    string // where it is now; "" when it was not put back
	Note  string // why not, or that it went under another name
}

// PutBackIDs puts back what ids name: entry ids, or batches (everything one plan or one automatic clean took), newest
// first (undone in the opposite order: a folder before a file that was in it). A batch leaves out malware and what
// starts by itself: those come back only when named on their own. Never over anything: when the original place is
// taken it goes next to it as "名字（放回）". An automatic clean put back turns its kind off (ADR 0016, 10-27).
func (s *Service) PutBackIDs(ids []string) []PutBack {
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	type indexed struct {
		e Cleaned
		i int
	}
	var chosen []indexed
	for i, e := range s.Cleaned() {
		if wanted[e.ID] || wanted[e.Batch] {
			chosen = append(chosen, indexed{e, i})
		}
	}
	sort.SliceStable(chosen, func(a, b int) bool {
		if !chosen[a].e.At.Equal(chosen[b].e.At.Time) {
			return chosen[a].e.At.After(chosen[b].e.At.Time)
		}
		return chosen[a].i > chosen[b].i
	})
	anyTrashed := false
	for _, c := range chosen {
		if c.e.Trashed != nil {
			anyTrashed = true
		}
	}
	var out []PutBack
	against := map[string]bool{}
	type rename struct{ from, to string }
	var renamed []rename // folders of this batch that came back under another name
	for _, c := range chosen {
		e := c.e
		if e.Restored != nil {
			out = append(out, PutBack{Title: e.Title, Note: AlreadyBack})
			continue
		}
		// A cache deleted in the same batch was never in the Trash: nothing to put back, nothing to report.
		if anyTrashed && !wanted[e.ID] && e.Trashed == nil && strings.HasPrefix(e.Rule, "cache.") {
			continue
		}
		if !wanted[e.ID] && (strings.HasPrefix(e.Rule, "malware.") || strings.HasPrefix(e.Rule, "persistence.")) {
			out = append(out, PutBack{Title: e.Title, Note: "报毒的、开机自己运行的不随整批放回；真要放回，单独放它"})
			continue
		}
		place := ""
		for _, r := range renamed {
			if strings.HasPrefix(e.Original, r.from+"/") {
				place = r.to + e.Original[len(r.from):]
				break
			}
		}
		target := e.Original
		if place != "" {
			target = place
		}
		to, why := s.putBackOne(e, place)
		if to == "" {
			out = append(out, PutBack{Title: e.Title, Note: why})
			continue
		}
		if to != target {
			renamed = append(renamed, rename{target, to})
		}
		at := core.Time{Time: s.now()}
		if s.cleanLog().append([]cleanLine{{Op: "restored", ID: strPtr(e.ID), At: &at, To: strPtr(to)}}, at.Time) != nil {
			out = append(out, PutBack{Title: e.Title, To: to, Note: "放回了，但没记进清理记录"})
			continue
		}
		if e.Auto != nil {
			against[*e.Auto] = true
		}
		note := why // what putting back has to say about it (a config changed since stays)
		if note == "" && to != target {
			note = "原来的位置有同名的了，放在旁边：" + filepath.Base(to)
		}
		out = append(out, PutBack{Title: e.Title, To: to, Note: note})
	}
	if len(against) > 0 {
		at := core.Time{Time: s.now()}
		s.mutate(func(st *State) {
			if st.AutoOff == nil {
				st.AutoOff = map[string]core.Time{}
			}
			for k := range against {
				st.AutoOff[k] = at
			}
		})
	}
	return out
}

var restoreID = regexp.MustCompile(`^(c|p|auto)-[0-9A-Za-z:.+_-]+$`)

// restoreTool is scan_restore (luoke-agent#2, 10-27: the [撤销] of protocol §8a, labelled 「放回」): one record or one batch.
func (s *Service) restoreTool(args, meta O) (ToolOutput, error) {
	s.reconcileAdmin()
	id, _ := args["id"].(string)
	if len([]rune(id)) > 80 || !restoreID.MatchString(id) {
		return ToolOutput{}, Fail("invalid", "id 要是清理记录的编号")
	}
	done := s.PutBackIDs([]string{id})
	if len(done) == 0 {
		return ToolOutput{}, Fail("stale", "清理记录里没有这一条（可能已经过了很久）。")
	}
	// Put back now, put back before (a batch clicked again), and not put back: each said as what it is, the ones not
	// put back first, with why.
	var back, before, left []PutBack
	for _, d := range done {
		switch {
		case d.To != "":
			back = append(back, d)
		case d.Note == AlreadyBack:
			before = append(before, d)
		default:
			left = append(left, d)
		}
	}
	var parts []string
	if len(back) > 0 {
		parts = append(parts, fmt.Sprintf("放回了 %d 项", len(back)))
	}
	if len(left) > 0 {
		parts = append(parts, fmt.Sprintf("%d 项没放回", len(left)))
	}
	if len(before) > 0 {
		parts = append(parts, fmt.Sprintf("%d 项之前已经放回过了", len(before)))
	}
	text := strings.Join(parts, "，") + "。"
	// On the round's card, the rest of it stays: the decisions below still wait.
	round := s.roundRedraw(meta)
	waits := round != nil && round.waits
	card := s.answerCard(meta, waits, func(c *Card) {
		c.Text(text)
		var lines []string
		for _, d := range left {
			n := d.Note
			if n == "" {
				n = "没放回"
			}
			lines = append(lines, d.Title+"："+n)
		}
		for _, d := range back {
			if d.Note != "" {
				lines = append(lines, d.Title+"："+d.Note)
			} else if t := friendlyName(d.Title); !contains(lines, t) { // 同一个工具的一串临时文件夹合成一行
				lines = append(lines, t)
			}
		}
		for _, d := range before {
			lines = append(lines, d.Title+"："+AlreadyBack)
		}
		detailed := c.Clone()
		for i, l := range lines {
			if i >= maxRestoreLines {
				break
			}
			detailed.Text(l, true)
		}
		if len(lines) > maxRestoreLines {
			detailed.Text(fmt.Sprintf("等 %d 项，都记在清理记录里", len(lines)), true)
		}
		if round != nil {
			round.body(detailed)
		}
		// A card holds at most 200 components: the round's card goes first, the single lines give way.
		if detailed.Count() <= CardMaxComponents {
			*c = *detailed
		} else if round != nil {
			round.body(c)
		}
	})
	return ToolOutput{Text: text, Card: card, Done: Bool(len(left) == 0 && !waits)}, nil
}

// putBackOne puts one entry back, into place when given (a folder of the same batch came back under another name).
// Where it went, or "" and why not.
func (s *Service) putBackOne(e Cleaned, place string) (string, string) {
	if e.Wrote != nil {
		return s.putBackWrote(e, place)
	}
	return s.putBackTrashed(e, place)
}

// putBackTrashed puts back what went to the Trash.
func (s *Service) putBackTrashed(e Cleaned, place string) (string, string) {
	if e.Trashed == nil {
		switch {
		case strings.HasPrefix(e.Rule, "cache."):
			return "", "当时是直接删的，没进废纸篓（工具用到时会自己重建）"
		case e.Rule == homebrewLinksRule:
			return "", "是失效的链接，直接删的；要再用旧的那套 Homebrew，得重新 brew link"
		}
		return "", "移进废纸篓时没找到它在废纸篓里的位置，请在访达里放回"
	}
	if e.Admin != nil && *e.Admin {
		from := "是从系统目录里移走的，归 root"
		if e.Rule == homebrewRule {
			from = "是从 /usr/local 移走的（那里归系统）"
		}
		return "", from + "：要放回，在访达里把它从废纸篓拖回 " + e.Original + "（会要密码）"
	}
	folder, name, volume, ok := s.trashFolder(*e.Trashed)
	if !ok {
		return "", "记录里说的位置不在废纸篓里，不动它"
	}
	gone := "已经不在废纸篓里了（废纸篓倒过，或被挪走了）"
	sfd := core.OpenNoFollow(folder)
	if sfd < 0 {
		return "", gone
	}
	defer syscall.Close(sfd)
	// The item itself by name, not through a link; the one that went (another disk may come back with another device
	// number), carrying this tool's mark.
	ifd, err := core.Openat(sfd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", gone
	}
	defer syscall.Close(ifd)
	var st syscall.Stat_t
	if syscall.Fstat(ifd, &st) != nil || st.Ino != e.Inode || (!volume && int64(st.Dev) != e.Device) {
		return "", "废纸篓里那个已经不是它了"
	}
	if string(core.Fgetxattr(ifd, markName)) != e.ID {
		return "", "不是螺壳扫描移进废纸篓的，不动它；要放回请在访达里放回"
	}
	original := e.Original
	if place != "" {
		original = place
	}
	if s.protectedPlace(original) {
		return "", "原来的位置是别的应用的数据，螺壳扫描不往那里放；请在访达里放回"
	}
	dfd, why := s.openFolder(filepath.Dir(original))
	if dfd < 0 {
		return "", why
	}
	defer syscall.Close(dfd)
	// RENAME_EXCL against the folders opened above: never over anything, never somewhere else.
	for n := 0; n < 20; n++ {
		to := filepath.Base(original)
		if n > 0 {
			to = besideName(to, n)
		}
		err := core.RenameatxNp(sfd, name, dfd, to, core.RenameExcl)
		if err == nil {
			core.Fremovexattr(ifd, markName)
			return filepath.Join(filepath.Dir(original), to), ""
		}
		switch err {
		case syscall.EEXIST:
			continue
		case syscall.EXDEV:
			return "", "废纸篓和原来的位置不在一个磁盘上，请在访达里放回"
		}
		return "", "没能放回（" + errText(err) + "）"
	}
	return "", "原来的位置旁边同名的太多了"
}

// errText is an error number's text as strerror says it.
func errText(err error) string {
	if e, ok := err.(syscall.Errno); ok {
		return e.Error()
	}
	return err.Error()
}

// besideName: "report.pdf" → "report（放回）.pdf", then "report（放回 2）.pdf".
func besideName(name string, n int) string {
	base, ext := name, ""
	if i := strings.LastIndex(name, "."); i > 0 && i < len(name)-1 {
		base, ext = name[:i], name[i+1:]
	}
	tag := "（放回）"
	if n != 1 {
		tag = fmt.Sprintf("（放回 %d）", n)
	}
	if ext == "" {
		return base + tag
	}
	return base + tag + "." + ext
}

// openFolder is dir, opened from the home or temp folder down one folder at a time without following a link, the
// missing ones made as it goes (0700: only this user); -1 and why when it cannot be. The caller closes it.
func (s *Service) openFolder(dir string) (int, string) {
	fd, why, _ := s.openFolderAt(dir, true)
	return fd, why
}

// openFolderAt is openFolder; create false: a folder not there is not made, and missing says so (-1 then).
func (s *Service) openFolderAt(dir string, create bool) (fd int, why string, missing bool) {
	fd, why = s.openFolderWalk(dir, create, &missing)
	return fd, why, missing
}

func (s *Service) openFolderWalk(dir string, create bool, missing *bool) (int, string) {
	p := filepath.Clean(dir)
	roots := []string{s.Config.Context.Home}
	if s.Config.Context.Tmp != "" {
		roots = append(roots, s.Config.Context.Tmp)
	}
	for _, r := range roots {
		real := core.Canonical(r)
		for _, prefix := range uniq([]string{filepath.Clean(r), real}) {
			if p != prefix && !strings.HasPrefix(p, prefix+"/") {
				continue
			}
			fd, err := syscall.Open(real, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
			if err != nil {
				return -1, "家目录打不开"
			}
			for _, part := range strings.Split(p[len(prefix):], "/") {
				if part == "" {
					continue
				}
				if part == ".." || part == "." {
					syscall.Close(fd)
					return -1, "原来的位置写得不对"
				}
				flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
				next, err := core.Openat(fd, part, flags, 0)
				if err == syscall.ENOENT && !create {
					syscall.Close(fd)
					*missing = true
					return -1, "原来的文件夹不在了"
				}
				if err == syscall.ENOENT {
					if e := core.Mkdirat(fd, part, 0o700); e != nil && e != syscall.EEXIST {
						syscall.Close(fd)
						return -1, "原来的文件夹建不起来（" + errText(e) + "）"
					}
					next, err = core.Openat(fd, part, flags, 0)
				}
				if err != nil {
					why := "原来的文件夹打不开（" + errText(err) + "）"
					if err == syscall.ELOOP || err == syscall.ENOTDIR {
						why = "原来的文件夹现在是个链接，或者不是文件夹了"
					}
					syscall.Close(fd)
					return -1, why
				}
				syscall.Close(fd)
				fd = next
			}
			return fd, ""
		}
	}
	return -1, "原来的位置不在你的家目录或临时目录里"
}
