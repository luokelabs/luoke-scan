package core

import (
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// A folder the rules cannot name, named: the generate task luoke-scan.identify (prompts/identify.*) is given the
// folder's metadata (where, how big, when it last changed, how many files, their usual extensions, the first few
// names), never what is in a file, and answers whose it probably is and what it holds. The rules decide whether it may
// go; the name is evidence IdentifyNoteKey, shown next to the path, and its kind and sureness decide nothing.
//
// Asked about: a folder that keeps growing (space.growth: the rule says how fast, not whose it is) and an uninstalled
// app's data (leftover.app-data: the rule knows only the bundle id).

// IdentifyTask is luoke-core's name for it; the note is evidence IdentifyNoteKey (reporttext.go).
const IdentifyTask = "luoke-scan.identify"

// identifyWellKnown: folders everyone knows: naming them says nothing.
var identifyWellKnown = aiSet("Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Library", "Public", "Applications")

// IdentifyAsks says whether a finding's folder is named by the model.
func IdentifyAsks(f Finding, home string) bool {
	if len(f.Path) == 0 || f.Path[0] != '/' {
		return false
	}
	switch f.Rule {
	case "space.growth":
		u, h := Standardized(f.Path), Standardized(home)
		if u == h {
			return false
		}
		return !(filepath.Dir(u) == h && identifyWellKnown[filepath.Base(u)])
	case "leftover.app-data":
		return true
	}
	return false
}

// IdentifyLimits bound the look at a folder: names and dates only, no file opened.
type IdentifyLimits struct {
	Entries    int
	Duration   time.Duration
	Top        int
	Extensions int
}

// DefaultIdentifyLimits are the scan's.
func DefaultIdentifyLimits() IdentifyLimits {
	return IdentifyLimits{Entries: 20000, Duration: 2 * time.Second, Top: 6, Extensions: 4}
}

// listEntries is one folder's entries with their names (not following a link to the folder); ok false when it cannot
// be opened.
func listEntries(path string) ([]Entry, bool) {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || !mayOpen(path) {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	names, _ := f.Readdirnames(-1)
	f.Close()
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		var est syscall.Stat_t
		if syscall.Lstat(path+"/"+n, &est) != nil {
			continue
		}
		out = append(out, entryOf(path+"/"+n, &est))
	}
	return out, true
}

// IdentifyInput is what the model is given about the folder at path, shown as place; ok false when it cannot be
// listed. The shape of the evalset's inputs (bench/make_evalsets.py): 路径, 大小, 最后改动, 文件数, 常见扩展名, 前几项. A
// folder with more than limits.Entries entries gives the count it got to. bytes nil: what the walk adds up.
func IdentifyInput(path, place string, bytes *int64, now time.Time, limits IdentifyLimits) (Value, bool) {
	first, ok := listEntries(path)
	if !ok {
		return Value{}, false
	}
	deadline := time.Now().Add(limits.Duration)
	files, seen := 0, 0
	var total int64
	var newest *time.Time
	exts := map[string]int{}
	Tree(path, func(Entry) bool { return true }, func(e Entry) bool {
		seen++
		if !e.IsDir && !e.IsLink && e.Name != ".DS_Store" {
			files++
			total += e.Bytes
			exts[aiLower(aiNSExt(e.Name))]++
		}
		if !e.Modified.After(now) && (newest == nil || e.Modified.After(*newest)) {
			m := e.Modified
			newest = &m
		}
		return seen < limits.Entries && (seen%500 != 0 || time.Now().Before(deadline))
	})
	shown := func(n string) string { return ReviewVisible(n, 60) }
	var names []string
	for _, e := range first {
		if e.Name != ".DS_Store" {
			names = append(names, e.Name)
		}
	}
	sort.Strings(names)
	var top []string
	for i, n := range names {
		if i >= limits.Top {
			break
		}
		top = append(top, shown(n))
	}
	if len(top) < limits.Top {
		folders := append([]Entry(nil), first...)
		sort.SliceStable(folders, func(i, j int) bool { return folders[i].Name < folders[j].Name })
		for _, e := range folders {
			if !e.IsDir || e.IsLink {
				continue
			}
			sub, _ := listEntries(filepath.Join(path, e.Name))
			var subNames []string
			for _, s := range sub {
				if s.Name != ".DS_Store" {
					subNames = append(subNames, s.Name)
				}
			}
			sort.Strings(subNames)
			for _, s := range subNames {
				if len(top) >= limits.Top {
					break
				}
				top = append(top, shown(e.Name)+"/"+shown(s))
			}
			if len(top) >= limits.Top {
				break
			}
		}
	}
	type count struct {
		ext string
		n   int
	}
	var counted []count
	for k, n := range exts {
		counted = append(counted, count{k, n})
	}
	sort.Slice(counted, func(i, j int) bool {
		if counted[i].n != counted[j].n {
			return counted[i].n > counted[j].n
		}
		return counted[i].ext < counted[j].ext
	})
	var usual []Value
	for i, c := range counted {
		if i >= limits.Extensions {
			break
		}
		usual = append(usual, VStr(shown(c.ext)))
	}
	var topValues []Value
	for _, t := range top {
		topValues = append(topValues, VStr(t))
	}
	size := total
	if bytes != nil {
		size = *bytes
	}
	changed := "?"
	if newest != nil {
		changed = ISODay(*newest)
	} else if m, ok := Modified(path); ok {
		changed = ISODay(m)
	}
	return VObj(Field{"路径", VStr(shown(place))}, Field{"大小", VStr(FormatBytes(size))}, Field{"最后改动", VStr(changed)},
		Field{"文件数", VInteger(int64(files))}, Field{"常见扩展名", VList(usual...)}, Field{"前几项", VList(topValues...)}), true
}

// FolderAnswer is the model's answer about a folder.
type FolderAnswer struct {
	Name, What, Kind string
	Sure             bool
}

var (
	identifyKinds = aiSet("cache", "app-data", "user-data", "logs", "tool", "build", "unknown")
	// identifyDeleteAdvice: advice on deleting, which the task must not give (bench/run_eval.py's DELETE_ADVICE).
	identifyDeleteAdvice = icuCS(`(可以|可|能|建议|不要|别|不能|不可|放心|无需|不用|随时)(直接)?(删|清理|清掉|移到废纸篓)|删(了|掉)(就)?(吧|好了)`)
	identifyNotSure      = icuCI(`^\s*(不确定|未知|unknown)`)
)

// IdentifyAnswer is the model's answer when it is what the task asks for (prompts/identify.schema.json).
func IdentifyAnswer(raw string) (FolderAnswer, bool) {
	obj, ok := answerObject(WithoutThinking(raw), "name", "what", "kind", "sure")
	if !ok {
		return FolderAnswer{}, false
	}
	name, _ := obj.Get("name")
	what, _ := obj.Get("what")
	kind, _ := obj.Get("kind")
	sure, _ := obj.Get("sure")
	if name.Kind != VString || what.Kind != VString || kind.Kind != VString || sure.Kind != VBool || !identifyKinds[kind.Str] ||
		scalars(name.Str) > 40 || scalars(what.Str) > 60 {
		return FolderAnswer{}, false
	}
	return FolderAnswer{Name: aiTrimWSNL(name.Str), What: aiTrimWSNL(what.Str), Kind: kind.Str, Sure: sure.Bool}, true
}

// IdentifyNote is the line shown next to the path; ok false unless it is a sure name, without advice on deleting, an
// address or a command.
func IdentifyNote(a FolderAnswer) (string, bool) {
	both := a.Name + "|" + a.What
	if !a.Sure || a.Kind == "unknown" || a.Name == "" || identifyNotSure.has(a.Name) || identifyDeleteAdvice.has(both) ||
		explainCommand.has(both) || hasAddress(both) {
		return "", false
	}
	note := "本机模型认的：" + aiClean(a.Name, 40)
	if a.What != "" {
		note += "（" + aiClean(a.What, 60) + "）"
	}
	return note, true
}
