package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func programFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProcessDyldInsertFromTheEnvironment(t *testing.T) {
	me := uint32(os.Getuid())
	shell, tool, other := programFile(t, "shell"), programFile(t, "tool"), programFile(t, "other")
	dir, err := filepath.EvalSymlinks(t.TempDir()) // /private/var/…, also there as /System/Volumes/Data/private/var/…
	if err != nil {
		t.Fatal(err)
	}
	lib := func(rel string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hook, proxy := lib(".cache/hook.dylib"), lib("opt/proxy/libproxy.dylib")
	xcode := lib("Applications/Xcode.app/Contents/Developer/usr/lib/libMainThreadChecker.dylib")
	viaData, viaDots := lib("data/hook2.dylib"), lib("dots/hook3.dylib")
	fifo := filepath.Join(dir, "fifo.dylib")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p := func(pid int32, path string, uid uint32, ago time.Duration) ProcInfo {
		return ProcInfo{PID: pid, PPID: 50, UID: uid, Path: path, Started: now.Add(-ago)}
	}
	env := map[int32][]string{
		10: {"HOME=/x", "DYLD_INSERT_LIBRARIES=" + hook},
		11: {"DYLD_INSERT_LIBRARIES=" + hook + ":" + proxy, "DYLD_INSERT_LIBRARIES=/later/not-read.dylib"},
		12: {"DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib"}, // the system's Guard Malloc
		13: {"DYLD_INSERT_LIBRARIES=" + xcode},
		14: {"DYLD_LIBRARY_PATH=/opt/lib", "XDYLD_INSERT_LIBRARIES=/x.dylib"}, // other variables
		15: {"DYLD_INSERT_LIBRARIES=" + hook},                                 // another user's: not looked at
		16: {"DYLD_INSERT_LIBRARIES=relative.dylib"},
		// spelled to look like the system's: the data volume's mount point, "..": still the user's files
		18: {"A=1", "", "DYLD_INSERT_LIBRARIES=/System/Volumes/Data" + viaData + ":/usr/lib/../.." + viaDots},
		19: {"DYLD_INSERT_LIBRARIES=" + fifo}, // a named pipe: codesign would wait on it
	}
	sigs := map[string]Signature{hook: {Kind: SigAdhoc}, proxy: {Kind: SigDeveloper, Team: "PROXY00000"}, xcode: {Kind: SigApple},
		viaData: {Kind: SigAdhoc}, viaDots: {Kind: SigAdhoc}}
	var read []string
	r := &ProcessRule{PileUp: 20, OrphanAge: 6 * time.Hour,
		Snapshot: func() []ProcInfo {
			return []ProcInfo{p(10, shell, me, time.Hour), p(11, tool, me, 2*time.Hour), p(12, tool, me, 0), p(13, other, me, 0),
				p(14, other, me, 0), p(15, other, me+1, 0), p(16, other, me, 0), p(17, other, me, 0), // 17: not readable
				p(18, other, me, 0), p(19, other, me, 0)}
		},
		LaunchdPIDs: func() (map[int32]bool, bool) { return map[int32]bool{}, true },
		Environment: func(pid int32) ([]string, bool) { e, ok := env[pid]; return e, ok },
		Signature: func(p string) Signature {
			read = append(read, p)
			if s, ok := sigs[p]; ok {
				return s
			}
			return Signature{Kind: SigMissing}
		}}
	got, err := r.Run(&Context{Home: t.TempDir(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Finding{}
	for _, f := range got {
		if f.Rule != "process.dyld-insert" {
			t.Fatalf("other finding: %+v", f)
		}
		by[f.Path] = f
	}
	if len(by) != 6 {
		t.Fatalf("findings: %+v", got)
	}
	h := by[hook]
	if h.Severity != High || h.Verdict != Info || h.Category != CatProcess || h.Key != h.Path ||
		h.Evidence["pids"] != "11,10" || h.Evidence["count"] != "2" || h.Evidence["programs"] != "tool、shell" ||
		h.Evidence["signature"] != "临时签名（没有开发者担保）" ||
		h.Title != "2 个进程启动时带着 DYLD_INSERT_LIBRARIES，要先载入 hook.dylib" {
		t.Fatalf("hook: %+v", h)
	}
	if px := by[proxy]; px.Severity != Medium || px.Title != "进程 11（tool）启动时带着 DYLD_INSERT_LIBRARIES，要先载入 libproxy.dylib" {
		t.Fatalf("proxy: %+v", px)
	}
	if rel := by["relative.dylib"]; rel.Severity != High || rel.Evidence["signature"] != "相对路径，没查签名" {
		t.Fatalf("relative: %+v", rel)
	}
	for _, spelled := range []string{"/System/Volumes/Data" + viaData, "/usr/lib/../.." + viaDots} {
		if f := by[spelled]; f.Severity != High || f.Evidence["signature"] != "临时签名（没有开发者担保）" || f.Evidence["pids"] != "18" {
			t.Fatalf("%s: %+v", spelled, f)
		}
	}
	if f := by[fifo]; f.Severity != High || f.Evidence["signature"] != "不是普通文件，没查签名" {
		t.Fatalf("named pipe: %+v", f)
	}
	for _, p := range read {
		if p == fifo {
			t.Fatal("codesign asked about a named pipe")
		}
	}
}

// The paths are anyone's to write, as many as they like: who signed them is read for ten, the others said so.
func TestProcessDyldInsertReadsTenSignaturesAtMost(t *testing.T) {
	dir := t.TempDir()
	var libs []string
	for i := 0; i < 15; i++ {
		p := filepath.Join(dir, fmt.Sprintf("lib%02d.dylib", i))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		libs = append(libs, p)
	}
	read := 0
	r := &ProcessRule{PileUp: 20, OrphanAge: 6 * time.Hour,
		Snapshot: func() []ProcInfo {
			return []ProcInfo{{PID: 10, PPID: 50, UID: uint32(os.Getuid()), Path: programFile(t, "tool"), Started: time.Now()}}
		},
		LaunchdPIDs: func() (map[int32]bool, bool) { return map[int32]bool{}, true },
		Environment: func(int32) ([]string, bool) {
			return []string{"DYLD_INSERT_LIBRARIES=" + strings.Join(libs, ":")}, true
		},
		Signature: func(string) Signature { read++; return Signature{Kind: SigDeveloper, Team: "T"} }}
	got, _ := r.Run(&Context{Home: t.TempDir(), Now: time.Now()})
	unread := 0
	for _, f := range got {
		if f.Evidence["signature"] == "没查签名" {
			unread++
			if f.Severity != High {
				t.Errorf("not checked yet medium: %+v", f)
			}
		}
	}
	if read != 10 || len(got) != 15 || unread != 5 {
		t.Fatalf("read %d, %d findings, %d not checked", read, len(got), unread)
	}
}

// Without Full Disk Access a library in a guarded folder is not opened to check who signed it; still reported.
func TestProcessDyldInsertLeavesGuardedFoldersUnread(t *testing.T) {
	home := t.TempDir()
	lib := filepath.Join(home, "Downloads/hook.dylib")
	tool := programFile(t, "tool")
	no := false
	read := false
	r := &ProcessRule{PileUp: 20, OrphanAge: 6 * time.Hour,
		Snapshot: func() []ProcInfo {
			return []ProcInfo{{PID: 10, PPID: 50, UID: uint32(os.Getuid()), Path: tool, Started: time.Now()}}
		},
		LaunchdPIDs: func() (map[int32]bool, bool) { return map[int32]bool{}, true },
		Environment: func(int32) ([]string, bool) { return []string{"DYLD_INSERT_LIBRARIES=" + lib}, true },
		Signature:   func(string) Signature { read = true; return Signature{Kind: SigApple} }}
	got, _ := r.Run(&Context{Home: home, Now: time.Now(), FullDiskAccess: &no})
	if read || len(got) != 1 || got[0].Severity != High {
		t.Fatalf("read %v: %+v", read, got)
	}
}

func TestProcessLibrariesFromOddPlacesAndDeleted(t *testing.T) {
	me := uint32(os.Getuid())
	real := func(d string) string { // the kernel's spelling: /private/var/…
		r, err := filepath.EvalSymlinks(d)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	home, tmp := real(t.TempDir()), real(t.TempDir())
	file := func(p string) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tool, server, other, loader := programFile(t, "tool"), programFile(t, "server"), programFile(t, "other"), programFile(t, "loader")
	// an app run from where it was downloaded: macOS runs it from a hidden copy under the temporary folder
	translocated := file(filepath.Join(tmp, "AppTranslocation/0A1B2C3D-0000-4000-8000-000000000000/d/Viewer.app/Contents/MacOS/Viewer"))
	hook, plugin := file(filepath.Join(tmp, "io.example/hook.dylib")), file(filepath.Join(home, "Downloads/plugin.dylib"))
	appleSigned := file(filepath.Join(tmp, "apple-signed.dylib"))
	named := file(filepath.Join(tmp, "io.example/AppTranslocation/hook.dylib")) // only named like it
	libs := map[int32][]LoadedLibrary{
		10: {{Path: hook}, {Path: plugin}, {Path: "/usr/lib/libz.1.dylib"}, {Path: filepath.Join(home, ".local/lib/libfine.dylib")}},
		11: {{Path: hook}},
		12: {{Path: filepath.Join(home, ".local/lib/libold.1.dylib"), Deleted: true}, {Path: "/System/Library/Frameworks/X.framework/X", Deleted: true}},
		13: {{Path: filepath.Join(filepath.Dir(filepath.Dir(translocated)), "Frameworks/Kit.framework/Kit")}}, // its own
		14: {{Path: filepath.Join(home, "lib/libgone.dylib"), Deleted: true}},                                 // its program is gone: process.deleted-binary
		15: {{Path: appleSigned}},
		16: {{Path: named}}, // the same program as 15: only this one counts
		17: {{Path: named}, {Path: hook}},
	}
	sigs := map[string]Signature{hook: {Kind: SigAdhoc}, plugin: {Kind: SigInvalid}, appleSigned: {Kind: SigApple}, named: {Kind: SigAdhoc}}
	read := map[string]int{}
	now := time.Now()
	p := func(pid int32, path string, ago time.Duration) ProcInfo {
		return ProcInfo{PID: pid, PPID: 50, UID: me, Path: path, Started: now.Add(-ago)}
	}
	r := &ProcessRule{PileUp: 20, OrphanAge: 6 * time.Hour,
		Snapshot: func() []ProcInfo {
			return []ProcInfo{p(10, tool, time.Hour), p(11, tool, 2*time.Hour), p(12, server, 0), p(13, translocated, 0),
				p(14, filepath.Join(home, "gone"), 0), p(15, other, 0), p(16, other, 0), p(17, loader, 0)}
		},
		LaunchdPIDs: func() (map[int32]bool, bool) { return map[int32]bool{}, true },
		Environment: func(int32) ([]string, bool) { return nil, false },
		Libraries:   func(pid int32, _ string) ([]LoadedLibrary, bool) { l, ok := libs[pid]; return l, ok },
		Signature:   func(p string) Signature { read[p]++; return sigs[p] }}
	got, err := r.Run(&Context{Home: home, Tmp: tmp, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Finding{}
	for _, f := range got {
		k := f.Key
		if k == "" {
			k = f.Path
		}
		by[f.Rule+" "+k] = f
	}
	if len(got) != 5 || by["process.deleted-binary "+filepath.Join(home, "gone")].Rule == "" {
		t.Fatalf("findings: %+v", got)
	}
	temp := by["process.library-temp "+tool]
	if temp.Severity != High || temp.Verdict != Info || temp.Path != hook ||
		temp.Title != "2 个 tool 进程载入了临时文件夹和下载文件夹里的 2 个库" || temp.Evidence["pids"] != "11,10" ||
		temp.Evidence["libraries"] != hook+"（临时签名（没有开发者担保））；"+plugin+"（签名和文件对不上（签名后被改过））" ||
		temp.Evidence["program"] != tool || temp.Evidence["library_count"] != "2" {
		t.Fatalf("temp: %+v", temp)
	}
	if n := by["process.library-temp "+loader]; n.Severity != Medium || n.Title != "进程 17（loader）载入了临时文件夹里的 2 个库" {
		t.Fatalf("a folder only named AppTranslocation: %+v", n)
	}
	if o := by["process.library-temp "+other]; o.Title != "进程 16（other）载入了临时文件夹里的库 hook.dylib" || o.Evidence["pids"] != "16" {
		t.Fatalf("15 loaded only Apple's: %+v", o)
	}
	old := by["process.library-deleted "+server]
	if old.Severity != Medium || old.Path != server || old.Evidence["libraries"] != filepath.Join(home, ".local/lib/libold.1.dylib") ||
		old.Title != "进程 12（server）载入的库 libold.1.dylib 已经被删掉了，还在用" {
		t.Fatalf("deleted: %+v", old)
	}
	if read[hook] != 1 { // loaded by two programs: read once
		t.Fatalf("signatures read: %v", read)
	}
}

// Who signed the libraries is read for twenty a round at most; the others are said not checked.
func TestProcessLibrariesReadTwentySignaturesAtMost(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var procs []ProcInfo
	libs := map[int32][]LoadedLibrary{}
	for i := 0; i < 5; i++ { // five programs, eight libraries each
		pid := int32(100 + i)
		procs = append(procs, ProcInfo{PID: pid, PPID: 50, UID: uint32(os.Getuid()), Path: programFile(t, fmt.Sprintf("tool%d", i)), Started: time.Now()})
		for j := 0; j < 8; j++ {
			p := filepath.Join(tmp, fmt.Sprintf("p%d/lib%d.dylib", i, j))
			os.MkdirAll(filepath.Dir(p), 0o700)
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			libs[pid] = append(libs[pid], LoadedLibrary{Path: p})
		}
	}
	read := 0
	r := &ProcessRule{PileUp: 20, OrphanAge: 6 * time.Hour,
		Snapshot:    func() []ProcInfo { return procs },
		LaunchdPIDs: func() (map[int32]bool, bool) { return map[int32]bool{}, true },
		Environment: func(int32) ([]string, bool) { return nil, false },
		Libraries:   func(pid int32, _ string) ([]LoadedLibrary, bool) { return libs[pid], true },
		Signature:   func(string) Signature { read++; return Signature{Kind: SigAdhoc} }}
	got, _ := r.Run(&Context{Home: t.TempDir(), Tmp: tmp, Now: time.Now()})
	unread := 0
	for _, f := range got {
		unread += strings.Count(f.Evidence["libraries"], "（没查签名）")
	}
	if read != 20 || len(got) != 5 || unread != 20 {
		t.Fatalf("read %d, %d findings, %d not checked", read, len(got), unread)
	}
}

// The Mac's shared temporary folders count only for this Mac's rule; a user's /var/folders/…/T, not its caches (C).
func TestLibraryPlace(t *testing.T) {
	ctx := &Context{Home: "/Users/x", Tmp: "/var/folders/ab/cd/T/"}
	mac, fake := &ProcessRule{SystemTemp: true}, &ProcessRule{}
	cases := []struct {
		path, mac, fake string
	}{
		{"/tmp/x.dylib", "临时文件夹", ""},
		{"/private/tmp/x.dylib", "临时文件夹", ""},
		{"/private/var/folders/zz/yy/T/_MEI123/libpython.dylib", "临时文件夹", ""},
		{"/private/var/folders/zz/yy/C/com.example/x.dylib", "", ""},
		{"/private/var/folders/ab/cd/T/AppTranslocation/1/d/A.app/Contents/Frameworks/K", "临时文件夹", "临时文件夹"}, // by place only
		{"/tmp/x/AppTranslocation/hook.dylib", "临时文件夹", ""},
		{"/var/folders/ab/cd/T/x.so", "临时文件夹", "临时文件夹"},
		{"/private/var/folders/ab/cd/T/x.so", "临时文件夹", "临时文件夹"}, // the kernel's spelling of the round's Tmp
		{"/Users/x/Downloads/tool/libx.dylib", "下载文件夹", "下载文件夹"},
		{"/Users/x/Downloadsx/libx.dylib", "", ""},
		{"/Users/x/.local/lib/libx.dylib", "", ""},
	}
	for _, c := range cases {
		if got := mac.libraryPlace(ctx, c.path); got != c.mac {
			t.Errorf("this Mac: %s = %q, want %q", c.path, got, c.mac)
		}
		if got := fake.libraryPlace(ctx, c.path); got != c.fake {
			t.Errorf("a fake home: %s = %q, want %q", c.path, got, c.fake)
		}
	}
}
