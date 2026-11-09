//go:build darwin && cgo

package core

// The FSEvents journal: one of the three places cgo is allowed. Only what journal.go needs: the current event id, the
// journal's identity for a volume, and a replay of the history from an event id up to now.

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation
#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <stdlib.h>

extern void luokeFSEventsGathered(uintptr_t handle, size_t n, char **paths, FSEventStreamEventFlags *flags, FSEventStreamEventId *ids);

static void luoke_fsevents_callback(ConstFSEventStreamRef stream, void *info, size_t n, void *paths,
                                    const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) {
	luokeFSEventsGathered((uintptr_t)info, n, (char **)paths, (FSEventStreamEventFlags *)flags, (FSEventStreamEventId *)ids);
}

typedef struct { FSEventStreamRef stream; dispatch_queue_t queue; } luoke_stream;

// Starts a stream replaying the history of paths after event since; 0 when it cannot.
static int luoke_fsevents_start(uintptr_t handle, char **paths, int n, FSEventStreamEventId since, luoke_stream *out) {
	CFMutableArrayRef roots = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
	for (int i = 0; i < n; i++) {
		CFStringRef s = CFStringCreateWithFileSystemRepresentation(NULL, paths[i]);
		if (s == NULL) { CFRelease(roots); return 0; }
		CFArrayAppendValue(roots, s);
		CFRelease(s);
	}
	FSEventStreamContext ctx = {0, (void *)handle, NULL, NULL, NULL};
	// WatchRoot: a root that is moved or replaced is reported (RootChanged).
	FSEventStreamRef stream = FSEventStreamCreate(NULL, luoke_fsevents_callback, &ctx, roots, since, 0,
	                                              kFSEventStreamCreateFlagWatchRoot);
	CFRelease(roots);
	if (stream == NULL) return 0;
	dispatch_queue_t queue = dispatch_queue_create("luoke-scan.fsevents", NULL);
	FSEventStreamSetDispatchQueue(stream, queue);
	if (!FSEventStreamStart(stream)) {
		FSEventStreamInvalidate(stream);
		FSEventStreamRelease(stream);
		dispatch_release(queue);
		return 0;
	}
	out->stream = stream;
	out->queue = queue;
	return 1;
}

static void luoke_noop(void *ctx) {}

// Stops the stream; a callback still running on its queue finishes first.
static void luoke_fsevents_stop(luoke_stream *s) {
	FSEventStreamStop(s->stream);
	FSEventStreamInvalidate(s->stream);
	FSEventStreamRelease(s->stream);
	dispatch_sync_f(s->queue, NULL, luoke_noop);
	dispatch_release(s->queue);
}

// The journal's UUID for a device, written into buf; 0 when there is none.
static int luoke_fsevents_uuid(dev_t dev, char *buf, int size) {
	CFUUIDRef u = FSEventsCopyUUIDForDevice(dev);
	if (u == NULL) return 0;
	CFStringRef s = CFUUIDCreateString(NULL, u);
	CFRelease(u);
	if (s == NULL) return 0;
	Boolean ok = CFStringGetCString(s, buf, size, kCFStringEncodingUTF8);
	CFRelease(s);
	return ok ? 1 : 0;
}
*/
import "C"

import (
	"os"
	"path/filepath"
	"runtime/cgo"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

func fseventsCurrentID() uint64 { return uint64(C.FSEventsGetCurrentEventId()) }

func fseventsUUID(path string) string {
	var st syscall.Stat_t
	if syscall.Stat(path, &st) != nil {
		return ""
	}
	var buf [64]C.char
	if C.luoke_fsevents_uuid(C.dev_t(st.Dev), &buf[0], C.int(len(buf))) == 0 {
		return ""
	}
	return C.GoString(&buf[0])
}

// fseventsGathered is what the stream's callback gathered: the callback runs on the stream's queue, the result is
// read on ours. Newest id per directory: a busy cache folder changes thousands of times a day, one entry is enough.
type fseventsGathered struct {
	mu               sync.Mutex
	events, subtrees map[string]uint64
	unknown          bool
	latest           uint64
	done             chan struct{}
	once             sync.Once
	// historyOnly: keep only what the journal replayed, not what happened after the replay began.
	historyOnly, past bool
}

//export luokeFSEventsGathered
func luokeFSEventsGathered(handle C.uintptr_t, n C.size_t, paths **C.char, flags *C.FSEventStreamEventFlags, ids *C.FSEventStreamEventId) {
	g := cgo.Handle(handle).Value().(*fseventsGathered)
	count := int(n)
	if count == 0 {
		return
	}
	names, fl, id := unsafe.Slice(paths, count), unsafe.Slice(flags, count), unsafe.Slice(ids, count)
	lost := uint32(C.kFSEventStreamEventFlagRootChanged | C.kFSEventStreamEventFlagEventIdsWrapped |
		C.kFSEventStreamEventFlagKernelDropped | C.kFSEventStreamEventFlagUserDropped)
	historyDone := false
	g.mu.Lock()
	for i := 0; i < count; i++ {
		f, e := uint32(fl[i]), uint64(id[i])
		if f&C.kFSEventStreamEventFlagHistoryDone != 0 {
			historyDone, g.past = true, true
			continue
		}
		if g.past && g.historyOnly {
			continue
		}
		g.latest = max(g.latest, e)
		if f&lost != 0 {
			g.unknown = true
			continue
		}
		p := JournalTrim(C.GoString(names[i]))
		if f&C.kFSEventStreamEventFlagMustScanSubDirs != 0 {
			g.subtrees[p] = max(g.subtrees[p], e)
		} else {
			g.events[p] = max(g.events[p], e)
		}
	}
	g.mu.Unlock()
	if historyDone {
		g.once.Do(func() { close(g.done) })
	}
}

func fseventsReplay(paths []string, since uint64, timeout time.Duration, cancelled func() bool) Changes {
	fseventsSettle(min(timeout, 5*time.Second), cancelled)
	return fseventsStream(paths, since, timeout, cancelled, false)
}

// fseventsSettle waits until what happened before now is in the journal a replay reads. A replay gives back only what
// fseventsd has written down; what it still holds (a file written a moment ago, or seconds ago when it is busy) comes
// at the next replay, a round later (#100: a cache that grew right before a round showed its old size). So: write a
// file in a folder of our own, and replay just that folder until the file is there; fseventsd writes in order, so
// everything before it is there too. Gives up after timeout (the round then goes on as before).
func fseventsSettle(timeout time.Duration, cancelled func() bool) bool {
	dir, err := os.MkdirTemp("", "luoke-scan-fsevents-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	before := fseventsCurrentID()
	if os.WriteFile(filepath.Join(real, "mark"), nil, 0o600) != nil {
		return false
	}
	want := JournalTrim(real)
	until := time.Now().Add(timeout)
	for time.Now().Before(until) && !cancelled() {
		c := fseventsStream([]string{real}, before, time.Until(until), cancelled, true)
		if !c.Unknown && c.Touched(want, before) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func fseventsStream(paths []string, since uint64, timeout time.Duration, cancelled func() bool, historyOnly bool) Changes {
	g := &fseventsGathered{events: map[string]uint64{}, subtrees: map[string]uint64{}, done: make(chan struct{}),
		historyOnly: historyOnly}
	h := cgo.NewHandle(g)
	defer h.Delete()
	cpaths := make([]*C.char, len(paths))
	for i, p := range paths {
		cpaths[i] = C.CString(p)
	}
	defer func() {
		for _, p := range cpaths {
			C.free(unsafe.Pointer(p))
		}
	}()
	var s C.luoke_stream
	if C.luoke_fsevents_start(C.uintptr_t(h), &cpaths[0], C.int(len(cpaths)), C.FSEventStreamEventId(since), &s) == 0 {
		return Everything()
	}
	until := time.Now().Add(timeout)
	finished := false
	for !finished && time.Now().Before(until) && !cancelled() {
		select {
		case <-g.done:
			finished = true
		case <-time.After(250 * time.Millisecond):
		}
	}
	C.luoke_fsevents_stop(&s)
	if !finished {
		return Everything()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return NewChanges(journalEvents(g.events), journalEvents(g.subtrees), g.unknown, g.latest)
}

func journalEvents(m map[string]uint64) []ChangeEvent {
	out := make([]ChangeEvent, 0, len(m))
	for p, id := range m {
		out = append(out, ChangeEvent{ID: id, Path: p})
	}
	return out
}
