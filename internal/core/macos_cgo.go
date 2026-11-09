//go:build darwin && cgo

package core

// Two of the three places this program uses cgo (docs/go-port.md): the keyboard taps the window server knows of, and
// the volume's "available capacity for important usage" (free space as Finder counts it, purgeable space included).
// The third, the FSEvents journal, is in its own file. Neither runs for a fake home: those answer from their fakes.

/*
#cgo LDFLAGS: -framework CoreGraphics -framework CoreFoundation
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>
#include <stdlib.h>

static int luoke_capacity(const char *path, long long *important, long long *total) {
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), true);
	if (url == NULL) return 0;
	int ok = 0;
	CFTypeRef free = NULL, all = NULL;
	if (CFURLCopyResourcePropertyForKey(url, kCFURLVolumeAvailableCapacityForImportantUsageKey, &free, NULL) && free != NULL &&
	    CFURLCopyResourcePropertyForKey(url, kCFURLVolumeTotalCapacityKey, &all, NULL) && all != NULL &&
	    CFGetTypeID(free) == CFNumberGetTypeID() && CFGetTypeID(all) == CFNumberGetTypeID()) {
		ok = CFNumberGetValue((CFNumberRef)free, kCFNumberLongLongType, important) &&
		     CFNumberGetValue((CFNumberRef)all, kCFNumberLongLongType, total);
	}
	if (free != NULL) CFRelease(free);
	if (all != NULL) CFRelease(all);
	CFRelease(url);
	return ok;
}
*/
import "C"

import "unsafe"

func init() {
	KeyboardTaps = cgoKeyboardTaps
	importantCapacity = cgoImportantCapacity
}

// cgoKeyboardTaps are the taps on key down or key up (CGGetEventTapList), each tapping process's program from
// proc_pidpath ("" when it is gone); ok false when the window server cannot be asked (no graphical session).
func cgoKeyboardTaps() ([]EventTap, bool) {
	var count C.uint32_t
	if C.CGGetEventTapList(0, nil, &count) != C.kCGErrorSuccess {
		return nil, false
	}
	if count == 0 {
		return []EventTap{}, true
	}
	list := make([]C.CGEventTapInformation, count)
	if C.CGGetEventTapList(count, &list[0], &count) != C.kCGErrorSuccess {
		return nil, false
	}
	keys := C.CGEventMask(1)<<C.kCGEventKeyDown | C.CGEventMask(1)<<C.kCGEventKeyUp
	out := []EventTap{}
	for _, t := range list[:count] {
		if t.eventsOfInterest&keys == 0 {
			continue
		}
		pid := int32(t.tappingProcess)
		path, _ := ProcPath(pid)
		out = append(out, EventTap{Program: path, ListenOnly: t.options == C.kCGEventTapOptionListenOnly,
			AllApps: t.processBeingTapped == 0, PID: pid})
	}
	return out, true
}

// cgoImportantCapacity is the free space for important usage and the total of the volume path is on.
func cgoImportantCapacity(path string) (int64, int64, bool) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var free, total C.longlong
	if C.luoke_capacity(p, &free, &total) == 0 {
		return 0, 0, false
	}
	return int64(free), int64(total), true
}
