package core

import (
	"path/filepath"
	"syscall"
)

// MountInside is a disk mounted at or inside path (its real path), if any: a move to the Trash would take it along,
// and a walk does not look into it. Read with getfsstat into a buffer of our own.
func MountInside(path string) (string, bool) {
	base, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	n, err := syscall.Getfsstat(nil, 2) // MNT_NOWAIT
	if err != nil || n <= 0 {
		return "", false
	}
	list := make([]syscall.Statfs_t, n+8)
	n, err = syscall.Getfsstat(list, 2)
	if err != nil || n <= 0 {
		return "", false
	}
	for _, st := range list[:n] {
		on := cString(st.Mntonname[:])
		// The data volume's own spelling of the same place, should a mount be listed that way.
		for _, b := range []string{base, "/System/Volumes/Data" + base} {
			if on == b || (len(on) > len(b) && on[:len(b)+1] == b+"/") {
				return on, true
			}
		}
	}
	return "", false
}

func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
