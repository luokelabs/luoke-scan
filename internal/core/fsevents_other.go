//go:build !darwin || !cgo

package core

import "time"

// Without FSEvents (another system, or built without cgo) the journal never answers: every incremental check counts
// everything as changed and walks it all, with the same results.

func fseventsCurrentID() uint64 { return 0 }

func fseventsUUID(string) string { return "" }

func fseventsReplay([]string, uint64, time.Duration, func() bool) Changes { return Everything() }
