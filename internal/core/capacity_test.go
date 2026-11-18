package core

import "testing"

func TestMergeCapacity(t *testing.T) {
	give := func(free, total int64, ok bool) func(string) (int64, int64, bool) {
		return func(string) (int64, int64, bool) { return free, total, ok }
	}
	cases := []struct {
		name             string
		important, plain func(string) (int64, int64, bool)
		free, total      int64
		ok               bool
	}{
		{"important usage counts purgeable space", give(80, 1000, true), give(60, 990, true), 80, 1000, true},
		{"0 for important usage is not a full disk", give(0, 1000, true), give(60, 990, true), 60, 1000, true},
		{"less than statfs: statfs", give(40, 1000, true), give(60, 990, true), 60, 1000, true},
		{"really full", give(0, 1000, true), give(0, 990, true), 0, 1000, true},
		{"important usage not known", give(0, 0, false), give(60, 990, true), 60, 990, true},
		{"statfs fails", give(80, 1000, true), give(0, 0, false), 80, 1000, true},
		{"nothing known", give(0, 0, false), give(0, 0, false), 0, 0, false},
	}
	for _, c := range cases {
		free, total, ok := mergeCapacity(c.important, c.plain, "/")
		if free != c.free || total != c.total || ok != c.ok {
			t.Errorf("%s: got %d %d %v, want %d %d %v", c.name, free, total, ok, c.free, c.total, c.ok)
		}
	}
}
