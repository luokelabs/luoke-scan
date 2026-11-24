package core

import "testing"

// space.low is judged by what can be written now, not by the figure that counts purgeable space (luoke-scan#210).
func TestFreeSpaceJudgedByWhatCanBeWrittenNow(t *testing.T) {
	const gb = int64(1) << 30
	ctx := NewContext(t.TempDir())
	rule := func(free, avail int64, known bool) *FreeSpaceRule {
		return &FreeSpaceRule{MinFreeBytes: 20 * gb, MinFreeFraction: 0.10,
			Volume:    func(string) (int64, int64, bool) { return free, 1000 * gb, true },
			Available: func(string) (int64, bool) { return avail, known },
			Swap:      func() (int64, bool) { return 0, false }}
	}
	// the Finder's figure is roomy, but only 2 GB can be written: reported, with what could be purged
	got, err := rule(300*gb, 2*gb, true).Run(&ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("2 GB to write of 300 GB counted free: %v %v", got, err)
	}
	f := got[0]
	if f.Bytes == nil || *f.Bytes != 2*gb || f.Evidence["purgeable_bytes"] != "319975063552" || f.Evidence["free"] != FormatBytes(2*gb) {
		t.Errorf("bytes %v, evidence %v", f.Bytes, f.Evidence)
	}
	// plenty to write: not reported, whatever the other figure says
	if got, _ := rule(300*gb, 250*gb, true).Run(&ctx); len(got) != 0 {
		t.Errorf("250 GB to write: %v", got)
	}
	// what can be written is not known: the other figure decides, as before
	if got, _ := rule(300*gb, 0, false).Run(&ctx); len(got) != 0 {
		t.Errorf("not known, 300 GB free: %v", got)
	}
	if got, _ := rule(50*gb, 0, false).Run(&ctx); len(got) != 1 || got[0].Evidence["purgeable_bytes"] != "" {
		t.Errorf("not known, 50 GB free: %v", got)
	}
	// more to write than counted free (the system answered less for important usage): no purgeable space
	if got, _ := rule(50*gb, 60*gb, true).Run(&ctx); len(got) != 1 || *got[0].Bytes != 50*gb || got[0].Evidence["purgeable_bytes"] != "" {
		t.Errorf("available above free: %v", got)
	}
}
