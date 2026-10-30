package app

import "testing"

func TestMergeIgnoresTransientZeroReading(t *testing.T) {
	var st lastKnownTunnelStats
	st = st.merge(1000, 500)
	st = st.merge(0, 0) // one failed read while still connected
	if st.rx != 1000 || st.tx != 500 {
		t.Fatalf("after 0/0 blip: rx=%d tx=%d, want 1000/500", st.rx, st.tx)
	}
	st = st.merge(1010, 510)
	if st.rx != 1010 || st.tx != 510 {
		t.Fatalf("after recovery: rx=%d tx=%d, want 1010/510 (no double count)", st.rx, st.tx)
	}
	// A genuine counter reset (new device) still carries the total over.
	st = st.merge(20, 10)
	if st.rx != 1030 || st.tx != 520 {
		t.Fatalf("after reset: rx=%d tx=%d, want 1030/520", st.rx, st.tx)
	}
}
