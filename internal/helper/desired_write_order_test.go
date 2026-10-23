package helper

import (
	"testing"
	"time"
)

// Q3 review: persistDesiredState snapshots state under mu/wifiMu but writes
// under desiredMu. A writer without connectMu (SetDNSProtection,
// pendingDesiredCfgs from reconnectFn, withdrawPendingDesired from
// automation) can snapshot before a Disconnect and write after it.
func TestDesiredStateSnapshotFollowsWriteLock(t *testing.T) {
	h := newPendingTestHelper(t, "A")
	h.done = make(chan struct{})
	h.pendingDesired["A"] = struct{}{}
	h.persistDesiredState()
	if got := loadDesiredState(h.dataDir); len(got) != 1 {
		t.Fatalf("setup: %v", got)
	}

	// Writer #1 (e.g. handleSetDNSProtection, no connectMu) gets as far as
	// its snapshot, then waits for desiredMu.
	h.desiredMu.Lock()
	finished := make(chan struct{})
	go func() { h.persistDesiredState(); close(finished) }()
	time.Sleep(100 * time.Millisecond)

	// Writer #2 (handleDisconnect "A", under connectMu) withdraws A and its
	// write wins desiredMu first.
	h.mu.Lock()
	delete(h.pendingDesired, "A")
	h.mu.Unlock()
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{}); err != nil {
		t.Fatal(err)
	}
	h.desiredMu.Unlock()
	<-finished

	h.mu.Lock()
	inMemory := len(h.pendingDesired)
	h.mu.Unlock()
	onDisk := loadDesiredState(h.dataDir)
	t.Logf("in-memory wanted=%d, on-disk wanted=%v", inMemory, onDisk)
	if inMemory == 0 && len(onDisk) > 0 {
		t.Errorf("stale snapshot resurrected %v on disk after the user's Off", onDisk)
	}
}
