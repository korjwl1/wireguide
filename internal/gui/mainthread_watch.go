package gui

import "time"

// mainThreadWatch permits one outstanding heartbeat. It reports once per
// sustained stall, waits for startup's first acknowledgement, and gives the
// UI a fresh grace period after a scheduler/sleep gap.
type mainThreadWatch struct {
	sequence uint64
	queuedAt time.Time
	lastTick time.Time
	started  bool
	reported bool
}

func (w *mainThreadWatch) tick(now time.Time, ack uint64, threshold time.Duration) (ping uint64, stalled bool) {
	if w.sequence > 0 && ack >= w.sequence {
		w.started = true
		w.queuedAt = time.Time{}
		w.reported = false
	}
	gap := !w.lastTick.IsZero() && now.Sub(w.lastTick) > threshold
	w.lastTick = now
	if w.queuedAt.IsZero() {
		w.sequence++
		w.queuedAt = now
		return w.sequence, false
	}
	if gap {
		w.queuedAt = now
		return 0, false
	}
	if w.started && !w.reported && now.Sub(w.queuedAt) >= threshold {
		w.reported = true
		return 0, true
	}
	return 0, false
}
