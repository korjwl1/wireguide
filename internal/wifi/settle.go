package wifi

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// NegationSettleWindow is how long the network fingerprint must stay
// unchanged before negated Automation rules may act on it. It is longer
// than the observed 4-10 s blank-SSID gaps during a Wi-Fi roam.
const NegationSettleWindow = 15 * time.Second

// NetworkFingerprint reduces the network state to a stable string. It uses
// the canonical gateway MAC and the (sorted) physical subnets rather than
// raw IPs, so IPv6 privacy-address churn doesn't keep resetting the window.
func NetworkFingerprint(ssid, primaryIface, gatewayMAC string, subnets []string) string {
	sorted := append([]string(nil), subnets...)
	sort.Strings(sorted)
	return strings.Join([]string{
		strings.TrimSpace(ssid),
		primaryIface,
		canonicalMAC(gatewayMAC),
		strings.Join(sorted, ","),
	}, "|")
}

// SettleTracker reports whether the network fingerprint has been stable
// for NegationSettleWindow. The clock is injectable for tests.
type SettleTracker struct {
	mu     sync.Mutex
	now    func() time.Time
	window time.Duration
	fp     string
	since  time.Time
	seen   bool
}

// NewSettleTracker builds a tracker using now (time.Now when nil) and
// NegationSettleWindow.
func NewSettleTracker(now func() time.Time) *SettleTracker {
	if now == nil {
		now = time.Now
	}
	return &SettleTracker{now: now, window: NegationSettleWindow}
}

// Observe records the current fingerprint. settled is true once the same
// fingerprint has been observed continuously for the window; otherwise
// remaining is how long until it would settle if nothing changes.
func (t *SettleTracker) Observe(fingerprint string) (settled bool, remaining time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if !t.seen || fingerprint != t.fp {
		t.seen = true
		t.fp = fingerprint
		t.since = now
	}
	elapsed := now.Sub(t.since)
	if elapsed >= t.window {
		return true, 0
	}
	return false, t.window - elapsed
}

// Peek reports what Observe would return for fingerprint without recording
// it. Read-only callers (the GUI's automation preview poll) use it so a
// transient fingerprint they happen to sample cannot restart the window.
func (t *SettleTracker) Peek(fingerprint string) (settled bool, remaining time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.seen || fingerprint != t.fp {
		return false, t.window
	}
	elapsed := t.now().Sub(t.since)
	if elapsed >= t.window {
		return true, 0
	}
	return false, t.window - elapsed
}
