package reconnect

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Confirms the failing helper sequence is reachable through real retry slots,
// without requiring OS routes, WireGuard devices or firewall mutation.
func TestAuditDistinctRetrySlotsOverlapFirewallSuspensions(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	var suspended atomic.Int32
	var maxSuspended atomic.Int32
	m, _, _ := newTestMonitor(testConfig(), func(ctx context.Context, name string) error {
		entered <- name
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	m.networkDetector = nil
	m.SetFirewallCallbacks(func() error {
		n := suspended.Add(1)
		for {
			old := maxSuspended.Load()
			if n <= old || maxSuspended.CompareAndSwap(old, n) {
				break
			}
		}
		return nil
	}, func() error { suspended.Add(-1); return nil })
	m.Start()
	defer m.Stop()
	defer close(release)
	m.startReconnectTunnel("alpha", true, nil)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first retry never entered")
	}
	m.startReconnectTunnel("bravo", true, nil)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("second retry could not overlap first")
	}
	if maxSuspended.Load() != 2 {
		t.Fatalf("overlap count=%d", maxSuspended.Load())
	}
	t.Log("real monitor held two successful firewall suspensions concurrently")
}

func TestReconnectPanicResumesFirewallAndReleasesRetrySlot(t *testing.T) {
	var suspended, resumed atomic.Int32
	m, _, _ := newTestMonitor(testConfig(), func(context.Context, string) error { panic("injected reconnect panic") })
	m.networkDetector = nil
	m.SetFirewallCallbacks(func() error { suspended.Add(1); return nil }, func() error { resumed.Add(1); return nil })
	m.Start()
	defer m.Stop()
	m.startReconnectTunnel("alpha", true, nil)
	waitFor(t, 2*time.Second, "panic retry exit", func() bool {
		m.mu.Lock()
		r := m.retries["alpha"]
		m.mu.Unlock()
		if r == nil {
			return suspended.Load() > 0
		}
		select {
		case <-r.done:
			return true
		default:
			return false
		}
	})
	if suspended.Load() != 1 || resumed.Load() != 1 {
		t.Fatalf("suspend=%d resume=%d after panic", suspended.Load(), resumed.Load())
	}
	m.mu.Lock()
	stuck := m.retries["alpha"] != nil
	m.mu.Unlock()
	if stuck {
		t.Fatal("panicked retry still occupies slot and prevents health recovery")
	}
}

func TestFailedSuspendLeavesTransportUpForRetry(t *testing.T) {
	var attempts, disconnects, connects, resumes atomic.Int32
	cfg := testConfig()
	cfg.MaxAttempts = 1
	m, mgr, _ := newTestMonitor(cfg, func(context.Context, string) error { connects.Add(1); return nil })
	mgr.disconnectFn = func() error { disconnects.Add(1); return nil }
	m.networkDetector = nil
	m.SetFirewallCallbacks(func() error { attempts.Add(1); return errors.New("OS refused firewall suspension") }, func() error { resumes.Add(1); return nil })
	m.Start()
	defer m.Stop()
	m.startReconnectTunnel("alpha", true, nil)
	waitFor(t, 2*time.Second, "failed suspension attempt exit", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return attempts.Load() > 0 && m.retries["alpha"] == nil
	})
	if disconnects.Load() != 0 || connects.Load() != 0 || resumes.Load() != 0 {
		t.Fatalf("disconnect=%d connect=%d resume=%d despite failed suspension", disconnects.Load(), connects.Load(), resumes.Load())
	}
}
