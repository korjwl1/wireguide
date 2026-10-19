package helper

import (
	"errors"
	"testing"
	"time"
)

type retryRemovalFirewall struct {
	*pendingTestFirewall
	fail  bool
	calls int
}

func (f *retryRemovalFirewall) RemoveKillSwitchTunnel(string) error {
	f.calls++
	if f.fail {
		return errors.New("firewall busy")
	}
	return nil
}

func TestFailedPermitRemovalRetriesWithBackoff(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h)
	f := &retryRemovalFirewall{pendingTestFirewall: dnsFW(h), fail: true}
	f.killSwitch = true
	h.firewall = f
	now := time.Now()
	if err := h.removeKillSwitchPermit("utun4", now); err == nil {
		t.Fatal("initial cleanup error was swallowed")
	}
	h.retryKillSwitchPermitRemovals(now.Add(time.Millisecond))
	if f.calls != 1 {
		t.Fatal("retried before backoff elapsed")
	}
	h.retryKillSwitchPermitRemovals(now.Add(time.Second))
	f.fail = false
	h.retryKillSwitchPermitRemovals(now.Add(2 * time.Second))
	if f.calls != 2 {
		t.Fatal("failed retry did not increase backoff")
	}
	h.retryKillSwitchPermitRemovals(now.Add(3 * time.Second))
	if f.calls != 3 || len(h.permitRemovalRetries) != 0 {
		t.Fatal("successful cleanup left a pending removal")
	}
}

func TestPermitRemovalRetryPreservesReusedLiveInterface(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h)
	f := &retryRemovalFirewall{pendingTestFirewall: dnsFW(h), fail: true}
	f.killSwitch = true
	h.firewall = f
	now := time.Now()
	_ = h.removeKillSwitchPermit("utun4", now)
	stubConnected(t, h, tn{"new-session", "utun4", []string{"10.0.0.1"}})
	h.retryKillSwitchPermitRemovals(now.Add(time.Minute))
	if f.calls != 1 || len(h.permitRemovalRetries) != 0 {
		t.Fatal("obsolete cleanup removed a new session's live permit")
	}
}
