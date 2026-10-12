package tunnel

import (
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// A watchdog trip with a hook set hands the teardown to the hook and leaves
// the tunnel up for it; the Manager must not disconnect on its own (issue
// #49).
func TestLoopWatchdogTrip_HandsTeardownToHook(t *testing.T) {
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), t.TempDir())
	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	got := make(chan ForcedDisconnect, 1)
	mgr.SetOnForcedDisconnect(func(ev ForcedDisconnect) { got <- ev })

	mgr.loopWatchdogTripped("vpn1", "utun42", tunnelEngine(mgr, "vpn1"), 60<<20)

	select {
	case ev := <-got:
		if ev.TunnelName != "vpn1" || ev.Interface != "utun42" || ev.Reason == "" {
			t.Fatalf("event = %+v", ev)
		}
		if !ev.Current() {
			t.Fatal("Current() = false for the live session")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hook not called")
	}
	if st := tunnelState(mgr, "vpn1"); st != domain.StateConnected {
		t.Fatalf("state = %s; the Manager disconnected by itself", st)
	}
}

// A trip raised for a session that was since replaced (disconnect, then a
// reconnect with a new engine) must report Current() == false, so the
// handler doesn't tear down the new session.
func TestForcedDisconnect_CurrentFalseAfterReconnect(t *testing.T) {
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), t.TempDir())
	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	got := make(chan ForcedDisconnect, 1)
	mgr.SetOnForcedDisconnect(func(ev ForcedDisconnect) { got <- ev })
	mgr.loopWatchdogTripped("vpn1", "utun42", tunnelEngine(mgr, "vpn1"), 60<<20)
	ev := <-got

	if err := mgr.DisconnectTunnel("vpn1"); err != nil {
		t.Fatalf("DisconnectTunnel: %v", err)
	}
	if ev.Current() {
		t.Fatal("Current() = true after the session was torn down")
	}
	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if ev.Current() {
		t.Fatal("Current() = true for a new session on the same tunnel name")
	}
}

// Without a hook the Manager keeps its old behaviour and disconnects the
// tunnel itself.
func TestLoopWatchdogTrip_NoHookDisconnects(t *testing.T) {
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), t.TempDir())
	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	mgr.loopWatchdogTripped("vpn1", "utun42", tunnelEngine(mgr, "vpn1"), 60<<20)

	deadline := time.Now().Add(2 * time.Second)
	for tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		if time.Now().After(deadline) {
			t.Fatalf("state = %s; want disconnected", tunnelState(mgr, "vpn1"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
