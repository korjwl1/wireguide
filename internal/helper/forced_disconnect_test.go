package helper

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// A watchdog trip drops the tunnel from the cached configs and the desired
// state, so neither the wake reconnect nor a crash restore brings the
// looping tunnel back (issue #49).
func TestForcedDisconnectDropsTunnelEverywhere(t *testing.T) {
	h := newPendingTestHelper(t, "vpn1", "vpn2")
	h.activeCfgs["vpn1"] = &domain.WireGuardConfig{Name: "vpn1"}
	h.activeCfgs["vpn2"] = &domain.WireGuardConfig{Name: "vpn2"}
	h.persistDesiredState()

	h.handleForcedDisconnect(tunnel.NewForcedDisconnect("vpn1", "utun9", "routing loop detected", nil))

	if _, ok := h.activeCfgs["vpn1"]; ok {
		t.Fatal("vpn1 still cached; the wake reconnect would bring it back")
	}
	if _, ok := h.activeCfgs["vpn2"]; !ok {
		t.Fatal("vpn2 was dropped too")
	}
	if got := loadDesiredState(h.dataDir); len(got) != 1 || got[0] != "vpn2" {
		t.Fatalf("desired state = %v; want [vpn2]", got)
	}
}

// A trip for a session that is already gone (the user turned it off, or a
// reconnect replaced it) must leave the tunnel alone.
func TestForcedDisconnectStaleSessionIsIgnored(t *testing.T) {
	h := newPendingTestHelper(t, "vpn1")
	h.activeCfgs["vpn1"] = &domain.WireGuardConfig{Name: "vpn1"}
	h.persistDesiredState()

	stale := func() bool { return false }
	h.handleForcedDisconnect(tunnel.NewForcedDisconnect("vpn1", "utun9", "routing loop detected", stale))

	if _, ok := h.activeCfgs["vpn1"]; !ok {
		t.Fatal("vpn1 dropped for a stale trip")
	}
	if got := loadDesiredState(h.dataDir); len(got) != 1 || got[0] != "vpn1" {
		t.Fatalf("desired state = %v; want [vpn1]", got)
	}
}
