package helper

import (
	"errors"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

type preflightFirewall struct {
	*pendingTestFirewall
	disables int
}

func (f *preflightFirewall) DisableKillSwitch() error {
	f.disables++
	return f.pendingTestFirewall.DisableKillSwitch()
}

func TestUnsupportedSplitDNSNeverRelaxesKillSwitch(t *testing.T) {
	h := newPendingTestHelper(t)
	f := &preflightFirewall{pendingTestFirewall: dnsFW(h)}
	f.killSwitch = true
	h.firewall = f
	cfg := &domain.WireGuardConfig{Name: "unsupported", Interface: domain.InterfaceConfig{DNS: []string{"10.0.0.53", "~corp.example"}}}
	if err := h.doConnectHeld(cfg); !errors.Is(err, network.ErrSplitDNSUnsupported) {
		t.Fatalf("unsupported DNS error = %v", err)
	}
	if f.disables != 0 || !f.killSwitch || len(h.activeCfgs) != 0 || len(h.manager.ActiveTunnels()) != 0 {
		t.Fatalf("rejected connect changed protection or intent: disables=%d active=%v", f.disables, h.activeCfgs)
	}
}
