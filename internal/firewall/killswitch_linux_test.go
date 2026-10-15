//go:build linux

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestLinuxKillSwitchReplacementIsOneTransactionAndFailureKeepsModel(t *testing.T) {
	oldApply, oldFlush := nftApply, nftFlush
	t.Cleanup(func() { nftApply, nftFlush = oldApply, oldFlush })
	var batches []string
	fail := false
	nftApply = func(rules string) error {
		batches = append(batches, rules)
		if fail {
			return errors.New("replace failed")
		}
		return nil
	}
	nftFlush = func() error { t.Fatal("replacement flushed the live blockade separately"); return nil }
	f := NewPlatformFirewall().(*LinuxFirewall)
	if err := f.EnableKillSwitch("wg0", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.AddKillSwitchTunnel("wg1", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || !strings.HasPrefix(batches[1], "delete table inet wireguide\n") {
		t.Fatalf("replacement not atomic: %v", batches)
	}
	fail = true
	if err := f.RemoveKillSwitchTunnel("wg0"); err == nil {
		t.Fatal("replacement failure hidden")
	}
	if _, ok := f.killSwitchTunnels["wg0"]; !ok {
		t.Fatal("failed transaction changed applied model")
	}
}

func TestLinuxKillSwitchDeleteFailureRetainsStateAndRetries(t *testing.T) {
	old := nftFlush
	t.Cleanup(func() { nftFlush = old })
	fail := true
	nftFlush = func() error {
		if fail {
			return errors.New("permission denied")
		}
		return nil
	}
	f := &LinuxFirewall{killSwitchEnabled: true}
	if err := f.DisableKillSwitch(); err == nil || !f.IsKillSwitchEnabled() {
		t.Fatal("failed deletion discarded applied state")
	}
	fail = false
	if err := f.DisableKillSwitch(); err != nil || f.IsKillSwitchEnabled() {
		t.Fatal("successful deletion not committed")
	}
}

func TestLinuxRecoveryRemovesStaleKillSwitch(t *testing.T) {
	oldFlush, oldDNS := nftFlush, nftDeleteDNSTable
	t.Cleanup(func() { nftFlush, nftDeleteDNSTable = oldFlush, oldDNS })
	deleted := false
	nftFlush = func() error { deleted = true; return nil }
	nftDeleteDNSTable = func() ([]byte, error) { return nil, nil }
	f := NewPlatformFirewall().(*LinuxFirewall)
	if !f.RecoverFromCrash() || !deleted {
		t.Fatal("startup recovery left stale kill switch")
	}
}
