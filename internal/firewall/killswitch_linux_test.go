//go:build linux

package firewall

import (
	"errors"
	"os"
	"os/exec"
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
	if len(batches) != 2 || !strings.HasPrefix(batches[1], "add table inet wireguide\ndelete table inet wireguide\n") {
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

// Executed only inside CI's isolated network namespace, with no host rules.
func TestLinuxKillSwitchInKernel(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_NFT") != "1" {
		t.Skip("requires isolated nftables namespace")
	}
	firewall := NewPlatformFirewall().(*LinuxFirewall)
	t.Cleanup(func() { _ = firewall.Cleanup() })
	if err := firewall.EnableKillSwitch("wg0", nil, nil); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("nft", "delete", "table", "inet", "wireguide").CombinedOutput(); err != nil {
		t.Fatalf("external flush: %v %s", err, output)
	}
	if err := firewall.AddKillSwitchTunnel("wg1", nil, nil); err != nil {
		t.Fatalf("replacement after external flush: %v", err)
	}
	if err := firewall.RemoveKillSwitchTunnel("wg0"); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("nft", "list", "table", "inet", "wireguide").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "wg1") || strings.Contains(string(output), "wg0") {
		t.Fatalf("kernel replacement: %v %s", err, output)
	}
}
