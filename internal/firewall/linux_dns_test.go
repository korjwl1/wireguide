//go:build linux

package firewall

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run only in an isolated Linux network namespace with CAP_NET_ADMIN.
func TestLinuxDNSRulesInKernel(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_NFT") != "1" {
		t.Skip("requires isolated nftables namespace")
	}
	f := NewPlatformFirewall().(*LinuxFirewall)
	t.Cleanup(func() { _ = f.Cleanup() })
	allow := []DNSAllow{{Interface: "wg-test0", Servers: []string{"10.0.0.1"}}, {Servers: []string{"1.1.1.1"}}}
	for range 2 {
		if err := f.EnableDNSProtection(allow); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("nft", "list", "table", "inet", "wireguide_dns").CombinedOutput()
	if err != nil {
		t.Fatalf("list: %v %s", err, out)
	}
	rules := string(out)
	if strings.Count(rules, "ip daddr 1.1.1.1 udp dport 53 accept") != 1 ||
		strings.Count(rules, "udp dport 53 oifname \"wg-test0\" accept") != 1 ||
		strings.Count(rules, "udp dport 53 drop") != 1 {
		t.Fatalf("kernel rule set duplicated or lost resolver permits: %s", rules)
	}
	if err := f.DisableDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Command("nft", "list", "table", "inet", "wireguide_dns").CombinedOutput(); err == nil {
		t.Fatal("disable left the kernel DNS table installed")
	}
}

func TestLinuxDNSDeleteFailureRetainsStateAndCanRetry(t *testing.T) {
	original := nftDeleteDNSTable
	t.Cleanup(func() { nftDeleteDNSTable = original })
	nftDeleteDNSTable = func() ([]byte, error) { return []byte("Operation not permitted"), errors.New("exit 1") }
	f := &LinuxFirewall{dnsProtectionEnabled: true}
	if err := f.DisableDNSProtection(); err == nil || !f.IsDNSProtectionEnabled() {
		t.Fatal("failed delete was recorded as success")
	}
	if err := f.EnableDNSProtection(nil); err == nil || !f.IsDNSProtectionEnabled() {
		t.Fatal("empty apply hid failed delete")
	}
	nftDeleteDNSTable = func() ([]byte, error) { return nil, nil }
	if err := f.DisableDNSProtection(); err != nil || f.IsDNSProtectionEnabled() {
		t.Fatalf("delete retry: %v", err)
	}
}

func TestLinuxCrashRecoveryRemovesStaleDNSTableWithoutJournal(t *testing.T) {
	original := nftDeleteDNSTable
	originalFlush := nftFlush
	nftFlush = func() error { return nil }
	t.Cleanup(func() { nftFlush = originalFlush })
	t.Cleanup(func() { nftDeleteDNSTable = original })
	calls := 0
	nftDeleteDNSTable = func() ([]byte, error) { calls++; return nil, nil }
	f := &LinuxFirewall{}
	if !f.RecoverFromCrash() || calls != 1 {
		t.Fatal("crash recovery left the kernel DNS table behind")
	}
}
