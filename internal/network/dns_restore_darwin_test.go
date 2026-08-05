//go:build darwin

package network

import (
	"strings"
	"sync"
	"testing"
)

// Issue #34 regression: a last-tunnel disconnect must restore search
// domains, not just DNS servers — and must cover services the pre-VPN
// snapshot doesn't know about (they appeared mid-session and got tunnel
// DNS from a reapply).
func TestRestoreDNSFromSnapshotRestoresSearchDomains(t *testing.T) {
	var mu sync.Mutex
	var calls [][]string
	origRun := run
	run = func(name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	defer func() { run = origRun }()

	m := NewPlatformManager().(*DarwinManager)
	m.mu.Lock()
	m.dnsActive = true
	// Mid-session service the global snapshot below predates: its original
	// values were captured into the per-manager maps on discovery.
	m.savedDNS["USB Ethernet"] = []string{"192.168.10.1"}
	m.savedSearch["USB Ethernet"] = []string{"lan.local"}
	m.mu.Unlock()

	snap := DNSSnapshot{
		Servers: map[string][]string{
			"Wi-Fi":   {"1.1.1.1"},
			"Ethernet": nil, // was DHCP → must be reset to Empty
		},
		Search: map[string][]string{
			"Wi-Fi": {"corp.example.com"},
		},
	}
	if err := m.RestoreDNSFromSnapshot(snap); err != nil {
		t.Fatalf("RestoreDNSFromSnapshot: %v", err)
	}

	find := func(sub string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range calls {
			if strings.Contains(strings.Join(c, " "), sub) {
				return true
			}
		}
		return false
	}

	for _, want := range []string{
		"-setdnsservers Wi-Fi 1.1.1.1",
		"-setsearchdomains Wi-Fi corp.example.com",
		"-setdnsservers Ethernet Empty",
		"-setsearchdomains Ethernet Empty",
		"-setdnsservers USB Ethernet 192.168.10.1",
		"-setsearchdomains USB Ethernet lan.local",
	} {
		if !find(want) {
			t.Errorf("missing expected restore call containing %q\ncalls: %v", want, calls)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dnsActive {
		t.Error("dnsActive should be false after restore")
	}
}
