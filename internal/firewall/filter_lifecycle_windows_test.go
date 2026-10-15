package firewall

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestTunnelFilterRemovalFailureKeepsTracking(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(fmt.Sprintf("endpoint=%v", endpoint), func(t *testing.T) {
			w := stubWFP(t)
			f := newTestWindowsFirewall()
			f.killSwitchEnabled = true
			ids := []uint64{1, 2}
			w.installed = map[uint64]string{1: "first", 2: "second"}
			w.deleteStatus[2] = 0x80320009
			f.tunnelFilterIDs = map[string][]uint64{"vpn": slices.Clone(ids)}
			f.endpointProtectionFilterIDs = map[string][]uint64{"vpn": slices.Clone(ids)}
			f.endpointProtectionState = map[string][]string{"vpn": {"203.0.113.1:51820"}}
			remove := func() error { return f.RemoveKillSwitchTunnel("vpn") }
			tracked := func() []uint64 { return f.tunnelFilterIDs["vpn"] }
			if endpoint {
				remove = func() error { return f.DisableEndpointProtection("vpn") }
				tracked = func() []uint64 { return f.endpointProtectionFilterIDs["vpn"] }
			}
			if err := remove(); err == nil || !slices.Equal(tracked(), ids) || len(w.installed) != 2 {
				t.Fatalf("failed deletion changed tracking or committed a partial removal: %v, %v, %v", err, tracked(), w.installed)
			}
			delete(w.deleteStatus, 2)
			if err := remove(); err != nil || len(tracked()) != 0 || len(w.installed) != 0 {
				t.Fatalf("retry failed: %v, %v, %v", err, tracked(), w.installed)
			}
		})
	}
}

func TestEndpointReplacementFailurePreservesOldSet(t *testing.T) {
	for _, failure := range []string{"delete", "add", "commit", "invalid endpoint"} {
		t.Run(failure, func(t *testing.T) {
			w := stubWFP(t)
			f := newTestWindowsFirewall()
			if err := f.EnableEndpointProtection("vpn", []string{"203.0.113.1:51820"}); err != nil {
				t.Fatal(err)
			}
			beforeIDs, beforeFilters := slices.Clone(f.endpointProtectionFilterIDs["vpn"]), w.names()
			newEndpoints := []string{"203.0.113.2:51820"}
			switch failure {
			case "delete":
				w.deleteStatus[beforeIDs[0]] = 0x80320009
			case "add":
				fwpmFilterAdd0 = func(uintptr, *fwpmFilter0) (uint64, uint32) { return 0, 0x80320009 }
			case "commit":
				w.commitStatus = 0x80320001
			case "invalid endpoint":
				newEndpoints = []string{"not-an-IP"}
			}
			if err := f.EnableEndpointProtection("vpn", newEndpoints); err == nil {
				t.Fatal("replacement failure hidden")
			}
			if !slices.Equal(f.endpointProtectionFilterIDs["vpn"], beforeIDs) || w.names() != beforeFilters ||
				!slices.Equal(f.endpointProtectionState["vpn"], []string{"203.0.113.1:51820"}) {
				t.Fatal("failed endpoint replacement lost the previous protection")
			}
		})
	}
}

func TestKillSwitchDisableKeepsOtherProtectionInSameSession(t *testing.T) {
	w := stubWFP(t)
	f := newTestWindowsFirewall()
	if err := f.EnableKillSwitch("vpn", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.EnableDNSProtection([]DNSAllow{{Interface: "vpn", Servers: []string{"10.0.0.1"}}, {Servers: []string{"1.1.1.1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := f.EnableEndpointProtection("vpn", []string{"203.0.113.1:51820"}); err != nil {
		t.Fatal(err)
	}
	endpointIDs := slices.Clone(f.endpointProtectionFilterIDs["vpn"])
	close := fwpmEngineClose0
	closes := 0
	fwpmEngineClose0 = func(h uintptr) uint32 { closes++; return close(h) }
	if err := f.DisableKillSwitch(); err != nil {
		t.Fatal(err)
	}
	if closes != 0 || f.sessionHandle != 1 || !slices.Equal(endpointIDs, f.endpointProtectionFilterIDs["vpn"]) {
		t.Fatal("disabling kill switch tore down independent protection")
	}
	if f.IsKillSwitchEnabled() || !f.IsDNSProtectionEnabled() || strings.Contains(w.names(), "Block all (catch-all)") ||
		!strings.Contains(w.names(), "1.1.1.1") || len(f.baseFilterIDs) != 0 || len(f.tunnelFilterIDs) != 0 {
		t.Fatalf("incorrect post-disable policy: %s", w.names())
	}
}

func TestKillSwitchDisableFailurePreservesPreviousPolicy(t *testing.T) {
	for _, failure := range []string{"delete", "DNS add", "commit"} {
		t.Run(failure, func(t *testing.T) {
			w := stubWFP(t)
			f := newTestWindowsFirewall()
			if err := f.EnableKillSwitch("vpn", nil, nil); err != nil {
				t.Fatal(err)
			}
			if err := f.EnableDNSProtection([]DNSAllow{{Interface: "vpn", Servers: []string{"10.0.0.1"}}}); err != nil {
				t.Fatal(err)
			}
			before, base, dns := w.names(), slices.Clone(f.baseFilterIDs), slices.Clone(f.dnsFilterIDs)
			switch failure {
			case "delete":
				w.deleteStatus[base[0]] = 0x80320009
			case "DNS add":
				fwpmFilterAdd0 = func(uintptr, *fwpmFilter0) (uint64, uint32) { return 0, 0x80320009 }
			case "commit":
				w.commitStatus = 0x80320001
			}
			if err := f.DisableKillSwitch(); err == nil || !f.IsKillSwitchEnabled() || w.names() != before ||
				!slices.Equal(base, f.baseFilterIDs) || !slices.Equal(dns, f.dnsFilterIDs) {
				t.Fatalf("failed transition changed policy: %v", err)
			}
		})
	}
}

func TestPinnedDNSFiltersIncludeInterfaceCondition(t *testing.T) {
	stubWFP(t)
	add := fwpmFilterAdd0
	pinned, unpinned := 0, 0
	fwpmFilterAdd0 = func(h uintptr, filter *fwpmFilter0) (uint64, uint32) {
		name := windows.UTF16PtrToString(filter.displayData.name)
		if strings.HasPrefix(name, "Permit DNS") {
			hasInterface := false
			for _, condition := range unsafe.Slice(filter.filterCondition, filter.numFilterConditions) {
				if condition.fieldKey == guidCondIPLocalInterface {
					hasInterface = condition.conditionValue.dataType == dataTypeUint64 && condition.conditionValue.value != 0
				}
			}
			if strings.Contains(name, "1.1.1.1") {
				if hasInterface {
					t.Error("off-tunnel resolver unexpectedly pinned")
				}
				unpinned++
			} else {
				if !hasInterface {
					t.Error("tunnel resolver permit lacks its interface condition")
				}
				pinned++
			}
		}
		return add(h, filter)
	}
	f := newTestWindowsFirewall()
	if err := f.EnableDNSProtection([]DNSAllow{
		{Interface: "vpn", Servers: []string{"10.0.0.1", "2001:db8::53"}},
		{Servers: []string{"1.1.1.1"}},
	}); err != nil {
		t.Fatal(err)
	}
	if pinned != 4 || unpinned != 2 {
		t.Fatalf("unexpected permit counts: pinned=%d unpinned=%d", pinned, unpinned)
	}
}
