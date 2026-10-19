//go:build windows

package firewall

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// fakeWFP replaces the WFP transaction/filter calls. The firewall's session
// handle is preset, so ensureSession never opens a real engine.
type fakeWFP struct {
	nextID       uint64
	installed    map[uint64]string // filter ID -> display name
	pending      map[uint64]string // added in the open transaction
	deleted      []uint64          // deleted in the open transaction
	commitStatus uint32
	deleteStatus map[uint64]uint32
}

func stubWFP(t *testing.T) *fakeWFP {
	t.Helper()
	w := &fakeWFP{nextID: 100, installed: map[uint64]string{}, deleteStatus: map[uint64]uint32{}}
	oldLUID := resolveInterfaceLUID
	resolveInterfaceLUID = func(string) (uint64, error) { return 42, nil }
	t.Cleanup(func() { resolveInterfaceLUID = oldLUID })
	oldBegin, oldCommit, oldAbort := fwpmTransactionBegin0, fwpmTransactionCommit0, fwpmTransactionAbort0
	oldAdd, oldDel, oldClose := fwpmFilterAdd0, fwpmFilterDeleteById0, fwpmEngineClose0
	oldOpen, oldProvider, oldSublayer := fwpmEngineOpen0, fwpmProviderAdd0, fwpmSubLayerAdd0
	fwpmEngineOpen0 = func(_ *fwpmSession0, handle *uintptr) uint32 { *handle = 1; return 0 }
	fwpmProviderAdd0 = func(uintptr, *fwpmProvider0) uint32 { return 0 }
	fwpmSubLayerAdd0 = func(uintptr, *fwpmSubLayer0) uint32 { return 0 }
	fwpmTransactionBegin0 = func(uintptr) uint32 {
		w.pending, w.deleted = map[uint64]string{}, nil
		return 0
	}
	fwpmTransactionCommit0 = func(uintptr) uint32 {
		if w.commitStatus != 0 {
			return w.commitStatus
		}
		for _, id := range w.deleted {
			delete(w.installed, id)
		}
		for id, name := range w.pending {
			w.installed[id] = name
		}
		return 0
	}
	fwpmTransactionAbort0 = func(uintptr) uint32 { return 0 }
	fwpmFilterAdd0 = func(_ uintptr, f *fwpmFilter0) (uint64, uint32) {
		w.nextID++
		w.pending[w.nextID] = windows.UTF16PtrToString(f.displayData.name)
		return w.nextID, 0
	}
	fwpmFilterDeleteById0 = func(_ uintptr, id uint64) uint32 {
		if st := w.deleteStatus[id]; st != 0 {
			return st
		}
		if _, ok := w.installed[id]; !ok {
			return fwpErrFilterNotFound
		}
		w.deleted = append(w.deleted, id)
		return 0
	}
	// Closing a dynamic session removes every filter it owns.
	fwpmEngineClose0 = func(uintptr) uint32 { w.installed = map[uint64]string{}; return 0 }
	t.Cleanup(func() {
		fwpmEngineOpen0, fwpmProviderAdd0, fwpmSubLayerAdd0 = oldOpen, oldProvider, oldSublayer
		fwpmTransactionBegin0, fwpmTransactionCommit0, fwpmTransactionAbort0 = oldBegin, oldCommit, oldAbort
		fwpmFilterAdd0, fwpmFilterDeleteById0, fwpmEngineClose0 = oldAdd, oldDel, oldClose
	})
	return w
}

func (w *fakeWFP) names() string {
	var out []string
	for _, n := range w.installed {
		out = append(out, n)
	}
	slices.Sort(out)
	return strings.Join(out, "\n")
}

func newTestWindowsFirewall() *WindowsFirewall {
	return &WindowsFirewall{sessionHandle: 1}
}

// Review M-10: a failed removal transaction must keep the filters tracked
// and the protection reported, so the helper retries instead of recording
// success while port-53 blocks stay installed.
func TestDNSRemovalCommitFailureKeepsFiltersTracked(t *testing.T) {
	w := stubWFP(t)
	f := newTestWindowsFirewall()
	if err := f.EnableDNSProtection([]DNSAllow{{Interface: "WireGuide", Servers: []string{"10.0.0.1"}}}); err != nil {
		t.Fatal(err)
	}
	before := slices.Clone(f.dnsFilterIDs)
	w.commitStatus = 0x80320001
	if err := f.DisableDNSProtection(); err == nil {
		t.Fatal("failed removal reported success")
	}
	if !f.IsDNSProtectionEnabled() || !slices.Equal(f.dnsFilterIDs, before) || len(w.installed) == 0 {
		t.Fatalf("failed removal lost track of installed filters: enabled=%v ids=%v installed=%v",
			f.IsDNSProtectionEnabled(), f.dnsFilterIDs, w.installed)
	}
	w.commitStatus = 0
	if err := f.DisableDNSProtection(); err != nil || f.IsDNSProtectionEnabled() || len(w.installed) != 0 {
		t.Fatalf("retry: err=%v enabled=%v installed=%v", err, f.IsDNSProtectionEnabled(), w.installed)
	}
}

func TestDNSRemovalAbortsOnFailedFilterDelete(t *testing.T) {
	w := stubWFP(t)
	f := newTestWindowsFirewall()
	if err := f.EnableDNSProtection([]DNSAllow{{Interface: "WireGuide", Servers: []string{"10.0.0.1"}}}); err != nil {
		t.Fatal(err)
	}
	w.deleteStatus[f.dnsFilterIDs[0]] = 0x80320009
	if err := f.DisableDNSProtection(); err == nil || !f.IsDNSProtectionEnabled() {
		t.Fatal("a filter that could not be deleted was dropped from tracking")
	}
}

func TestDNSRemovalToleratesAlreadyDeletedFilters(t *testing.T) {
	w := stubWFP(t)
	f := newTestWindowsFirewall()
	if err := f.EnableDNSProtection([]DNSAllow{{Interface: "WireGuide", Servers: []string{"10.0.0.1"}}}); err != nil {
		t.Fatal(err)
	}
	delete(w.installed, f.dnsFilterIDs[0])
	if err := f.DisableDNSProtection(); err != nil || f.IsDNSProtectionEnabled() {
		t.Fatalf("missing filter wedged removal: %v", err)
	}
}

// A failed replacement keeps the previous (installed) set tracked.
func TestDNSReplacementFailureKeepsPreviousSetTracked(t *testing.T) {
	w := stubWFP(t)
	f := newTestWindowsFirewall()
	if err := f.EnableDNSProtection([]DNSAllow{{Interface: "WireGuide", Servers: []string{"10.0.0.1"}}}); err != nil {
		t.Fatal(err)
	}
	before := slices.Clone(f.dnsFilterIDs)
	w.commitStatus = 0x80320001
	if err := f.EnableDNSProtection([]DNSAllow{{Interface: "WireGuide", Servers: []string{"10.9.9.9"}}}); err == nil {
		t.Fatal("failed replacement reported success")
	}
	if !slices.Equal(f.dnsFilterIDs, before) || f.dnsAllow[0].Servers[0] != "10.0.0.1" {
		t.Fatalf("failed replacement changed tracking: ids=%v allow=%+v", f.dnsFilterIDs, f.dnsAllow)
	}
}

// Review M-4 (Windows): DNS permits outrank the kill switch's catch-all and
// are not interface-bound, so an off-tunnel resolver permit must not stay
// installed while the kill switch is on.
func TestKillSwitchNarrowsDNSPermits(t *testing.T) {
	w := stubWFP(t)
	f := newTestWindowsFirewall()
	allow := []DNSAllow{{Servers: []string{"1.1.1.1"}}, {Interface: "WireGuide", Servers: []string{"10.0.0.1"}}}
	if err := f.EnableDNSProtection(allow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.names(), "Permit DNS v4 UDP 1.1.1.1") {
		t.Fatalf("DNS-only mode lost the off-tunnel permit:\n%s", w.names())
	}
	if err := f.EnableKillSwitch("", nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.names(), "1.1.1.1") || !strings.Contains(w.names(), "Permit DNS v4 UDP 10.0.0.1") {
		t.Fatalf("kill switch kept an off-tunnel DNS exception:\n%s", w.names())
	}
	if err := f.EnableDNSProtection(allow); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.names(), "1.1.1.1") {
		t.Fatalf("re-apply under kill switch punched a hole:\n%s", w.names())
	}
	if err := f.DisableKillSwitch(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.names(), "Permit DNS v4 UDP 1.1.1.1") {
		t.Fatalf("off-tunnel permit not restored without kill switch:\n%s", w.names())
	}
}

// Review follow-up: the DNS narrowing commits with the kill switch. When it
// fails, nothing commits — the kill switch is not reported enabled with the
// old off-tunnel exception (weight 15 > catch-all 0) still in force, and the
// previous DNS-only set stays installed and tracked.
func TestKillSwitchNotEnabledWhenDNSNarrowingFails(t *testing.T) {
	failures := map[string]func(w *fakeWFP){
		"permit add fails": func(w *fakeWFP) {
			add := fwpmFilterAdd0
			fwpmFilterAdd0 = func(h uintptr, f *fwpmFilter0) (uint64, uint32) {
				if strings.HasPrefix(windows.UTF16PtrToString(f.displayData.name), "Permit DNS") {
					return 0, 0x80320009
				}
				return add(h, f)
			}
		},
		"stale DNS delete fails": func(w *fakeWFP) {
			for id := range w.installed {
				w.deleteStatus[id] = 0x80320009
			}
		},
		"commit fails": func(w *fakeWFP) { w.commitStatus = 0x80320001 },
	}
	for name, inject := range failures {
		t.Run(name, func(t *testing.T) {
			w := stubWFP(t)
			f := newTestWindowsFirewall()
			if err := f.EnableDNSProtection([]DNSAllow{
				{Servers: []string{"1.1.1.1"}},
				{Interface: "WireGuide", Servers: []string{"10.0.0.1"}},
			}); err != nil {
				t.Fatal(err)
			}
			beforeIDs, beforeFilters := slices.Clone(f.dnsFilterIDs), w.names()
			inject(w)
			if err := f.EnableKillSwitch("", nil, nil); err == nil {
				t.Fatal("kill switch reported enabled although the DNS exception was not removed")
			}
			if f.IsKillSwitchEnabled() || strings.Contains(w.names(), "Block all (catch-all)") {
				t.Fatalf("kill switch committed with the old DNS exception:\n%s", w.names())
			}
			if w.names() != beforeFilters || !slices.Equal(f.dnsFilterIDs, beforeIDs) || !f.IsDNSProtectionEnabled() {
				t.Fatalf("aborted kill switch changed DNS protection: ids=%v\n%s", f.dnsFilterIDs, w.names())
			}
		})
	}
}

// The tunnel permits share that transaction; an abort must not leave
// phantom IDs that make a later AddKillSwitchTunnel skip the tunnel.
func TestAbortedKillSwitchRecordsNoTunnelPermits(t *testing.T) {
	w := stubWFP(t)
	oldLUID := resolveInterfaceLUID
	resolveInterfaceLUID = func(string) (uint64, error) { return 42, nil }
	t.Cleanup(func() { resolveInterfaceLUID = oldLUID })
	f := newTestWindowsFirewall()
	w.commitStatus = 0x80320001
	if err := f.EnableKillSwitch("WireGuide", nil, []string{"203.0.113.1:51820"}); err == nil {
		t.Fatal("commit failure hidden")
	}
	if len(f.tunnelFilterIDs["WireGuide"]) != 0 {
		t.Fatalf("aborted transaction recorded tunnel permits: %v", f.tunnelFilterIDs)
	}
	w.commitStatus = 0
	if err := f.EnableKillSwitch("WireGuide", nil, []string{"203.0.113.1:51820"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.names(), "Permit tunnel") || len(f.tunnelFilterIDs["WireGuide"]) == 0 {
		t.Fatalf("tunnel permit missing after retry:\n%s", w.names())
	}
}
