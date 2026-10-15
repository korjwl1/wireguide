//go:build darwin

package network

import (
	"errors"
	"fmt"
	"sync"
)

// ResetDNSToSystemDefault clears DNS overrides on every network service
// back to DHCP-provided defaults. Used by crash recovery when the process
// has no memory of the pre-crash DNS state. Parallel across services.
func (m *DarwinManager) ResetDNSToSystemDefault() error {
	servers, search := map[string][]string{}, map[string][]string{}
	for _, svc := range getAllNetworkServices() {
		servers[svc] = nil
		search[svc] = nil
	}
	return restoreServiceDNS(servers, search)
}

// restoreServiceDNS retains every write failure; a partial restore is retryable.
func restoreServiceDNS(servers, search map[string][]string) error {
	errs := make(chan error, len(servers)+len(search))
	var wg sync.WaitGroup
	apply := func(option string, values map[string][]string) {
		for svc, values := range values {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if len(values) == 0 {
					values = []string{"Empty"}
				}
				if err := run("networksetup", append([]string{option, svc}, values...)...); err != nil {
					errs <- fmt.Errorf("%s %s: %w", option, svc, err)
				}
			}()
		}
	}
	apply("-setdnsservers", servers)
	apply("-setsearchdomains", search)
	wg.Wait()
	close(errs)
	var failures []error
	for err := range errs {
		failures = append(failures, err)
	}
	flushDNSCache()
	return errors.Join(failures...)
}

// RestoreDNS restores original DNS for every service we touched. Parallel
// across services — each networksetup call is ~200 ms, and with 5+ services
// the serial version added a full second to every Disconnect.
//
// Returns a non-nil error listing the services whose networksetup call failed,
// so the caller (and ultimately the user) knows DNS may still point at the
// tunnel's resolver instead of the original. The in-memory dnsActive flag is
// retained on partial failure so the original settings remain available
// for another restore attempt.
func (m *DarwinManager) RestoreDNS(ifaceName string) error {
	// Split-DNS keys are derived from the interface name alone and must go
	// even when dnsActive is false (split mode never sets it, and
	// RestoreDNSFromSnapshot clears it before Cleanup runs RestoreDNS).
	m.mu.Lock()
	splitActive := m.splitDNSActive
	m.mu.Unlock()
	if splitActive {
		if err := m.removeSplitDNS(ifaceName); err != nil {
			return err
		}
	}

	// Snapshot saved state under the lock. We deliberately keep dnsActive=true
	// during the restore: a concurrent SetDNS racing in here would otherwise
	// re-snapshot the *partially-restored* system DNS as if it were the
	// pristine original, permanently losing the real baseline. We clear the
	// flag only after every restore write succeeds.
	m.mu.Lock()
	if !m.dnsActive {
		m.mu.Unlock()
		return nil
	}
	savedDNS := m.savedDNS
	savedSearch := m.savedSearch
	m.mu.Unlock()

	if err := restoreServiceDNS(savedDNS, savedSearch); err != nil {
		return err
	}
	m.clearRestoredDNS()
	return nil
}

func (m *DarwinManager) clearRestoredDNS() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.savedDNS, m.savedSearch = map[string][]string{}, map[string][]string{}
	m.dnsActive = false
	m.lastDNS = nil
}

// SavedDNSSnapshot returns the current per-service DNS snapshot (servers
// AND search domains), including the prepared snapshot before DNS is applied.
// Thread-safe; the owner checkpoints this before persistent system changes.
func (m *DarwinManager) SavedDNSSnapshot() DNSSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.savedDNSSnapshotLocked()
}

func (m *DarwinManager) savedDNSSnapshotLocked() DNSSnapshot {
	if len(m.savedDNS) == 0 {
		return DNSSnapshot{}
	}
	snap := DNSSnapshot{
		Servers: make(map[string][]string, len(m.savedDNS)),
		Search:  make(map[string][]string, len(m.savedSearch)),
	}
	for svc, dns := range m.savedDNS {
		snap.Servers[svc] = append([]string(nil), dns...)
	}
	for svc, search := range m.savedSearch {
		snap.Search[svc] = append([]string(nil), search...)
	}
	return snap
}

// RestoreDNSFromSnapshot restores DNS from a persisted pre-modification
// snapshot. Used during crash recovery when in-memory state is unavailable,
// AND on the multi-tunnel last-disconnect path so we restore the system's
// PRE-VPN DNS instead of whatever the per-netMgr savedDNS captured (which
// for the second-to-connect tunnel would have been the first tunnel's DNS,
// not the original DHCP defaults).
//
// Side effect: clears in-memory dnsActive/savedDNS so a subsequent
// Cleanup() doesn't re-fire RestoreDNS over our manual restore.
//
// The restore is COMPLETE (issue #34): it writes both servers and search
// domains, and it iterates the union of the snapshot's services, this
// manager's own saved maps, and every service live right now — so a
// service that appeared mid-session (Ethernet plugged in, iPhone USB) and
// received tunnel DNS from a reapply is cleaned too. Per-service fallback
// order: global pre-VPN snapshot → this manager's captured original
// (covers mid-session services the global snapshot predates) → "Empty".
func (m *DarwinManager) RestoreDNSFromSnapshot(snap DNSSnapshot) error {
	m.mu.Lock()
	savedDNS, savedSearch := m.savedDNS, m.savedSearch
	m.mu.Unlock()
	services := map[string]bool{}
	for svc := range snap.Servers {
		services[svc] = true
	}
	for svc := range snap.Search {
		services[svc] = true
	}
	for svc := range savedDNS {
		services[svc] = true
	}
	for svc := range savedSearch {
		services[svc] = true
	}
	for _, svc := range getAllNetworkServices() {
		services[svc] = true
	}
	servers, search := map[string][]string{}, map[string][]string{}
	for svc := range services {
		servers[svc] = snap.Servers[svc]
		if _, ok := snap.Servers[svc]; !ok {
			servers[svc] = savedDNS[svc]
		}
		search[svc] = snap.Search[svc]
		if _, ok := snap.Search[svc]; !ok {
			search[svc] = savedSearch[svc]
		}
	}
	if err := restoreServiceDNS(servers, search); err != nil {
		return err
	}
	m.clearRestoredDNS()
	return nil
}
