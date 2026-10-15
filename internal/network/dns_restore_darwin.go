//go:build darwin

package network

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// ResetDNSToSystemDefault clears DNS overrides on every network service
// back to DHCP-provided defaults. Used by crash recovery when the process
// has no memory of the pre-crash DNS state. Parallel across services.
func (m *DarwinManager) ResetDNSToSystemDefault() error {
	services := getAllNetworkServices()
	var wg sync.WaitGroup
	for _, svc := range services {
		svc := svc
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := run("networksetup", "-setdnsservers", svc, "Empty"); err != nil {
				slog.Warn("reset DNS servers failed", "service", svc, "error", err)
			}
			if err := run("networksetup", "-setsearchdomains", svc, "Empty"); err != nil {
				slog.Warn("reset search domains failed", "service", svc, "error", err)
			}
		}()
	}
	wg.Wait()
	flushDNSCache()
	return nil
}

// RestoreDNS restores original DNS for every service we touched. Parallel
// across services — each networksetup call is ~200 ms, and with 5+ services
// the serial version added a full second to every Disconnect.
//
// Returns a non-nil error listing the services whose networksetup call failed,
// so the caller (and ultimately the user) knows DNS may still point at the
// tunnel's resolver instead of the original. The in-memory dnsActive flag is
// still cleared on partial failure: the saved entries no longer reflect a
// consistent system snapshot once we've started mutating, and re-running
// RestoreDNS with the same stale map would just repeat the same failed call.
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
	// flag at the end after networksetup finishes (success or fail).
	m.mu.Lock()
	if !m.dnsActive {
		m.mu.Unlock()
		return nil
	}
	savedDNS := m.savedDNS
	savedSearch := m.savedSearch
	m.mu.Unlock()

	// Fan out networksetup calls in parallel — each is ~200ms, so for 5+
	// services we save multiple seconds vs serial. errCh is buffered to the
	// total work count so each goroutine sends without blocking even when no
	// reader is yet draining.
	totalOps := len(savedDNS) + len(savedSearch)
	errCh := make(chan error, totalOps)
	var wg sync.WaitGroup
	for svc, orig := range savedDNS {
		svc, orig := svc, orig
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if len(orig) == 0 {
				err = run("networksetup", "-setdnsservers", svc, "Empty")
			} else {
				args := append([]string{"-setdnsservers", svc}, orig...)
				err = run("networksetup", args...)
			}
			if err != nil {
				errCh <- fmt.Errorf("setdnsservers %s: %w", svc, err)
			}
		}()
	}
	for svc, search := range savedSearch {
		svc, search := svc, search
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if len(search) == 0 {
				err = run("networksetup", "-setsearchdomains", svc, "Empty")
			} else {
				args := append([]string{"-setsearchdomains", svc}, search...)
				err = run("networksetup", args...)
			}
			if err != nil {
				errCh <- fmt.Errorf("setsearchdomains %s: %w", svc, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	// Clear state regardless of success — the saved maps no longer match
	// any consistent system state after partial mutation, and keeping the
	// flag would block future SetDNS from re-capturing a fresh baseline.
	m.mu.Lock()
	m.savedDNS = make(map[string][]string)
	m.savedSearch = make(map[string][]string)
	m.dnsActive = false
	m.lastDNS = nil
	m.mu.Unlock()

	flushDNSCache()

	var failures []string
	for e := range errCh {
		failures = append(failures, e.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("RestoreDNS: %d service(s) failed: %s",
			len(failures), strings.Join(failures, "; "))
	}
	return nil
}

// SavedDNSSnapshot returns the current per-service DNS snapshot (servers
// AND search domains) for persistence to the crash recovery journal.
// Thread-safe.
func (m *DarwinManager) SavedDNSSnapshot() DNSSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dnsActive || len(m.savedDNS) == 0 {
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
	savedDNS := m.savedDNS
	savedSearch := m.savedSearch
	m.dnsActive = false
	m.savedDNS = make(map[string][]string)
	m.savedSearch = make(map[string][]string)
	m.lastDNS = nil
	m.mu.Unlock()

	svcSet := make(map[string]struct{})
	for svc := range snap.Servers {
		svcSet[svc] = struct{}{}
	}
	for svc := range snap.Search {
		svcSet[svc] = struct{}{}
	}
	for svc := range savedDNS {
		svcSet[svc] = struct{}{}
	}
	for svc := range savedSearch {
		svcSet[svc] = struct{}{}
	}
	for _, svc := range getAllNetworkServices() {
		svcSet[svc] = struct{}{}
	}

	var wg sync.WaitGroup
	for svc := range svcSet {
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers, ok := snap.Servers[svc]
			if !ok {
				servers = savedDNS[svc]
			}
			if len(servers) > 0 {
				args := append([]string{"-setdnsservers", svc}, servers...)
				if err := run("networksetup", args...); err != nil {
					slog.Warn("RestoreDNSFromSnapshot: setting DNS failed", "service", svc, "error", err)
				}
			} else {
				if err := run("networksetup", "-setdnsservers", svc, "Empty"); err != nil {
					slog.Warn("RestoreDNSFromSnapshot: clearing DNS failed", "service", svc, "error", err)
				}
			}
			search, ok := snap.Search[svc]
			if !ok {
				search = savedSearch[svc]
			}
			if len(search) > 0 {
				args := append([]string{"-setsearchdomains", svc}, search...)
				if err := run("networksetup", args...); err != nil {
					slog.Warn("RestoreDNSFromSnapshot: setting search domains failed", "service", svc, "error", err)
				}
			} else {
				if err := run("networksetup", "-setsearchdomains", svc, "Empty"); err != nil {
					slog.Warn("RestoreDNSFromSnapshot: clearing search domains failed", "service", svc, "error", err)
				}
			}
		}()
	}
	wg.Wait()
	flushDNSCache()
	return nil
}
