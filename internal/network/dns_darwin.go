//go:build darwin

package network

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// SetDNS sets DNS on ALL network services (matching wg-quick).
// Entries are split into servers (IPs) and search domains (hostnames),
// mirroring wg-quick's `set_dns` which parses `DNS = 1.1.1.1, corp.example.com`
// that way.
//
// Performance: `networksetup -setdnsservers` is synchronous and slow
// (~150–400 ms per call on a typical Mac). With 5 network services (Wi-Fi,
// Ethernet, Bluetooth PAN, Thunderbolt Bridge, iPhone USB) this can add
// 1.5–4 seconds to Connect if done sequentially. We therefore fan out one
// goroutine per service and wait on them in parallel — they touch different
// resources so there's no contention.
func (m *DarwinManager) SetDNS(ifaceName string, entries []string) error {
	if len(entries) == 0 {
		return nil
	}

	// Mode decision is made once, before any splitting: a "~name" token
	// means split DNS, which installs a supplemental resolver in the
	// dynamic store and never touches the system's own DNS. Everything
	// below (snapshot, networksetup, lastDNS/dnsActive, verifyDNS, the
	// reapply drift loop) is the global-override machinery and must not run.
	parsed := domain.ParseDNSEntries(entries)
	if len(parsed.Match) > 0 {
		return m.setSplitDNS(ifaceName, parsed)
	}

	services := getAllNetworkServices()
	if len(services) == 0 {
		return fmt.Errorf("no network services found")
	}

	// Check/update `dnsActive` under the lock — this field is also read by
	// RestoreDNS and (potentially) by reapply via applyDNS, so touching it
	// without the lock is a data race.
	m.mu.Lock()
	alreadyActive := m.dnsActive
	m.mu.Unlock()

	// Save original DNS for each service before overriding (only on first apply).
	// Parallelised: each networksetup -getdnsservers call is ~100–200 ms.
	if !alreadyActive {
		type savedEntry struct {
			svc    string
			dns    []string
			search []string
			err    error
		}
		saved := make([]savedEntry, len(services))
		var wg sync.WaitGroup
		for i, svc := range services {
			i, svc := i, svc
			wg.Add(1)
			go func() {
				defer wg.Done()
				dns, dnsErr := getCurrentDNS(svc)
				search, searchErr := getCurrentSearchDomains(svc)
				saved[i] = savedEntry{svc: svc, dns: dns, search: search, err: errors.Join(dnsErr, searchErr)}
			}()
		}
		wg.Wait()
		for _, e := range saved {
			if e.err != nil {
				return fmt.Errorf("capture DNS for %s: %w", e.svc, e.err)
			}
		}
		m.mu.Lock()
		m.dnsCheckpointVersion++
		for _, e := range saved {
			m.savedDNS[e.svc] = e.dns
			m.savedSearch[e.svc] = e.search
		}
		m.mu.Unlock()
	} else if err := m.captureNewServices(services); err != nil {
		return err
	}

	if err := m.checkpointDNS(); err != nil {
		return fmt.Errorf("persist original DNS: %w", err)
	}
	// Push the new DNS to every service only after its recovery snapshot.
	m.applyDNSToServices(entries, services)

	// Commit state BEFORE verification: once applyDNSToServices ran, the
	// system carries our overrides, and every restore path (Cleanup →
	// RestoreDNS, crash-recovery SavedDNSSnapshot) keys off dnsActive.
	// Returning a verification error with dnsActive still false left the
	// user stuck on tunnel DNS that nothing would ever remove (issue #34
	// gap: connect rollback no-op'd on !dnsActive).
	m.mu.Lock()
	// Defensive copy — callers today build a fresh slice but a future
	// caller passing cfg.Interface.DNS directly would let reapply() (via
	// append-and-grow on the slice header) silently read live config.
	m.lastDNS = append([]string(nil), entries...)
	m.dnsActive = true
	m.mu.Unlock()

	// Verify DNS actually took effect on at least one service. macOS can
	// silently fail to apply DNS settings (e.g. permission issues, MDM
	// profiles overriding). Without this check the user thinks VPN DNS
	// is active but traffic goes to their ISP resolver.
	servers, _ := splitDNSEntries(entries)
	if len(servers) > 0 {
		if err := m.verifyDNS(services, servers); err != nil {
			slog.Warn("DNS verification failed", "error", err)
			return fmt.Errorf("DNS applied but verification failed: %w", err)
		}
	}

	// Flush the macOS DNS cache so lookups see the new servers immediately.
	// Without this users can keep hitting stale resolutions for several
	// minutes — wg-quick does this at the end of its set_dns.
	flushDNSCache()
	return nil
}

// applyDNS pushes DNS servers and search domains to every network service.
// Captures original DNS for new network services that were not
// present when SetDNS was first called, so they can be properly restored.
func (m *DarwinManager) applyDNS(entries []string) error {
	if hasSplitDNSToken(entries) {
		return fmt.Errorf("refusing to apply split-DNS entries to network services")
	}
	services := getAllNetworkServices()
	if err := m.captureNewServices(services); err != nil {
		return err
	}
	m.applyDNSToServices(entries, services)
	flushDNSCache()
	return nil
}

// applyDNSIfDrifted re-applies DNS only to services whose current values
// differ from the desired set. Route-table events fire on Wi-Fi roams,
// DHCP renewals, sleep/wake and other VPNs starting; unconditionally
// rewriting identical DNS on every one of them spawned 10-20 networksetup
// processes and HUP'd mDNSResponder — wiping the machine-wide resolver
// cache — per event. Reads are parallel networksetup queries; the resolver
// flush runs only when at least one service actually needed a rewrite.
func (m *DarwinManager) applyDNSIfDrifted(entries []string) error {
	if hasSplitDNSToken(entries) {
		return fmt.Errorf("refusing to apply split-DNS entries to network services")
	}
	services := getAllNetworkServices()
	if err := m.captureNewServices(services); err != nil {
		return err
	}

	servers, search := splitDNSEntries(entries)
	drifted := make([]bool, len(services))
	var wg sync.WaitGroup
	for i, svc := range services {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cur, err := getCurrentDNS(svc)
			if err != nil || !stringSetEqual(cur, servers) {
				// Read failure counts as drift: rewriting is the safe side.
				drifted[i] = true
				return
			}
			if len(search) > 0 {
				curSearch, serr := getCurrentSearchDomains(svc)
				if serr != nil || !stringSetEqual(curSearch, search) {
					drifted[i] = true
				}
			}
		}()
	}
	wg.Wait()

	var need []string
	for i, svc := range services {
		if drifted[i] {
			need = append(need, svc)
		}
	}
	if len(need) == 0 {
		slog.Debug("reapply: DNS already correct on all services — skipping rewrite")
		return nil
	}
	m.applyDNSToServices(entries, need)
	flushDNSCache()
	return nil
}

// captureNewServices saves the original DNS of network services that
// appeared after SetDNS was first called, so they can be restored too.
// Collect the list needing capture under the lock, release it for the
// network calls, and re-lock once to store.
func (m *DarwinManager) captureNewServices(services []string) error {
	var newServices []string
	m.mu.Lock()
	if m.dnsActive {
		for _, svc := range services {
			if _, exists := m.savedDNS[svc]; !exists {
				newServices = append(newServices, svc)
			}
		}
	}
	m.mu.Unlock()

	if len(newServices) == 0 {
		return m.checkpointDNS()
	}
	type savedEntry struct {
		svc    string
		dns    []string
		search []string
		err    error
	}
	fetched := make([]savedEntry, len(newServices))
	var wg sync.WaitGroup
	for i, svc := range newServices {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dns, dnsErr := getCurrentDNS(svc)
			search, searchErr := getCurrentSearchDomains(svc)
			fetched[i] = savedEntry{svc: svc, dns: dns, search: search, err: errors.Join(dnsErr, searchErr)}
		}()
	}
	wg.Wait()
	for _, e := range fetched {
		if e.err != nil {
			return fmt.Errorf("capture DNS for new service %s: %w", e.svc, e.err)
		}
	}

	m.mu.Lock()
	for _, e := range fetched {
		if _, exists := m.savedDNS[e.svc]; !exists {
			m.dnsCheckpointVersion++
			m.savedDNS[e.svc] = e.dns
			m.savedSearch[e.svc] = e.search
			slog.Info("discovered new network service, saving DNS", "service", e.svc)
		}
	}
	m.mu.Unlock()
	return m.checkpointDNS()
}

// applyDNSToServices is the shared hot path used by both SetDNS and applyDNS.
// Takes a pre-fetched service list (avoids redundant
// `networksetup -listallnetworkservices` calls) and fans out one goroutine
// per service.
func (m *DarwinManager) applyDNSToServices(entries []string, services []string) {
	if hasSplitDNSToken(entries) {
		slog.Error("applyDNSToServices: refusing split-DNS entries")
		return
	}
	servers, search := splitDNSEntries(entries)
	if len(services) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, svc := range services {
		svc := svc
		wg.Add(1)
		go func() {
			defer wg.Done()
			if len(servers) > 0 {
				args := append([]string{"-setdnsservers", svc}, servers...)
				if err := run("networksetup", args...); err != nil {
					slog.Warn("failed to set DNS on service", "service", svc, "error", err)
				}
			}
			if len(search) > 0 {
				args := append([]string{"-setsearchdomains", svc}, search...)
				if err := run("networksetup", args...); err != nil {
					slog.Warn("failed to set search domains on service", "service", svc, "error", err)
				}
			}
		}()
	}
	wg.Wait()
}

// flushDNSCache tells macOS's mDNSResponder to drop any cached entries so
// lookups see the new DNS servers immediately. Best-effort: errors are not
// propagated because a failed flush is not worth aborting a successful
// Connect over — but we now log the outcome at debug so a flaky
// mDNSResponder ("operation not permitted" under SIP, MDM blocks) leaves
// a breadcrumb in helper.log instead of vanishing.
var flushDNSCache = func() {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "dscacheutil", "-flushcache").CombinedOutput(); err != nil {
		slog.Debug("dscacheutil flush failed", "error", err, "output", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "killall", "-HUP", "mDNSResponder").CombinedOutput(); err != nil {
		slog.Debug("mDNSResponder HUP failed", "error", err, "output", strings.TrimSpace(string(out)))
	}
}

// validHostnameRegex matches RFC 1123 hostname characters plus '.'.
// Reject anything else so a malicious DNS entry like `foo;rm -rf ~`
// can't end up in `networksetup -setsearchdomains` arguments (even
// though Go's exec.Command isn't shell-interpreting, the string still
// lands in /Library/Preferences/SystemConfiguration/preferences.plist
// and persists there).
var validHostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)*$`)

// splitDNSEntries partitions a mixed DNS list into IP servers and hostname
// search domains, matching wg-quick's parse of `DNS = 1.1.1.1, corp.example.com`.
// Entries that are neither valid IPs nor valid RFC-1123 hostnames are
// dropped (with a debug log) — letting them through risked persisting
// attacker-supplied strings into system DNS config.
func splitDNSEntries(entries []string) (servers, search []string) {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if net.ParseIP(e) != nil {
			servers = append(servers, e)
			continue
		}
		if len(e) <= 253 && validHostnameRegex.MatchString(e) {
			search = append(search, e)
			continue
		}
		slog.Debug("splitDNSEntries: dropping invalid DNS entry", "entry", e)
	}
	return
}

// verifyDNS checks that at least one network service has the expected DNS
// servers applied. macOS can silently drop DNS changes (MDM profiles,
// permission issues, etc.), so we read back and confirm. Retries once
// after a short delay to handle asynchronous DNS propagation.
func (m *DarwinManager) verifyDNS(services, expectedServers []string) error {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		// Check all services in parallel.
		type result struct {
			found bool
		}
		results := make([]result, len(services))
		var wg sync.WaitGroup
		for i, svc := range services {
			i, svc := i, svc
			wg.Add(1)
			go func() {
				defer wg.Done()
				current, err := getCurrentDNS(svc)
				if err != nil || len(current) == 0 {
					return
				}
				for _, got := range current {
					if got == expectedServers[0] {
						results[i].found = true
						return
					}
				}
			}()
		}
		wg.Wait()
		for _, r := range results {
			if r.found {
				return nil
			}
		}
	}
	return fmt.Errorf("DNS server %s not found on any network service after apply", expectedServers[0])
}

// getAllNetworkServices returns all network services, including disabled ones.
// wg-quick includes disabled services (strips the "*" prefix) so DNS is
// applied/restored uniformly regardless of current enabled state.
// networkServices is the error-preserving enumeration seam for restoration.
var networkServices = listNetworkServices

func getAllNetworkServices() []string {
	services, err := networkServices()
	if err != nil {
		slog.Warn("cannot enumerate network services", "error", err)
	}
	return services
}

func listNetworkServices() ([]string, error) {
	out, err := runOut("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	firstLine := true
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if firstLine {
			// First non-empty line is the header ("An asterisk...")
			firstLine = false
			continue
		}
		// Strip leading "*" from disabled services (don't skip them)
		if strings.HasPrefix(line, "*") {
			line = strings.TrimSpace(line[1:])
		}
		if line != "" {
			services = append(services, line)
		}
	}
	return services, nil
}

func getCurrentDNS(service string) ([]string, error) {
	out, err := runOut("networksetup", "-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "There aren't any DNS Servers") {
		return nil, nil
	}
	var servers []string
	for _, line := range strings.Split(output, "\n") {
		s := strings.TrimSpace(line)
		if s != "" {
			servers = append(servers, s)
		}
	}
	return servers, nil
}

func getCurrentSearchDomains(service string) ([]string, error) {
	out, err := runOut("networksetup", "-getsearchdomains", service)
	if err != nil {
		return nil, err
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "There aren't any Search Domains") {
		return nil, nil
	}
	var domains []string
	for _, line := range strings.Split(output, "\n") {
		s := strings.TrimSpace(line)
		if s != "" {
			domains = append(domains, s)
		}
	}
	return domains, nil
}

// TrackDNSUnion keeps every live adapter's drift monitor on the same policy.
func (m *DarwinManager) TrackDNSUnion(entries []string) {
	m.mu.Lock()
	m.lastDNS = append([]string(nil), entries...)
	m.mu.Unlock()
}
