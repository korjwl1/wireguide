package tunnel

import (
	"log/slog"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

// AllDNSServers returns the union of DNS servers from all connected tunnels'
// configs. Used to re-apply the combined DNS when a tunnel connects or
// disconnects, preventing one tunnel from overwriting another's DNS settings.
func (m *Manager) AllDNSServers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allDNSServersLocked()
}

// CapturePreModDNS records the system's pre-VPN DNS state once, on the
// FIRST tunnel's connect. Subsequent connects do nothing because the
// snapshot they'd capture has already been polluted by the first tunnel's
// DNS. ClearPreModDNS resets it on the LAST tunnel's disconnect.
//
// Why: each per-tunnel netMgr keeps its own savedDNS that matches whatever
// the system DNS was at THAT tunnel's SetDNS time. If tunnel B connects
// after A, B's savedDNS is A's DNS — so when B disconnects last via
// netMgr_B.Cleanup the user's system would get restored to A's DNS
// instead of the original DHCP defaults.
func (m *Manager) CapturePreModDNS(snapshot network.DNSSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.globalPreModDNS != nil || snapshot.Empty() {
		return
	}
	m.globalPreModDNS = &network.DNSSnapshot{
		Servers: copyServiceMap(snapshot.Servers),
		Search:  copyServiceMap(snapshot.Search),
	}
}

// PreModDNSSnapshot returns a copy of the captured pre-VPN DNS state and
// whether anything has been captured yet.
func (m *Manager) PreModDNSSnapshot() (network.DNSSnapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.globalPreModDNS == nil {
		return network.DNSSnapshot{}, false
	}
	return network.DNSSnapshot{
		Servers: copyServiceMap(m.globalPreModDNS.Servers),
		Search:  copyServiceMap(m.globalPreModDNS.Search),
	}, true
}

// ClearPreModDNS drops the captured snapshot once the last tunnel has
// disconnected so a fresh capture happens on the next session.
func (m *Manager) ClearPreModDNS() {
	m.mu.Lock()
	m.globalPreModDNS = nil
	m.mu.Unlock()
}

// RestoreDNSBestEffort restores the pre-VPN DNS state using the global
// snapshot and any live tunnel's network manager. Used by ForceShutdown,
// which exits without tunnel teardown: the utun devices die with the
// process but networksetup overrides persist in SystemConfiguration
// (issue #34 gap 4) — without this a helper upgrade while connected left
// tunnel DNS behind until crash recovery ran.
func (m *Manager) RestoreDNSBestEffort() {
	pre, captured := m.PreModDNSSnapshot()
	if !captured {
		return
	}
	m.mu.Lock()
	var restorer network.DNSStateRestorer
	for _, e := range m.tunnels {
		if r, ok := e.netMgr.(network.DNSStateRestorer); ok {
			restorer = r
			break
		}
	}
	m.mu.Unlock()
	if restorer == nil {
		return
	}
	if err := restorer.RestoreDNSFromSnapshot(pre); err != nil {
		slog.Warn("RestoreDNSBestEffort failed", "error", err)
	}
	m.ClearPreModDNS()
}

func copyServiceMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// allDNSServersLocked is AllDNSServers without the lock — for callers
// that already hold m.mu (e.g. inside the Phase-3 commit of Connect).
// Today no caller needs it, but exposing the locked variant means a
// future callsite added inside the manager's critical section won't
// silently deadlock by re-acquiring m.mu.
func (m *Manager) allDNSServersLocked() []string {
	seen := make(map[string]struct{})
	var all []string
	for _, e := range m.tunnels {
		if e.state == domain.StateConnected && e.cfg != nil {
			for _, dns := range e.cfg.Interface.DNS {
				if _, ok := seen[dns]; !ok {
					seen[dns] = struct{}{}
					all = append(all, dns)
				}
			}
		}
	}
	return all
}
