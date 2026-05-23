package tunnel

import "github.com/korjwl1/wireguide/internal/domain"

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
func (m *Manager) CapturePreModDNS(snapshot map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.globalPreModDNS != nil || len(snapshot) == 0 {
		return
	}
	cp := make(map[string][]string, len(snapshot))
	for k, v := range snapshot {
		c := make([]string, len(v))
		copy(c, v)
		cp[k] = c
	}
	m.globalPreModDNS = cp
}

// PreModDNSSnapshot returns a copy of the captured pre-VPN DNS, or nil
// if nothing has been captured yet.
func (m *Manager) PreModDNSSnapshot() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.globalPreModDNS == nil {
		return nil
	}
	cp := make(map[string][]string, len(m.globalPreModDNS))
	for k, v := range m.globalPreModDNS {
		c := make([]string, len(v))
		copy(c, v)
		cp[k] = c
	}
	return cp
}

// ClearPreModDNS drops the captured snapshot once the last tunnel has
// disconnected so a fresh capture happens on the next session.
func (m *Manager) ClearPreModDNS() {
	m.mu.Lock()
	m.globalPreModDNS = nil
	m.mu.Unlock()
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
