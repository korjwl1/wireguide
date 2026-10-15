package tunnel

import (
	"log/slog"
	"time"

	"github.com/korjwl1/wireguide/internal/network"
)

type pendingDNSCleanup struct {
	name    string
	remover network.SplitDNSRemover
	retryAt time.Time
	delay   time.Duration
}

// RetryPendingDNSCleanup runs under the helper's connect lock. The journal
// remains until cleanup succeeds, so a crash can retry it at startup too.
func (m *Manager) RetryPendingDNSCleanup() { m.RetryPendingDNSCleanupAt(time.Now()) }

func (m *Manager) RetryPendingDNSCleanupAt(now time.Time) {
	m.mu.Lock()
	pending := make(map[string]pendingDNSCleanup, len(m.pendingDNSCleanup))
	for iface, entry := range m.pendingDNSCleanup {
		pending[iface] = entry
	}
	m.mu.Unlock()
	for iface, entry := range pending {
		if now.Before(entry.retryAt) {
			continue
		}
		m.mu.Lock()
		reused := false
		for _, live := range m.tunnels {
			if live.engine != nil && live.engine.InterfaceName() == iface {
				reused = true
				break
			}
		}
		m.mu.Unlock()
		if !reused {
			if err := entry.remover.RemoveSplitDNS(iface); err != nil {
				entry.delay = min(30*time.Second, max(time.Second, entry.delay*2))
				entry.retryAt = now.Add(entry.delay)
				m.mu.Lock()
				m.pendingDNSCleanup[iface] = entry
				m.mu.Unlock()
				slog.Warn("split DNS cleanup pending", "interface", iface, "retry_in", entry.delay, "error", err)
				continue
			}
		}
		m.mu.Lock()
		_, sameNameActive := m.tunnels[entry.name]
		delete(m.pendingDNSCleanup, iface)
		m.mu.Unlock()
		if !sameNameActive {
			if err := ClearActiveState(m.dataDir, entry.name); err != nil {
				slog.Warn("split DNS cleanup journal removal failed", "error", err)
			}
		}
	}
}

// prepareInterfaceDNS clears a former owner's supplemental resolver before
// a recycled interface is used. A new global-DNS or DNS-less tunnel must not
// inherit stale split resolvers, and a retry must not delete the new owner's
// keys after SetDNS. Called before any network configuration is installed.
func (m *Manager) prepareInterfaceDNS(iface string) error {
	m.mu.Lock()
	entry, pending := m.pendingDNSCleanup[iface]
	m.mu.Unlock()
	if !pending {
		return nil
	}
	if err := entry.remover.RemoveSplitDNS(iface); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.pendingDNSCleanup, iface)
	_, sameNameActive := m.tunnels[entry.name]
	m.mu.Unlock()
	if !sameNameActive {
		if err := ClearActiveState(m.dataDir, entry.name); err != nil {
			slog.Warn("old DNS journal removal failed", "tunnel", entry.name, "error", err)
		}
	}
	return nil
}
