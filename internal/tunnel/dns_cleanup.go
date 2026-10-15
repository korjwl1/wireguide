package tunnel

import (
	"errors"
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
	m.retryNetworkCleanup(now)
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
		_, recoveryPending := m.pendingNetworkCleanup[entry.name]
		sameNameActive = sameNameActive || recoveryPending
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
	_, recoveryPending := m.pendingNetworkCleanup[entry.name]
	sameNameActive = sameNameActive || recoveryPending
	m.mu.Unlock()
	if !sameNameActive {
		if err := ClearActiveState(m.dataDir, entry.name); err != nil {
			slog.Warn("old DNS journal removal failed", "tunnel", entry.name, "error", err)
		}
	}
	return nil
}

type pendingNetworkCleanup struct {
	iface   string
	manager network.NetworkManager
	retryAt time.Time
	delay   time.Duration
}

func (m *Manager) queueNetworkCleanup(name, iface string, manager network.NetworkManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pendingNetworkCleanup == nil {
		m.pendingNetworkCleanup = map[string]pendingNetworkCleanup{}
	}
	m.pendingNetworkCleanup[name] = pendingNetworkCleanup{iface: iface, manager: manager, retryAt: time.Now().Add(time.Second), delay: time.Second}
}

func (m *Manager) cleanupNetwork(manager network.NetworkManager, iface string) error {
	// Never substitute a later adapter's polluted snapshot for the original.
	if pre, captured := m.PreModDNSSnapshot(); captured {
		if restorer, ok := manager.(network.DNSStateRestorer); ok {
			if err := restorer.RestoreDNSFromSnapshot(pre); err != nil {
				return err
			}
		}
	}
	return manager.Cleanup(iface)
}

func (m *Manager) retryNetworkCleanup(now time.Time) {
	m.mu.Lock()
	pending := make(map[string]pendingNetworkCleanup, len(m.pendingNetworkCleanup))
	for name, entry := range m.pendingNetworkCleanup {
		pending[name] = entry
	}
	busy := len(m.tunnels) != 0
	m.mu.Unlock()
	if busy {
		return
	} // a newer session must never be reset by an old owner
	for name, entry := range pending {
		if now.Before(entry.retryAt) {
			continue
		}
		err := m.cleanupNetwork(entry.manager, entry.iface)
		if err == nil {
			m.mu.Lock()
			splitPending := false
			for _, split := range m.pendingDNSCleanup {
				if split.name == name {
					splitPending = true
					break
				}
			}
			m.mu.Unlock()
			if !splitPending {
				err = ClearActiveState(m.dataDir, name)
			}
		}
		if err != nil {
			entry.delay = min(30*time.Second, entry.delay*2)
			entry.retryAt = now.Add(entry.delay)
			slog.Warn("network recovery retry failed", "tunnel", name, "error", err)
			m.mu.Lock()
			m.pendingNetworkCleanup[name] = entry
			m.mu.Unlock()
			continue
		}
		m.mu.Lock()
		delete(m.pendingNetworkCleanup, name)
		m.mu.Unlock()
	}
	m.mu.Lock()
	clean := len(m.pendingNetworkCleanup) == 0
	m.mu.Unlock()
	if clean {
		m.ClearPreModDNS()
	}
}

func (m *Manager) checkPendingNetworkCleanup() error {
	m.retryNetworkCleanup(time.Now().Add(30 * time.Second))
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pendingNetworkCleanup) != 0 {
		return errors.New("previous network cleanup is still pending; retry after DNS recovery")
	}
	return nil
}
