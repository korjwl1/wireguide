package tunnel

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
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
		recoveryPending := m.hasPendingRecoveryLocked(entry.name)
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
	recoveryPending := m.hasPendingRecoveryLocked(entry.name)
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
	name       string
	journalKey string
	recovery   *ActiveTunnelState
	iface      string
	manager    network.NetworkManager
	retryAt    time.Time
	delay      time.Duration
}

// SetOnRecoveryWarning lets the helper surface retained recovery work to its GUI.
func (m *Manager) SetOnRecoveryWarning(warn func(string, error)) {
	m.mu.Lock()
	m.onRecoveryWarning = warn
	m.mu.Unlock()
}

func (m *Manager) queueNetworkCleanup(name, iface string, manager network.NetworkManager, failures ...error) {
	key := ".cleanup-" + rand.Text()
	entry := pendingNetworkCleanup{name: name, journalKey: name, iface: iface, manager: manager, retryAt: time.Now().Add(time.Second), delay: time.Second}
	if err := m.archiveCleanupJournal(name, key); err == nil {
		entry.journalKey = key
	} else {
		slog.Warn("retaining original recovery journal", "tunnel", name, "error", err)
	}
	m.mu.Lock()
	if m.pendingNetworkCleanup == nil {
		m.pendingNetworkCleanup = map[string]pendingNetworkCleanup{}
	}
	m.pendingNetworkCleanup[key] = entry
	warn := m.onRecoveryWarning
	m.mu.Unlock()
	if warn != nil {
		warn(name, errors.Join(append([]error{errors.New("DNS recovery is pending; original settings were retained")}, failures...)...))
	}
}

func (m *Manager) archiveCleanupJournal(name, key string) error {
	dir := filepath.Join(m.dataDir, tunnelStatesDir)
	err := os.Rename(filepath.Join(dir, stateFileName(name)), filepath.Join(dir, stateFileName(key)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (m *Manager) hasPendingRecoveryLocked(name string) bool {
	for _, entry := range m.pendingNetworkCleanup {
		if entry.name == name {
			return true
		}
	}
	return false
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
	for key, entry := range pending {
		name := entry.name
		if now.Before(entry.retryAt) {
			continue
		}
		err := m.cleanupNetwork(entry.manager, entry.iface)
		if err == nil && entry.recovery != nil && entry.iface != "" {
			err = errors.Join(entry.manager.RemoveRoutes(entry.iface, nil, entry.recovery.FullTunnel), cleanupStaleUAPI(entry.iface))
		}
		if err == nil {
			err = ClearActiveState(m.dataDir, entry.journalKey)
			if err == nil {
				m.mu.Lock()
				if split, ok := m.pendingDNSCleanup[entry.iface]; ok && split.name == name {
					delete(m.pendingDNSCleanup, entry.iface)
				}
				m.mu.Unlock()
			}
		}
		if err != nil {
			entry.delay = min(30*time.Second, entry.delay*2)
			entry.retryAt = now.Add(entry.delay)
			slog.Warn("network recovery retry failed", "tunnel", name, "error", err)
			m.mu.Lock()
			m.pendingNetworkCleanup[key] = entry
			m.mu.Unlock()
			continue
		}
		m.mu.Lock()
		delete(m.pendingNetworkCleanup, key)
		m.mu.Unlock()
	}
	m.mu.Lock()
	clean := len(m.pendingNetworkCleanup) == 0
	m.mu.Unlock()
	if clean {
		m.ClearPreModDNS()
	}
}

// A retired journal must not be overwritten when its profile reconnects.
// Unrelated recovery failures never block another connection.
func (m *Manager) preparePendingJournal(name string) error {
	m.mu.Lock()
	pending := map[string]pendingNetworkCleanup{}
	for key, entry := range m.pendingNetworkCleanup {
		if entry.name == name && entry.journalKey == name {
			pending[key] = entry
		}
	}
	m.mu.Unlock()
	for key, entry := range pending {
		if err := m.archiveCleanupJournal(name, key); err != nil {
			return err
		}
		entry.journalKey = key
		m.mu.Lock()
		m.pendingNetworkCleanup[key] = entry
		m.mu.Unlock()
	}
	return nil
}

func (m *Manager) clearRecoveredBaseline() {
	m.mu.Lock()
	pending := len(m.pendingNetworkCleanup) != 0
	m.mu.Unlock()
	if !pending {
		m.ClearPreModDNS()
	}
}

// AdoptPendingRecovery retains records startup recovery could not finish.
// New sessions reuse the original baseline instead of snapshotting stale VPN DNS.
func (m *Manager) AdoptPendingRecovery() {
	for _, state := range LoadActiveState(m.dataDir) {
		if len(state.PreModDNS) > 0 || len(state.PreModSearch) > 0 {
			m.CapturePreModDNS(network.DNSSnapshot{Servers: state.PreModDNS, Search: state.PreModSearch})
		}
		manager := newRecoveryManager()
		if setter, ok := manager.(network.PersistentStateDirSetter); ok {
			setter.SetPersistentStateDir(m.dataDir)
		}
		if restorer, ok := manager.(network.RoutingStateRestorer); ok {
			restorer.RestoreRoutingState(state.Table, state.FwMark)
		}
		if restorer, ok := manager.(network.EndpointRouteStateRestorer); ok {
			restorer.RestoreEndpointRoutes(state.EndpointRoutes)
		}
		journalKey := activeStateKey(state)
		key := journalKey
		if state.journalKey == "" {
			key = ".cleanup-" + rand.Text()
			if err := m.archiveCleanupJournal(state.TunnelName, key); err != nil {
				slog.Warn("could not archive startup recovery journal", "error", err)
			} else {
				journalKey = key
			}
		}
		entry := pendingNetworkCleanup{name: state.TunnelName, journalKey: journalKey, iface: state.InterfaceName, manager: manager, recovery: state, retryAt: time.Now().Add(time.Second), delay: time.Second}
		m.mu.Lock()
		if m.pendingNetworkCleanup == nil {
			m.pendingNetworkCleanup = map[string]pendingNetworkCleanup{}
		}
		m.pendingNetworkCleanup[key] = entry
		m.mu.Unlock()
	}
}
