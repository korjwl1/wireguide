package network

// SetDNSCheckpoint configures persistence before the first SetDNS call.
func (m *DarwinManager) SetDNSCheckpoint(checkpoint func(DNSSnapshot) error) {
	m.dnsCheckpointMu.Lock()
	defer m.dnsCheckpointMu.Unlock()
	m.mu.Lock()
	m.dnsCheckpoint = checkpoint
	m.dnsCheckpointVersion++
	m.mu.Unlock()
}

// checkpointDNS publishes newly captured services once. Failure remains dirty
// so a later repair retries before changing DNS. The callback runs outside mu
// and is serialized; generations prevent a concurrent capture from being lost.
func (m *DarwinManager) checkpointDNS() error {
	m.dnsCheckpointMu.Lock()
	defer m.dnsCheckpointMu.Unlock()
	m.mu.Lock()
	version := m.dnsCheckpointVersion
	checkpoint := m.dnsCheckpoint
	if checkpoint == nil || version == m.dnsCheckpointSaved {
		m.mu.Unlock()
		return nil
	}
	snapshot := m.savedDNSSnapshotLocked()
	m.mu.Unlock()
	if err := checkpoint(snapshot); err != nil {
		return err
	}
	m.mu.Lock()
	m.dnsCheckpointSaved = version
	m.mu.Unlock()
	return nil
}
