//go:build darwin

package network

import (
	"errors"
	"testing"
)

// Q3 review: a failed networksetup write during snapshot restore must be
// reported; crash recovery and last-disconnect use the error to keep the
// journal / fall back to reset.
func TestRestoreDNSFromSnapshotReportsWriteFailure(t *testing.T) {
	orig := run
	run = func(string, ...string) error { return errors.New("networksetup failed") }
	t.Cleanup(func() { run = orig })
	origFlush := flushDNSCache
	flushDNSCache = func() {}
	t.Cleanup(func() { flushDNSCache = origFlush })

	m := NewPlatformManager().(*DarwinManager)
	err := m.RestoreDNSFromSnapshot(DNSSnapshot{Servers: map[string][]string{"Wi-Fi": {"192.0.2.1"}}})
	if err == nil {
		t.Fatalf("RestoreDNSFromSnapshot returned nil although every write failed")
	}
}

func TestResetDNSToSystemDefaultReportsWriteFailure(t *testing.T) {
	if len(getAllNetworkServices()) == 0 {
		t.Skip("no services")
	}
	orig := run
	run = func(string, ...string) error { return errors.New("networksetup failed") }
	t.Cleanup(func() { run = orig })
	origFlush := flushDNSCache
	flushDNSCache = func() {}
	t.Cleanup(func() { flushDNSCache = origFlush })
	m := NewPlatformManager().(*DarwinManager)
	if err := m.ResetDNSToSystemDefault(); err == nil {
		t.Fatalf("ResetDNSToSystemDefault returned nil although every write failed")
	}
}

func TestDNSRestoreReportsServiceEnumerationFailure(t *testing.T) {
	old := networkServices
	networkServices = func() ([]string, error) { return nil, errors.New("enumeration failed") }
	t.Cleanup(func() { networkServices = old })
	manager := NewPlatformManager().(*DarwinManager)
	if err := manager.ResetDNSToSystemDefault(); err == nil {
		t.Fatal("reset concealed enumeration failure")
	}
	if err := manager.RestoreDNSFromSnapshot(DNSSnapshot{}); err == nil {
		t.Fatal("restore concealed enumeration failure")
	}
}
