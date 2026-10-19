//go:build darwin

package network

import (
	"errors"
	"testing"
)

func TestSplitDNSRemovalFailurePropagatesAndRetainsState(t *testing.T) {
	old := scutilExec
	t.Cleanup(func() { scutilExec = old })
	scutilExec = func(string) ([]byte, error) { return nil, errors.New("dynamic store unavailable") }
	m := &DarwinManager{splitDNSActive: true}
	if err := m.RestoreDNS("utun5"); err == nil || !m.splitDNSActive {
		t.Fatal("failed removal reported restored")
	}
	scutilExec = func(string) ([]byte, error) { return []byte("No such key"), nil }
	if err := m.RestoreDNS("utun5"); err != nil || m.splitDNSActive {
		t.Fatalf("cleanup retry failed: %v", err)
	}
}
