//go:build windows

package network

import (
	"errors"
	"testing"
)

// Split mode must return the sentinel before any netsh call (the manager
// has no state to observe, so a call would also fail the test host-side).
func TestWindowsSetDNSSplitIsUnsupported(t *testing.T) {
	m := &WindowsManager{}
	err := m.SetDNS("wg0", []string{"10.0.0.1", "~corp.lan"})
	if !errors.Is(err, ErrSplitDNSUnsupported) {
		t.Fatalf("err = %v, want ErrSplitDNSUnsupported", err)
	}
	if m.origDNSIface != "" || len(m.origDNS) != 0 {
		t.Fatal("split mode must not capture or touch DNS state")
	}
}
