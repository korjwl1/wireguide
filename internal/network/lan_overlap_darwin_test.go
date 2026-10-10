//go:build darwin

package network

import "testing"

// With only an overlapping CIDR, the guard must skip it before any `route`
// invocation: AddRoutes succeeds without root and installs nothing (a
// missed guard would try `route add` and fail without privileges).
func TestAddRoutes_SkipsLANOverlap(t *testing.T) {
	withLocalAddrs(t, "192.168.50.65/24")
	m := NewPlatformManager()
	if err := m.AddRoutes("utun99", []string{"192.168.50.0/24"}, false, nil, "", ""); err != nil {
		t.Fatalf("AddRoutes should skip the overlapping route and succeed: %v", err)
	}
}
