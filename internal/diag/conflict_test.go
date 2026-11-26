package diag

import "testing"

func TestFindOverlapsFullTunnel(t *testing.T) {
	overlaps := findOverlaps(
		[]string{"0.0.0.0/0"},
		[]string{"0.0.0.0/0"},
	)
	if len(overlaps) == 0 {
		t.Error("expected overlap for two full tunnels")
	}
}

func TestFindOverlapsSubnetContained(t *testing.T) {
	overlaps := findOverlaps(
		[]string{"10.0.0.0/16"},
		[]string{"10.0.5.0/24"},
	)
	if len(overlaps) == 0 {
		t.Error("expected overlap: /24 is inside /16")
	}
}

func TestFindOverlapsNoConflict(t *testing.T) {
	overlaps := findOverlaps(
		[]string{"10.0.0.0/24"},
		[]string{"192.168.0.0/24"},
	)
	if len(overlaps) != 0 {
		t.Errorf("expected no overlap, got %v", overlaps)
	}
}

func TestFindOverlapsFullVsSubnet(t *testing.T) {
	overlaps := findOverlaps(
		[]string{"0.0.0.0/0"},
		[]string{"10.0.0.0/24"},
	)
	if len(overlaps) == 0 {
		t.Error("full tunnel should overlap with any subnet")
	}
}

func TestNormalizeCIDR(t *testing.T) {
	if normalizeCIDR("10.0.0.1") != "10.0.0.1/32" {
		t.Error("should add /32 to bare IP")
	}
	if normalizeCIDR("10.0.0.0/24") != "10.0.0.0/24" {
		t.Error("should keep existing CIDR")
	}
}

func TestAddressConflicts(t *testing.T) {
	connected := map[string][]string{
		"Branch": {"10.66.66.2/32"},
		"Site":   {"10.66.66.2/32", "fd00::2/128"},
		"Other":  {"10.9.9.9/32"},
	}
	got := AddressConflicts([]string{"10.66.66.2/32", "fd00::2/128"}, connected)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].InterfaceName != "Branch" || got[0].Owner != OwnerAddress || len(got[0].OverlappingIPs) != 1 {
		t.Errorf("first: %+v", got[0])
	}
	if got[1].InterfaceName != "Site" || len(got[1].OverlappingIPs) != 2 {
		t.Errorf("second: %+v", got[1])
	}
	if c := AddressConflicts([]string{"10.0.0.2/24"}, connected); len(c) != 0 {
		t.Errorf("unexpected: %+v", c)
	}
	if c := AddressConflicts([]string{"10.66.66.2/24"}, connected); len(c) != 2 {
		t.Errorf("prefix must be ignored: %+v", c)
	}
}
