package tunnel

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
