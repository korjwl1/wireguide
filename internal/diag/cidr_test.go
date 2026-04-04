package diag

import "testing"

func TestCalculateCIDR24(t *testing.T) {
	info, err := CalculateCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if info.Network != "192.168.1.0" {
		t.Errorf("network: %s", info.Network)
	}
	if info.Broadcast != "192.168.1.255" {
		t.Errorf("broadcast: %s", info.Broadcast)
	}
	if info.FirstHost != "192.168.1.1" {
		t.Errorf("first host: %s", info.FirstHost)
	}
	if info.LastHost != "192.168.1.254" {
		t.Errorf("last host: %s", info.LastHost)
	}
	if info.TotalHosts != 254 {
		t.Errorf("total hosts: %d", info.TotalHosts)
	}
}

func TestCalculateCIDR32(t *testing.T) {
	info, err := CalculateCIDR("10.0.0.1/32")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if info.TotalHosts != 1 {
		t.Errorf("expected 1 host, got %d", info.TotalHosts)
	}
}

func TestCalculateCIDR16(t *testing.T) {
	info, err := CalculateCIDR("172.16.0.0/16")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if info.TotalHosts != 65534 {
		t.Errorf("expected 65534 hosts, got %d", info.TotalHosts)
	}
}

func TestCalculateCIDRInvalid(t *testing.T) {
	_, err := CalculateCIDR("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}
