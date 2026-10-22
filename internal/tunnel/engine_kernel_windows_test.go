//go:build windows

package tunnel

import (
	"encoding/base64"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
)

func TestKernelAdapterGUIDStable(t *testing.T) {
	first := kernelAdapterGUID("office")
	second := kernelAdapterGUID("office")
	other := kernelAdapterGUID("home")
	if first != second {
		t.Fatal("GUID is not deterministic for the same tunnel name")
	}
	if first == other {
		t.Fatal("different tunnel names produced the same GUID")
	}
	if first.Data3>>12 != 5 {
		t.Fatalf("GUID version = %d, want 5", first.Data3>>12)
	}
	if first.Data4[0]&0xc0 != 0x80 {
		t.Fatalf("GUID variant bits = %#x, want RFC 4122", first.Data4[0])
	}
}

func TestKernelConfigurationIPv6Endpoint(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := &config.WireGuardConfig{
		Interface: config.InterfaceConfig{PrivateKey: key},
		Peers: []config.PeerConfig{{
			PublicKey:  key,
			Endpoint:   "[2001:db8::1]:51820",
			AllowedIPs: []string{"::/0"},
		}},
	}
	kernelCfg, err := kernelConfiguration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := kernelCfg.Peers[0].Endpoint.Addr().String(); got != "2001:db8::1" {
		t.Fatalf("endpoint address = %q, want 2001:db8::1", got)
	}
	if got := kernelCfg.Peers[0].Endpoint.Port(); got != 51820 {
		t.Fatalf("endpoint port = %d, want 51820", got)
	}
}

func TestKernelConfigurationRejectsHostnameEndpoint(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := &config.WireGuardConfig{
		Interface: config.InterfaceConfig{PrivateKey: key},
		Peers: []config.PeerConfig{{
			PublicKey:  key,
			Endpoint:   "example.com:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
	if _, err := kernelConfiguration(cfg); err == nil {
		t.Fatal("hostname endpoint was accepted; NewEngine is expected to resolve it first")
	}
}
