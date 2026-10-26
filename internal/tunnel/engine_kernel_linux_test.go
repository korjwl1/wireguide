//go:build linux

package tunnel

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/korjwl1/wireguide/internal/config"
)

func TestKernelWgtypesConfig(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.WireGuardConfig{
		Interface: config.InterfaceConfig{
			PrivateKey: privateKey.String(),
			ListenPort: 51820,
		},
		Peers: []config.PeerConfig{{
			PublicKey:           publicKey.String(),
			PresharedKey:        presharedKey.String(),
			Endpoint:            "198.51.100.7:51821",
			AllowedIPs:          []string{"10.0.0.0/24", "2001:db8::/32"},
			PersistentKeepalive: 25,
		}},
	}

	got, err := kernelWgtypesConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey == nil || *got.PrivateKey != privateKey {
		t.Fatal("private key was not translated")
	}
	if got.ListenPort == nil || *got.ListenPort != 51820 {
		t.Fatalf("listen port = %v, want 51820", got.ListenPort)
	}
	if !got.ReplacePeers {
		t.Fatal("ReplacePeers must be true to mirror the profile instead of appending")
	}
	if len(got.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(got.Peers))
	}
	peer := got.Peers[0]
	if peer.PublicKey != publicKey {
		t.Fatal("peer public key was not translated")
	}
	if peer.PresharedKey == nil || *peer.PresharedKey != presharedKey {
		t.Fatal("peer preshared key was not translated")
	}
	if peer.Endpoint == nil {
		t.Fatal("peer endpoint was not translated")
	}
	if peer.Endpoint.String() != "198.51.100.7:51821" {
		t.Fatalf("endpoint = %s", peer.Endpoint)
	}
	if peer.PersistentKeepaliveInterval == nil || *peer.PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("keepalive = %v, want 25s", peer.PersistentKeepaliveInterval)
	}
	if !peer.ReplaceAllowedIPs {
		t.Fatal("ReplaceAllowedIPs must be true")
	}
	if len(peer.AllowedIPs) != 2 {
		t.Fatalf("allowed IPs = %d, want 2", len(peer.AllowedIPs))
	}
	_, want4, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if peer.AllowedIPs[0].String() != want4.String() {
		t.Fatalf("allowed IP = %s, want %s", peer.AllowedIPs[0].String(), want4.String())
	}
}

func TestKernelWgtypesConfigRejectsInvalidInputs(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	valid := func() *config.WireGuardConfig {
		return &config.WireGuardConfig{
			Interface: config.InterfaceConfig{PrivateKey: privateKey.String()},
			Peers: []config.PeerConfig{{
				PublicKey:  publicKey.String(),
				AllowedIPs: []string{"10.0.0.0/24"},
			}},
		}
	}

	tests := map[string]func(*config.WireGuardConfig){
		"interface key": func(c *config.WireGuardConfig) { c.Interface.PrivateKey = "not-base64" },
		"peer key":      func(c *config.WireGuardConfig) { c.Peers[0].PublicKey = "not-base64" },
		"preshared key": func(c *config.WireGuardConfig) { c.Peers[0].PresharedKey = "not-base64" },
		"endpoint":      func(c *config.WireGuardConfig) { c.Peers[0].Endpoint = "198.51.100.7" },
		"allowed IP":    func(c *config.WireGuardConfig) { c.Peers[0].AllowedIPs = []string{"10.0.0.0/33"} },
		"listen port":   func(c *config.WireGuardConfig) { c.Interface.ListenPort = 70000 },
		"keepalive":     func(c *config.WireGuardConfig) { c.Peers[0].PersistentKeepalive = 70000 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			mutate(cfg)
			if _, err := kernelWgtypesConfig(cfg); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
