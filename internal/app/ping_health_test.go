package app

import (
	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/healthcheck"
	"github.com/korjwl1/wireguide/internal/storage"
	"os"
	"path/filepath"
	"testing"
)

func TestPingHealthMetadataLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunnels")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store := storage.NewTunnelStore(dir)
	// Store.Save performs serialization; validation of cryptographic keys is a
	// connect-time concern and this test never creates a tunnel.
	cfg := &config.WireGuardConfig{Name: "first"}
	cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cfg.Interface.Address = []string{"10.0.0.2/24"}
	cfg.Peers = []config.PeerConfig{{PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", AllowedIPs: []string{"10.0.0.0/24"}}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	service := &TunnelService{tunnelStore: store}
	settings, err := service.GetTunnelPingHealth("first")
	if err != nil || settings.Enabled || settings.IntervalSeconds != 30 {
		t.Fatalf("default: %+v %v", settings, err)
	}
	if err := service.SetTunnelNotes("first", "keep these notes"); err != nil {
		t.Fatal(err)
	}
	settings.Enabled = true
	settings.Targets = []string{"10.0.0.1"}
	if err := service.SaveTunnelPingHealth("first", settings); err != nil {
		t.Fatal(err)
	}
	if err := store.Rename("first", "renamed"); err != nil {
		t.Fatal(err)
	}
	meta, err := store.LoadMeta("renamed")
	if err != nil {
		t.Fatal(err)
	}
	if meta.PingHealth == nil || !meta.PingHealth.Enabled || meta.Notes != "keep these notes" {
		t.Fatalf("metadata lost: %+v", meta)
	}
	if err := service.SaveTunnelPingHealth("renamed", healthcheck.Config{Enabled: true, Targets: []string{"192.0.2.1"}}); err == nil {
		t.Fatal("accepted target outside AllowedIPs")
	}
	if err := store.Delete("renamed"); err != nil {
		t.Fatal(err)
	}
	if err := service.SaveTunnelPingHealth("renamed", settings); err == nil {
		t.Fatal("saved deleted tunnel")
	}
}
