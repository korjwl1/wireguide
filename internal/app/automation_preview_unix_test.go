//go:build !windows

package app

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/network"
	"github.com/korjwl1/wireguide/internal/storage"
)

func TestAutomationPreviewSharesOnlyOneRequestLocalNetworkSnapshot(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wgp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "s")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(l)
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil
	})
	server.Handle(ipc.MethodAutomationPreview, func(json.RawMessage) (interface{}, error) {
		return ipc.AutomationPreviewResponse{Tunnels: []ipc.AutomationTunnelDecision{
			{Name: "off", Decision: "connect"},
			{Name: "a", Decision: "connect"},
			{Name: "b", Decision: "connect"},
			{Name: "active", Decision: "connect", Active: true},
		}}, nil
	})
	go server.Serve()
	t.Cleanup(func() { server.Shutdown() })
	client, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	store := storage.NewTunnelStore(t.TempDir())
	for _, name := range []string{"a", "b", "off", "active"} {
		cfg := &config.WireGuardConfig{Name: name}
		cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		if name == "off" {
			cfg.Interface.Table = "off"
		}
		cidr := "192.168.1.0/24"
		if name == "b" {
			cidr = "10.0.0.0/24"
		}
		cfg.Peers = []config.PeerConfig{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{cidr}}}
		if err := store.Save(cfg); err != nil {
			t.Fatal(err)
		}
	}
	settings := storage.NewSettingsStore(t.TempDir())
	svc := NewTunnelService(store, settings, nil, ipc.NewClientHolder(client))
	old := network.LocalPhysicalAddrs
	t.Cleanup(func() { network.LocalPhysicalAddrs = old })
	snapshots := 0
	ip := net.ParseIP("192.168.1.42")
	network.LocalPhysicalAddrs = func() []*net.IPNet {
		snapshots++
		return []*net.IPNet{{IP: ip, Mask: net.CIDRMask(24, 32)}}
	}
	first := svc.GetAutomationPreview()
	if snapshots != 1 || verdictFor(t, first, "a").Verdict != VerdictOverlap || verdictFor(t, first, "b").Verdict != VerdictConnect {
		t.Fatalf("first snapshot: count=%d preview=%+v", snapshots, first)
	}
	if verdictFor(t, first, "off").Verdict != VerdictConnect || verdictFor(t, first, "active").Verdict != VerdictConnect {
		t.Fatal("table=off and active tunnels must not be marked as overlapping")
	}
	ip = net.ParseIP("10.0.0.42")
	second := svc.GetAutomationPreview()
	if snapshots != 2 || verdictFor(t, second, "a").Verdict != VerdictConnect || verdictFor(t, second, "b").Verdict != VerdictOverlap {
		t.Fatalf("next request must use a fresh snapshot: count=%d preview=%+v", snapshots, second)
	}
}
