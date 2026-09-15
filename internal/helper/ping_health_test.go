package helper

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/healthcheck"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// No actual tunnel, routes or firewall state is touched by these tests.
type pingRetryManager struct{ disconnects atomic.Int32 }

func (*pingRetryManager) IsConnected() bool                       { return false }
func (*pingRetryManager) ActiveTunnel() string                    { return "" }
func (*pingRetryManager) Status() *tunnel.ConnectionStatus        { return nil }
func (*pingRetryManager) AllStatuses() []*tunnel.ConnectionStatus { return nil }
func (m *pingRetryManager) Disconnect() error                     { m.disconnects.Add(1); return nil }
func (m *pingRetryManager) DisconnectTunnel(string) error         { return m.Disconnect() }

func TestSavedPingSettingsInvalidatePendingRetry(t *testing.T) {
	for _, change := range []string{"disable", "targets", "rename", "delete"} {
		t.Run(change, func(t *testing.T) {
			store := storage.NewTunnelStore(t.TempDir())
			cfg := &config.WireGuardConfig{Name: "review"}
			cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			cfg.Interface.Address = []string{"10.0.0.2/24"}
			cfg.Peers = []config.PeerConfig{{PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", AllowedIPs: []string{"10.0.0.0/24"}}}
			if err := store.Save(cfg); err != nil {
				t.Fatal(err)
			}
			service := app.NewTunnelService(store, nil, nil, nil)
			settings, err := (healthcheck.Config{Enabled: true, Targets: []string{"10.0.0.1"}}).Normalize()
			if err != nil {
				t.Fatal(err)
			}
			if err := service.SaveTunnelPingHealth("review", settings); err != nil {
				t.Fatal(err)
			}
			h := &Helper{userTunnelStore: store}
			manager := &pingRetryManager{}
			var attempts atomic.Int32
			queued := make(chan struct{}, 1)
			monitor := reconnect.NewMonitor(manager, func(context.Context, string) error {
				attempts.Add(1)
				return nil
			}, func(state reconnect.State) {
				if state.Reconnecting {
					select {
					case queued <- struct{}{}:
					default:
					}
				}
			}, reconnect.Config{InitialDelay: 150 * time.Millisecond, MaxDelay: time.Second})
			monitor.Start()
			defer monitor.Stop()
			monitor.ReconnectTunnelIfIdle("review", h.pingRetryGuard("review", settings))
			select {
			case <-queued:
			case <-time.After(time.Second):
				t.Fatal("retry was not queued")
			}
			switch change {
			case "disable":
				settings.Enabled = false
				err = service.SaveTunnelPingHealth("review", settings)
			case "targets":
				settings.Targets = []string{"10.0.0.3"}
				err = service.SaveTunnelPingHealth("review", settings)
			case "rename":
				err = store.Rename("review", "renamed")
			case "delete":
				err = store.Delete("review")
			}
			if err != nil {
				t.Fatal(err)
			}
			// Do not call the periodic sweep: the attempt boundary itself must
			// catch a save that lands between two helper health ticks.
			deadline := time.Now().Add(2 * time.Second)
			for monitor.GetState().Reconnecting && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if monitor.GetState().Reconnecting {
				t.Fatal("invalid retry was not removed")
			}
			if attempts.Load() != 0 || manager.disconnects.Load() != 0 {
				t.Fatalf("stale settings triggered disconnect=%d reconnect=%d", manager.disconnects.Load(), attempts.Load())
			}
		})
	}
}
