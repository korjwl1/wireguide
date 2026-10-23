package helper

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
)

func TestWantedTransportBackoffKeepsHelperAlive(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["work"] = &domain.WireGuardConfig{Name: "work"}
	h.armShutdownTimer(time.Millisecond, "reconnect gap")
	if h.shutdownTimer != nil {
		h.shutdownTimer.Stop()
		t.Fatal("wanted cached transport was treated as idle")
	}
}
func TestStartupRestoresDNSIntentBeforeHeadlessConnect(t *testing.T) {
	h := newPendingTestHelper(t)
	h.userAppSupport = t.TempDir()
	h.logLevel = new(slog.LevelVar)
	h.monitor = reconnect.NewMonitor(h.manager, nil, nil, reconnect.DefaultConfig())
	if err := os.WriteFile(filepath.Join(h.userAppSupport, "config.json"), []byte(`{"dns_protection":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	h.restoreUserSettings()
	if !h.dnsProtectionWanted || dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("DNS intent not restored or applied without tunnel")
	}
	stubConnected(t, h, tn{"work", "utun4", []string{"10.0.0.53"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if !dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("headless connect lost saved DNS protection")
	}
}
func TestLegacyReconnectPanicReleasesConnectLock(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["work"] = &domain.WireGuardConfig{Name: "work"}
	dnsFW(h).killSwitch = true
	prev := connectUnderKillSwitch
	connectUnderKillSwitch = func(*Helper, *domain.WireGuardConfig) error { panic("injected connect panic") }
	t.Cleanup(func() { connectUnderKillSwitch = prev })
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing injected panic")
			}
		}()
		_ = h.reconnectFn(context.Background(), "")
	}()
	if !h.connectMu.TryLock() {
		t.Fatal("panic leaked connectMu")
	}
	h.connectMu.Unlock()
}
func TestPingExposesWantedAndPendingTransportWithoutGUI(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["retry"] = &domain.WireGuardConfig{Name: "retry"}
	h.pendingDesired["restore"] = struct{}{}
	r, err := h.handlePing(json.RawMessage(nil))
	if err != nil {
		t.Fatal(err)
	}
	p := r.(ipc.PingResponse)
	if p.GUIAttached || len(p.WantedTunnels) != 2 {
		t.Fatalf("wanted helper invisible: %+v", p)
	}
}
func TestSignalDeadlineAttemptsFallback(t *testing.T) {
	signals := make(chan os.Signal, 1)
	ready := make(chan func(), 1)
	finished := make(chan struct{})
	unblock := make(chan struct{})
	defer close(unblock)
	ready <- func() { <-unblock }
	signals <- os.Interrupt
	attempted := make(chan struct{}, 1)
	exited := make(chan int, 1)
	go superviseHelperSignals(signals, ready, finished, 60*time.Millisecond, func(c int) { exited <- c }, func() { attempted <- struct{}{}; <-unblock })
	select {
	case <-attempted:
	case <-time.After(time.Second):
		t.Fatal("deadline skipped fallback")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("fallback exceeded deadline")
	}
}

func TestIdleTimerRechecksNewWantedTransport(t *testing.T) {
	h := newPendingTestHelper(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.server = ipc.NewServer(listener)
	done := make(chan struct{})
	go func() { _ = h.server.Serve(); close(done) }()
	t.Cleanup(h.server.Shutdown)
	h.armShutdownTimer(40*time.Millisecond, "idle before recovery")
	h.mu.Lock()
	h.activeCfgs["work"] = &domain.WireGuardConfig{Name: "work"}
	h.mu.Unlock()
	select {
	case <-done:
		t.Fatal("idle timer shut down a newly wanted transport")
	case <-time.After(80 * time.Millisecond):
	}
}
