//go:build darwin

package gui

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/elevate"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/update"
)

func TestSlowAuthorizationDoesNotConsumeReadinessTimeout(t *testing.T) {
	// Darwin Unix socket paths are limited to 104 bytes. t.TempDir embeds
	// the test name and can exceed that limit on this platform.
	dir, err := os.MkdirTemp("/tmp", "wg-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	args := elevate.Args{SocketPath: filepath.Join(dir, "helper.sock")}
	spawn := func(ctx context.Context, _ elevate.Args) error {
		// Longer than the entire readiness budget, as with slow password entry.
		time.Sleep(150 * time.Millisecond)
		if err := ctx.Err(); err != nil {
			return err
		}
		listener, err := ipc.Listen(args.SocketPath, -1, "")
		if err != nil {
			return err
		}
		server := ipc.NewServer(listener)
		server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
			return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: update.CurrentVersion()}, nil
		})
		go server.Serve()
		t.Cleanup(func() { server.Shutdown() })
		return nil
	}
	client, err := spawnAndConnectHelper(context.Background(), args, spawn, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
}

func TestHelperReadinessStillTimesOut(t *testing.T) {
	args := elevate.Args{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}
	spawn := func(context.Context, elevate.Args) error { return nil }
	_, err := spawnAndConnectHelper(context.Background(), args, spawn, 20*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want readiness timeout", err)
	}
}

func TestHelperShutdownDuringAuthorization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spawn := func(context.Context, elevate.Args) error { cancel(); return nil }
	_, err := spawnAndConnectHelper(ctx, elevate.Args{}, spawn, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
}

func TestBackgroundReconnectDoesNotShutDownOldHelper(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wg-reconnect-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := filepath.Join(dir, "s.sock")
	listener, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(listener)
	var shutdowns atomic.Int32
	var current atomic.Bool
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		version := "0.0.0-old"
		if current.Load() {
			version = update.CurrentVersion()
		}
		return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: version}, nil
	})
	server.Handle(ipc.MethodShutdown, func(json.RawMessage) (interface{}, error) { shutdowns.Add(1); return nil, nil })
	server.Handle(ipc.MethodForceShutdown, func(json.RawMessage) (interface{}, error) { shutdowns.Add(1); return nil, nil })
	go server.Serve()
	defer server.Shutdown()
	for i := 0; i < 3; i++ {
		c, err := reconnectHelper(context.Background(), addr)
		if err == nil {
			c.Close()
			t.Fatal("accepted old helper")
		}
	}
	if shutdowns.Load() != 0 {
		t.Fatal("background recovery shut down helper")
	}
	current.Store(true)
	c, err := reconnectHelper(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestBackgroundReconnectHonorsCancellation(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wg-reconnect-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = reconnectHelper(ctx, addr)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("recovery blocked shutdown")
	}
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(time.Second):
		t.Fatal("no connection accepted")
	}
}

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wg-ens-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// With launchd socket activation the connect succeeds at once and the helper
// answers a few seconds later. That must be waited for, never answered with
// the administrator-prompt spawn path.
func TestSlowActivationConnectsWithoutAdminSpawn(t *testing.T) {
	origPlist := plistNeedsReinstall
	plistNeedsReinstall = func(elevate.Args) bool { return false }
	t.Cleanup(func() { plistNeedsReinstall = origPlist })

	addr := filepath.Join(shortSocketDir(t), "helper.sock")
	listener, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(listener)
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		time.Sleep(3 * time.Second) // launchd throttle + helper startup
		return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: update.CurrentVersion()}, nil
	})
	go server.Serve()
	t.Cleanup(server.Shutdown)

	var spawned atomic.Int32
	spawn := func(context.Context, elevate.Args) error {
		spawned.Add(1)
		return errors.New("admin spawn must not run")
	}
	client, err := ensureHelperWith(context.Background(), elevate.Args{SocketPath: addr}, spawn, "")
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if spawned.Load() != 0 {
		t.Fatal("admin spawn function was called although the helper answered")
	}
}

func TestFirstContactBudget(t *testing.T) {
	dir := shortSocketDir(t)
	missing := filepath.Join(dir, "missing.sock")
	if got := firstContactBudget(missing); got != plainContactBudget {
		t.Errorf("budget without socket file = %v, want %v", got, plainContactBudget)
	}
	present := filepath.Join(dir, "present.sock")
	if err := os.WriteFile(present, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got := firstContactBudget(present); got != activatedContactBudget {
		t.Errorf("budget with socket file = %v, want %v", got, activatedContactBudget)
	}
	if activatedContactBudget < 15*time.Second || reconnectBudget < 10*time.Second {
		t.Error("budgets must cover launchd ThrottleInterval plus helper startup")
	}
}

// An old helper still listening on the pre-activation path must get its
// graceful Shutdown before the reinstall (bootout would otherwise kill it).
func TestLegacyHelperGetsGracefulShutdownBeforeReinstall(t *testing.T) {
	dir := shortSocketDir(t)
	legacy := filepath.Join(dir, "legacy.sock")
	newAddr := filepath.Join(dir, "new.sock")

	l, err := ipc.Listen(legacy, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	old := ipc.NewServer(l)
	var shutdowns atomic.Int32
	old.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: "0.0.0-old", PID: 99999}, nil
	})
	old.Handle(ipc.MethodShutdown, func(json.RawMessage) (interface{}, error) { shutdowns.Add(1); return ipc.Empty{}, nil })
	go old.Serve()
	t.Cleanup(old.Shutdown)

	var spawnedAfterShutdown atomic.Bool
	var forced atomic.Bool
	spawn := func(_ context.Context, a elevate.Args) error {
		spawnedAfterShutdown.Store(shutdowns.Load() == 1)
		forced.Store(a.ForceReinstall)
		nl, err := ipc.Listen(a.SocketPath, -1, "")
		if err != nil {
			return err
		}
		srv := ipc.NewServer(nl)
		srv.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
			return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: update.CurrentVersion()}, nil
		})
		go srv.Serve()
		t.Cleanup(srv.Shutdown)
		return nil
	}
	client, err := ensureHelperWith(context.Background(), elevate.Args{SocketPath: newAddr}, spawn, legacy)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if shutdowns.Load() != 1 {
		t.Fatalf("legacy helper received %d Shutdown calls, want 1", shutdowns.Load())
	}
	if !spawnedAfterShutdown.Load() || !forced.Load() {
		t.Fatalf("spawn must run after the legacy Shutdown with ForceReinstall (afterShutdown=%v forced=%v)",
			spawnedAfterShutdown.Load(), forced.Load())
	}
}
