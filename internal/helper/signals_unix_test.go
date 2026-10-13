//go:build !windows

package helper

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

type signalTestFirewall struct {
	firewall.FirewallManager
	dir     string
	blocked bool
	started chan struct{}
}

func (f *signalTestFirewall) Cleanup() error {
	if err := os.WriteFile(filepath.Join(f.dir, "cleanup-started"), nil, 0600); err != nil {
		return err
	}
	close(f.started)
	if f.blocked {
		select {}
	}
	return os.WriteFile(filepath.Join(f.dir, "cleanup-completed"), nil, 0600)
}

// Real signals run in a subprocess so the test runner is never terminated.
// Production IPC and Helper.cleanup are used with an empty manager and a
// fake firewall, requiring neither root nor changes to the host network.
func TestNativeHelperTerminationSignals(t *testing.T) {
	for _, tc := range []struct {
		mode string
		sig  os.Signal
	}{
		{"normal-term", syscall.SIGTERM},
		{"normal-int", os.Interrupt},
		{"cleanup-blocked", syscall.SIGTERM},
		{"startup-blocked", os.Interrupt},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperSignalProcess$")
			cmd.Env = append(os.Environ(), "WIREGUIDE_SIGNAL_TEST_MODE="+tc.mode, "WIREGUIDE_SIGNAL_TEST_DIR="+dir)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill() }()
			deadline := time.Now().Add(4 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("signal subprocess did not become ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			start := time.Now()
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("helper did not exit cleanly after %s: %v", tc.sig, err)
			}
			if time.Since(start) > 6*time.Second {
				t.Fatal("signal deadline did not bound startup/cleanup")
			}
			if tc.mode == "normal-term" || tc.mode == "normal-int" {
				if _, err := os.Stat(filepath.Join(dir, "cleanup-completed")); err != nil {
					t.Fatal("signal skipped firewall cleanup")
				}
				if names := loadDesiredState(dir); len(names) != 0 {
					t.Fatalf("clean signal shutdown retained desired tunnels: %v", names)
				}
			}
		})
	}
}

func TestHelperSignalProcess(t *testing.T) {
	mode := os.Getenv("WIREGUIDE_SIGNAL_TEST_MODE")
	if mode == "" {
		t.Skip("subprocess fixture")
	}
	dir := os.Getenv("WIREGUIDE_SIGNAL_TEST_DIR")
	ready := make(chan func(), 1)
	finished := make(chan struct{})
	stop := watchHelperSignals(ready, finished)
	defer stop()
	if mode == "startup-blocked" {
		if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager := tunnel.NewManager(dir)
	fw := &signalTestFirewall{dir: dir, blocked: mode == "cleanup-blocked", started: make(chan struct{})}
	h := &Helper{server: ipc.NewServer(ln), manager: manager, firewall: fw, done: make(chan struct{}), dataDir: dir}
	h.monitor = reconnect.NewMonitor(manager, nil, nil, reconnect.DefaultConfig())
	if err := saveDesiredState(dir, []string{"wanted-before-signal"}); err != nil {
		t.Fatal(err)
	}
	ready <- h.shutdown
	if mode == "cleanup-blocked" {
		go h.cleanup()
		<-fw.started // signal arrives after ordinary cleanup has already begun
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.server.Serve(); err != nil {
		t.Fatal(err)
	}
	h.cleanup()
	close(finished)
}
