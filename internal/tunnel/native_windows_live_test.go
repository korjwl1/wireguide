//go:build windows

package tunnel

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/firewall"
	"golang.org/x/sys/windows"
)

// Opt-in live test: run elevated with WIREGUIDE_TEST_WINDOWS_CONFIG pointing
// to a working IPv4 full-tunnel configuration with a DNS server. Disconnect
// all other VPNs first. The executable needs wintun.dll beside it.
// Uses in-process UAPI because the external protected pipe is unavailable
// when the helper runs as an elevated user rather than LocalSystem.
func TestWindowsNativeListenPortRebind(t *testing.T) {
	file := os.Getenv("WIREGUIDE_TEST_WINDOWS_CONFIG")
	if file == "" {
		t.Skip("requires an explicitly supplied live Windows VPN configuration")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("run this opt-in test as administrator")
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseReader(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	servers := cfg.Interface.ParseDNS().Servers
	if !cfg.IsFullTunnel() || len(servers) == 0 {
		t.Fatal("the live fixture must be a full tunnel with a DNS server")
	}
	cfg.Name = "WG-Windows-Port-Verify"
	fw := firewall.NewPlatformFirewall()
	t.Cleanup(func() {
		if err := fw.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	m := NewManager(t.TempDir())
	m.SetEndpointProtector(fw)
	t.Cleanup(m.DisconnectAll)
	if err := m.Connect(cfg); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	engine := m.tunnels[cfg.Name].engine
	m.mu.Unlock()
	if engine.SocketPinV4 == 0 {
		t.Fatal("the native IPv4 socket was not pinned to an underlay")
	}
	query := func(stage string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort(servers[0], "53"))
		}}
		// Adapter address/route readiness and the remote peer handshake may
		// lag Connect or a socket rebind. Require working traffic within a
		// bounded interval rather than failing on the first transient route.
		started := time.Now()
		for {
			attempt, stop := context.WithTimeout(ctx, 3*time.Second)
			_, err := r.LookupHost(attempt, "example.com")
			stop()
			if err == nil {
				t.Logf("%s: tunnel DNS responded after %s", stage, time.Since(started))
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("%s: DNS traffic through the live tunnel failed: %v", stage, err)
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	port := func() string {
		t.Helper()
		state, err := queryUAPIInProcess(engine)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(state, "\n") {
			if value, ok := strings.CutPrefix(line, "listen_port="); ok {
				return value
			}
		}
		t.Fatal("the device did not report its listen port")
		return ""
	}
	query("before rebind")
	before := port()
	if err := engine.wgDevice.IpcSet("listen_port=0\n"); err != nil {
		t.Fatal(err)
	}
	after := port()
	if after == "0" || after == before {
		t.Fatalf("listen port did not change: %s -> %s", before, after)
	}
	query("after rebind")
	t.Logf("native pinned socket rebind %s -> %s retained working tunnel traffic", before, after)
	started := time.Now()
	if err := m.DisconnectTunnel(cfg.Name); err != nil {
		t.Fatal(err)
	}
	t.Logf("disconnect after rebind completed in %s", time.Since(started))
}
