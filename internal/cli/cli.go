// Package cli implements `wireguide ctl …` — a scriptable command-line
// interface to the running helper (issue #10). Like Tailscale's `tailscale`
// vs `tailscaled`, it's a thin third IPC client alongside the GUI: it talks
// to the already-elevated helper over the same local socket, so unlike
// wg-quick it needs no per-command sudo, works cross-platform, and inherits
// the app's kill switch / DNS protection / loop protection / automation.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// Run dispatches a `ctl` subcommand. args is everything after "ctl".
// Returns a process exit code.
func Run(args []string) int {
	// Silence the shared libraries' info/debug slog output (e.g. the ipc
	// client's "Close() called") so CLI output stays clean; real problems
	// surface as command errors on stderr.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))

	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		usage(os.Stdout)
		return 0
	case "status":
		return cmdStatus(rest)
	case "list", "ls":
		return cmdList(rest)
	case "connect", "up":
		return cmdConnect(rest)
	case "disconnect", "down":
		return cmdDisconnect(rest)
	case "import":
		return cmdImport(rest)
	case "automation":
		return cmdAutomation(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `wireguide ctl — control the WireGuide helper from the command line

Usage:
  wireguide ctl status                 show connection status
  wireguide ctl list                   list tunnels (● = connected)
  wireguide ctl connect <name>         connect a tunnel
  wireguide ctl disconnect [name]      disconnect one tunnel (or all)
  wireguide ctl import <file> [name]   import a .conf (name defaults to filename)
  wireguide ctl automation             show what the automation engine decides now

The WireGuide app (or its helper) must be running.
`)
}

// dialHelper connects to the running helper's IPC socket. The CLI does not
// spawn/elevate a helper itself — it attaches to the one the app started, so
// a plain `ctl` invocation never triggers an admin prompt.
func dialHelper() (*ipc.Client, error) {
	addr := ipc.DefaultSocketPath()
	c, err := ipc.NewClient(addr)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the WireGuide helper (is the app running?): %w", err)
	}
	// Confirm it's actually alive, not just a stale socket.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var ping ipc.PingResponse
	if err := c.CallWithContext(ctx, ipc.MethodPing, nil, &ping); err != nil {
		c.Close()
		return nil, fmt.Errorf("the WireGuide helper is not responding (is the app running?): %w", err)
	}
	return c, nil
}

func tunnelStore() (*storage.TunnelStore, error) {
	paths, err := storage.GetPaths()
	if err != nil {
		return nil, err
	}
	return storage.NewTunnelStore(paths.TunnelsDir), nil
}

func cmdStatus(_ []string) int {
	c, err := dialHelper()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()

	var active ipc.ActiveTunnelsResponse
	if err := c.Call(ipc.MethodActiveTunnels, nil, &active); err != nil {
		fmt.Fprintln(os.Stderr, "status:", err)
		return 1
	}
	if len(active.Names) == 0 {
		fmt.Println("disconnected")
		return 0
	}
	var st domain.ConnectionStatus
	if err := c.Call(ipc.MethodStatus, nil, &st); err != nil {
		fmt.Fprintln(os.Stderr, "status:", err)
		return 1
	}
	// Per-tunnel detail when available; fall back to the aggregate.
	rows := st.Tunnels
	if len(rows) == 0 {
		rows = []domain.ConnectionStatus{st}
	}
	for _, r := range rows {
		hs := r.LastHandshake
		if hs == "" {
			hs = "—"
		}
		fmt.Printf("● %s  %s  rx=%s tx=%s  handshake=%s\n",
			r.TunnelName, r.Duration, humanBytes(r.RxBytes), humanBytes(r.TxBytes), hs)
	}
	return 0
}

func cmdList(_ []string) int {
	store, err := tunnelStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		return 1
	}
	names, err := store.List()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		return 1
	}
	// Active markers are best-effort — a missing helper just means nothing
	// is shown as connected.
	activeSet := map[string]bool{}
	if c, err := dialHelper(); err == nil {
		var active ipc.ActiveTunnelsResponse
		if c.Call(ipc.MethodActiveTunnels, nil, &active) == nil {
			for _, n := range active.Names {
				activeSet[n] = true
			}
		}
		c.Close()
	}
	if len(names) == 0 {
		fmt.Println("(no tunnels)")
		return 0
	}
	for _, n := range names {
		marker := "○"
		if activeSet[n] {
			marker = "●"
		}
		fmt.Printf("%s %s\n", marker, n)
	}
	return 0
}

func cmdConnect(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl connect <name>")
		return 2
	}
	name := args[0]
	store, err := tunnelStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 1
	}
	cfg, err := store.Load(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: no such tunnel %q: %v\n", name, err)
		return 1
	}
	c, err := dialHelper()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	// Connect can take a while (handshake, route setup).
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.CallWithContext(ctx, ipc.MethodConnect, ipc.ConnectRequest{Config: cfg}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 1
	}
	fmt.Printf("connected %s\n", name)
	return 0
}

func cmdDisconnect(args []string) int {
	name := ""
	if len(args) >= 1 {
		name = args[0]
	}
	c, err := dialHelper()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.CallWithContext(ctx, ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: name}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "disconnect:", err)
		return 1
	}
	if name == "" {
		fmt.Println("disconnected all")
	} else {
		fmt.Printf("disconnected %s\n", name)
	}
	return 0
}

func cmdImport(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl import <file> [name]")
		return 2
	}
	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		return 1
	}
	name := ""
	if len(args) >= 2 {
		name = args[1]
	} else {
		base := filepath.Base(path)
		name = strings.TrimSuffix(base, filepath.Ext(base))
	}
	if _, err := config.Parse(string(data)); err != nil {
		fmt.Fprintf(os.Stderr, "import: %q is not a valid WireGuard config: %v\n", path, err)
		return 1
	}
	store, err := tunnelStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		return 1
	}
	if _, err := store.ImportFromContent(name, string(data)); err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		return 1
	}
	fmt.Printf("imported %s\n", name)
	return 0
}

func cmdAutomation(_ []string) int {
	c, err := dialHelper()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	var resp ipc.AutomationPreviewResponse
	if err := c.Call(ipc.MethodAutomationPreview, nil, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	ssid := resp.SSID
	if ssid == "" {
		ssid = "(none)"
	}
	fmt.Printf("network context: ssid=%s  physical-ips=%v\n", ssid, resp.PhysicalIPs)
	if len(resp.Tunnels) == 0 {
		fmt.Println("no tunnels have automation rules")
		return 0
	}
	for _, tdec := range resp.Tunnels {
		state := "down"
		if tdec.Active {
			state = "up"
		}
		fmt.Printf("  %-28s rules=%d  currently=%s  decision=%s\n",
			tdec.Name, tdec.RuleCount, state, tdec.Decision)
	}
	return 0
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
