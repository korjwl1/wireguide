// Package cli implements `wireguide ctl …` — a scriptable command-line
// interface to the running helper (issue #10). Like Tailscale's `tailscale`
// vs `tailscaled`, it's a thin third IPC client alongside the GUI: it talks
// to the already-elevated helper over the same local socket, so unlike
// wg-quick it needs no per-command sudo, works cross-platform, and inherits
// the app's kill switch / DNS protection / loop protection / automation.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"syscall"
	"time"

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
	case "start":
		return cmdStart(rest)
	case "stop":
		return cmdStop(rest)
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
	case "rename":
		return cmdRename(rest)
	case "delete", "rm":
		return cmdDelete(rest)
	case "automation":
		return cmdAutomation(rest)
	case "set":
		return cmdSet(rest)
	case "dnsleak":
		return cmdDNSLeak(rest)
	case "routes":
		return cmdRoutes(rest)
	case "install-skills":
		return cmdInstallSkills(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `wireguide ctl — control the WireGuide helper from the command line

App:
  wireguide ctl start                     launch WireGuide (app + helper) and wait
  wireguide ctl stop                      quit WireGuide (app + helper)

Tunnels:
  wireguide ctl status [--json]           show connection status
  wireguide ctl list [--json]             list tunnels (● = connected)
  wireguide ctl connect <name>            connect a tunnel
  wireguide ctl disconnect [name]         disconnect one tunnel (or all)
  wireguide ctl import <file> [name]      import a .conf (name defaults to filename)
  wireguide ctl rename <old> <new>        rename a tunnel
  wireguide ctl delete <name>             delete a tunnel (disconnects first if active)

Automation (per-tunnel connect/disconnect rules):
  wireguide ctl automation                show the engine's current decision
  wireguide ctl automation rules <name>   list a tunnel's rules (in priority order)
  wireguide ctl automation add <name> <connect|disconnect> <cond>
                                          append a rule; <cond> is one of:
                                            ssid:<wifi-name>   subnet:<CIDR>
                                            mac:<gateway-MAC>  else
                                          or negated: not-ssid:<name> not-subnet:<CIDR>
                                            not-mac:<MAC> (matches only when the value is
                                            known and different; unknown holds, see README)
  wireguide ctl automation rm <name> <n>  remove rule number <n> (from 'rules')

Settings & diagnostics:
  wireguide ctl set killswitch <on|off>       block non-VPN traffic if the tunnel drops
  wireguide ctl set dns-protection <on|off>   pin DNS to the tunnel
  wireguide ctl set healthcheck <on|off>      handshake monitor + auto-reconnect
  wireguide ctl set pin-interface <on|off>    bind sockets to the upstream interface
  wireguide ctl set loglevel <debug|info|warn|error>
  wireguide ctl dnsleak                        check whether DNS leaks outside the tunnel
  wireguide ctl routes                         show the OS routing table

Coding agents:
  wireguide ctl install-skills [--target claude,codex,opencode,hermes]
                                          teach coding agents how to use 'wireguide ctl'
                                          (installs into every detected agent by default)

Examples:
  wireguide ctl automation add work disconnect mac:b0:38:6c:54:8b:ab
  wireguide ctl automation add work connect else
  wireguide ctl automation add vpn disconnect ssid:HomeWiFi
  wireguide ctl automation add vpn connect not-ssid:HomeWiFi

WireGuide must be running for connect/disconnect/status — start it with
'wireguide ctl start' (or by opening the app). Nothing else starts it for you.
list, import, rename, delete and automation edits work against local files.
`)
}

// dialHelper connects to the running helper's IPC socket and requires that
// the app is actually running. The CLI does not spawn/elevate a helper
// itself — it attaches to the one the app started.
//
// On macOS the helper socket is owned by launchd, so a successful dial no
// longer proves the app is running: the dial itself starts the helper. The
// helper therefore reports whether a GUI is attached (PingResponse.GUIAttached)
// and a helper without one is treated as "app not running" — the CLI never
// acts through, or reports on, a helper nobody opened. (The probe may have
// started that helper; it exits on its own after a short idle grace.)
//
// The client is TRANSIENT: the helper must not mistake a CLI command for a
// GUI attaching and detaching. Without that, every `ctl` invocation would
// re-arm the helper's 10s "GUI disconnected" shutdown window — a status
// query would cut the helper's life short. See ipc.Request.Transient.
func dialHelper() (*ipc.Client, error) {
	client, _, err := contactHelper(requireWorkingHelper)
	return client, err
}

// dialHelperStrict requires an attached GUI for ctl start semantics.
func dialHelperStrict() (*ipc.Client, error) {
	client, _, err := contactHelper(requireGUIHelper)
	return client, err
}

var errAppNotRunning = fmt.Errorf("WireGuide is not running (open the app, or run 'wireguide ctl start')")

// appRunning interprets a ping: a helper that predates GUIAttached (protocol
// minor < 2) cannot say, so it is assumed to have its app, as before.
func appRunning(p ipc.PingResponse) bool {
	return !p.GUIKnown() || p.GUIAttached
}

// helperSocketPath is a seam so tests can point the CLI at a private socket
// (DefaultSocketPath is fixed on macOS).
var helperSocketPath = ipc.DefaultSocketPath

// dialHelperRaw connects and pings without judging whether a GUI is attached.
func dialHelperRaw() (*ipc.Client, ipc.PingResponse, error) {
	return contactHelper(anyHelper)
}

type helperPolicy uint8

const (
	anyHelper helperPolicy = iota
	requireWorkingHelper
	requireGUIHelper
)

func contactHelper(policy helperPolicy) (*ipc.Client, ipc.PingResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout())
	defer cancel()
	client, err := ipc.NewTransientClientContext(ctx, helperSocketPath())
	if err != nil {
		return nil, ipc.PingResponse{}, fmt.Errorf("cannot reach the WireGuide helper: %w", err)
	}
	ping := client.Handshake()
	reject := func(err error) (*ipc.Client, ipc.PingResponse, error) {
		client.Close()
		return nil, ping, err
	}
	switch policy {
	case requireGUIHelper:
		if !appRunning(ping) {
			return reject(errAppNotRunning)
		}
	case requireWorkingHelper:
		if !helperWorking(ping) {
			active := activeTunnelCount(client)
			if active < 0 {
				return reject(errors.New("cannot verify the helper's active tunnels"))
			}
			if active == 0 {
				return reject(errAppNotRunning)
			}
		}
	}
	return client, ping, nil
}

// pingTimeout is how long the CLI waits for a helper to answer. On macOS the
// dial may be what starts the helper (launchd ThrottleInterval + startup).
func pingTimeout() time.Duration {
	if runtime.GOOS == "darwin" {
		return 15 * time.Second
	}
	return 2 * time.Second
}

// userPaths keeps CLI file access on the same user profile and allows isolated
// command tests without changing the process home directory.
var userPaths = storage.GetPaths

func helperAbsent(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		_, statErr := os.Lstat(helperSocketPath())
		return errors.Is(statErr, os.ErrNotExist)
	}
	return false
}

func tunnelStore() (*storage.TunnelStore, error) {
	paths, err := userPaths()
	if err != nil {
		return nil, err
	}
	// Create the data dirs if the CLI is the first thing to run on a fresh
	// install (before the GUI has ever launched) — otherwise `import`'s
	// atomic write into a nonexistent tunnels dir fails with ENOENT
	// (issue #10).
	if err := paths.EnsureDirs(); err != nil {
		return nil, err
	}
	return storage.NewTunnelStore(paths.TunnelsDir), nil
}

// tunnelListEntry is the --json shape for `ctl list`; domain.ConnectionStatus
// doesn't apply here since a listed tunnel may never have been connected.
type tunnelListEntry struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// hasFlag reports whether flag is present anywhere in args.
func hasFlag(args []string, flag string) bool {
	return slices.Contains(args, flag)
}

// printJSON marshals v as indented JSON to stdout. Always returns 0 unless
// marshalling itself fails.
func printJSON(v any) int {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "json:", err)
		return 1
	}
	fmt.Println(string(data))
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

// appRunning remains GUI-only for ctl start. Working intent also counts for
// status/disconnect/stop, so pending recovery can always be cancelled.
func helperWorking(p ipc.PingResponse) bool { return appRunning(p) || len(p.WantedTunnels) > 0 }
