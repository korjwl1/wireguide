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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
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

Tunnels:
  wireguide ctl status                    show connection status
  wireguide ctl list                      list tunnels (● = connected)
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

The WireGuide app (or its helper) must be running for connect/disconnect/status;
list, import, rename, delete and automation edits work against local files.
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
	// Create the data dirs if the CLI is the first thing to run on a fresh
	// install (before the GUI has ever launched) — otherwise `import`'s
	// atomic write into a nonexistent tunnels dir fails with ENOENT
	// (issue #10).
	if err := paths.EnsureDirs(); err != nil {
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
	// Pre-connect conflict check — mirrors the GUI's warning-on-connect.
	// Non-interactive: we warn and proceed (the GUI shows a dialog).
	var allowedIPs []string
	for _, p := range cfg.Peers {
		allowedIPs = append(allowedIPs, p.AllowedIPs...)
	}
	if conflicts, cerr := diag.CheckConflicts(allowedIPs); cerr == nil {
		for _, cf := range conflicts {
			fmt.Fprintf(os.Stderr, "warning: routes overlap with %s (%s): %s\n",
				cf.Owner, cf.InterfaceName, strings.Join(cf.OverlappingIPs, ", "))
		}
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

func cmdAutomation(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "rules", "list":
			return automationRules(args[1:])
		case "add":
			return automationAdd(args[1:])
		case "rm", "remove", "delete":
			return automationRm(args[1:])
		case "show", "status":
			// fall through to the live preview below
		default:
			fmt.Fprintf(os.Stderr, "unknown automation subcommand %q (try: rules, add, rm)\n", args[0])
			return 2
		}
	}
	return automationPreview()
}

func automationPreview() int {
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
	gwMAC := resp.GatewayMAC
	if gwMAC == "" {
		gwMAC = "(unknown)"
	}
	fmt.Printf("network context: ssid=%s  gateway-mac=%s  physical-ips=%v\n", ssid, gwMAC, resp.PhysicalIPs)
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

// --- automation rule configuration (edits config.json directly) ---

func settingsStore() (*storage.SettingsStore, error) {
	paths, err := storage.GetPaths()
	if err != nil {
		return nil, err
	}
	if err := paths.EnsureDirs(); err != nil {
		return nil, err
	}
	return storage.NewSettingsStore(paths.ConfigDir), nil
}

// loadSettingsWithAutomation loads settings and ensures Automation is
// populated (migrating legacy rules once) so edits build on the current
// effective rule set.
func loadSettingsWithAutomation() (*storage.SettingsStore, *storage.Settings, error) {
	ss, err := settingsStore()
	if err != nil {
		return nil, nil, err
	}
	s, err := ss.Load()
	if err != nil {
		return nil, nil, err
	}
	s.EnsureAutomation()
	if s.Automation.PerTunnel == nil {
		s.Automation.PerTunnel = map[string][]wifi.Rule{}
	}
	return ss, s, nil
}

func formatCondition(c wifi.Condition) string {
	switch c.Type {
	case wifi.CondSSID:
		return "ssid=" + c.SSID
	case wifi.CondSubnet:
		return "subnet=" + c.Subnet
	case wifi.CondNetwork:
		return "network(mac)=" + c.GatewayMAC
	case wifi.CondNoneMatch:
		return "otherwise"
	}
	return c.Type
}

func automationRules(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl automation rules <tunnel>")
		return 2
	}
	name := args[0]
	_, s, err := loadSettingsWithAutomation()
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	rules := s.Automation.PerTunnel[name]
	if len(rules) == 0 {
		fmt.Printf("%s has no automation rules\n", name)
		return 0
	}
	fmt.Printf("%s (top rule wins on conflict):\n", name)
	for i, r := range rules {
		fmt.Printf("  %d. %-10s when %s\n", i+1, r.Do, formatCondition(r.When))
	}
	return 0
}

// parseCondition turns "ssid:home" / "subnet:10.0.0.0/24" / "mac:.." /
// "else" into a wifi.Condition. Returns an error for malformed values.
func parseCondition(spec string) (wifi.Condition, error) {
	if spec == "else" || spec == "otherwise" || spec == "none" {
		return wifi.Condition{Type: wifi.CondNoneMatch}, nil
	}
	kind, val, ok := strings.Cut(spec, ":")
	if !ok || val == "" {
		return wifi.Condition{}, fmt.Errorf("condition %q must be ssid:<name>, subnet:<CIDR>, mac:<MAC> or else", spec)
	}
	switch kind {
	case "ssid":
		return wifi.Condition{Type: wifi.CondSSID, SSID: val}, nil
	case "subnet":
		if _, _, err := net.ParseCIDR(strings.TrimSpace(val)); err != nil {
			return wifi.Condition{}, fmt.Errorf("subnet %q is not a valid CIDR (e.g. 192.168.0.0/24)", val)
		}
		return wifi.Condition{Type: wifi.CondSubnet, Subnet: val}, nil
	case "mac":
		hex := strings.Map(func(r rune) rune {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				return r
			}
			return -1
		}, val)
		if len(hex) != 12 {
			return wifi.Condition{}, fmt.Errorf("mac %q is not a valid MAC address", val)
		}
		return wifi.Condition{Type: wifi.CondNetwork, GatewayMAC: strings.ToLower(val)}, nil
	default:
		return wifi.Condition{}, fmt.Errorf("unknown condition kind %q (use ssid/subnet/mac/else)", kind)
	}
}

func automationAdd(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl automation add <tunnel> <connect|disconnect> <cond>")
		return 2
	}
	name, action, spec := args[0], args[1], args[2]
	if action != "connect" && action != "disconnect" {
		fmt.Fprintf(os.Stderr, "action must be 'connect' or 'disconnect', got %q\n", action)
		return 2
	}
	cond, err := parseCondition(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 2
	}
	store, err := tunnelStore()
	if err == nil && !store.Exists(name) {
		fmt.Fprintf(os.Stderr, "warning: no tunnel named %q — the rule is saved but won't do anything until it exists\n", name)
	}
	ss, err := settingsStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	ruleNum := 0
	err = ss.Update(func(s *storage.Settings) error {
		s.EnsureAutomation()
		if s.Automation.PerTunnel == nil {
			s.Automation.PerTunnel = map[string][]wifi.Rule{}
		}
		s.Automation.PerTunnel[name] = append(s.Automation.PerTunnel[name], wifi.Rule{When: cond, Do: wifi.Action(action)})
		ruleNum = len(s.Automation.PerTunnel[name])
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation: save failed:", err)
		return 1
	}
	fmt.Printf("added rule %d for %s: %s when %s\n", ruleNum, name, action, formatCondition(cond))
	return 0
}

func automationRm(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl automation rm <tunnel> <rule-number>")
		return 2
	}
	name := args[0]
	idx, err := strconv.Atoi(args[1])
	if err != nil || idx < 1 {
		fmt.Fprintf(os.Stderr, "rule number must be a positive integer (see 'automation rules %s')\n", name)
		return 2
	}
	ss, err := settingsStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	var removed wifi.Rule
	tooFew := -1 // set to the actual rule count if idx is out of range
	err = ss.Update(func(s *storage.Settings) error {
		s.EnsureAutomation()
		rules := s.Automation.PerTunnel[name]
		if idx > len(rules) {
			tooFew = len(rules)
			return fmt.Errorf("rule number out of range")
		}
		removed = rules[idx-1]
		s.Automation.PerTunnel[name] = append(rules[:idx-1:idx-1], rules[idx:]...)
		if len(s.Automation.PerTunnel[name]) == 0 {
			delete(s.Automation.PerTunnel, name)
		}
		return nil
	})
	if tooFew >= 0 {
		fmt.Fprintf(os.Stderr, "%s has only %d rule(s)\n", name, tooFew)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation: save failed:", err)
		return 1
	}
	fmt.Printf("removed rule %d for %s: %s when %s\n", idx, name, removed.Do, formatCondition(removed.When))
	return 0
}

// --- tunnel management ---

func cmdRename(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl rename <old> <new>")
		return 2
	}
	old, newName := args[0], args[1]
	// Prefer the helper's rename (it serialises against connect/disconnect);
	// fall back to a local store rename if the helper isn't reachable.
	renamed := false
	if c, err := dialHelper(); err == nil {
		defer c.Close()
		if err := c.Call(ipc.MethodRename, ipc.RenameRequest{OldName: old, NewName: newName}, nil); err != nil {
			fmt.Fprintln(os.Stderr, "rename:", err)
			return 1
		}
		renamed = true
	}
	if !renamed {
		store, err := tunnelStore()
		if err != nil {
			fmt.Fprintln(os.Stderr, "rename:", err)
			return 1
		}
		if err := store.Rename(old, newName); err != nil {
			fmt.Fprintln(os.Stderr, "rename:", err)
			return 1
		}
	}
	// Carry the tunnel's automation rules over to the new name so they
	// aren't orphaned (issue #12). Best-effort: the rename already
	// succeeded; a rules-migration failure shouldn't fail the command.
	if ss, err := settingsStore(); err == nil {
		if err := ss.Update(func(s *storage.Settings) error {
			s.RenameTunnelRules(old, newName)
			return nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, "warning: renamed the tunnel but could not move its automation rules:", err)
		}
	}
	fmt.Printf("renamed %s → %s\n", old, newName)
	return 0
}

func cmdDelete(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl delete <name>")
		return 2
	}
	name := args[0]
	// Disconnect first if it's active, so we don't delete a live tunnel's
	// config out from under the helper. If it IS active and the disconnect
	// fails, abort rather than orphaning a running tunnel with no config
	// (issue #10).
	if c, err := dialHelper(); err == nil {
		var active ipc.ActiveTunnelsResponse
		if err := c.Call(ipc.MethodActiveTunnels, nil, &active); err != nil {
			c.Close()
			fmt.Fprintf(os.Stderr, "delete: can't verify whether %q is active: %v\n", name, err)
			return 1
		}
		isActive := false
		for _, n := range active.Names {
			if n == name {
				isActive = true
				break
			}
		}
		if isActive {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := c.CallWithContext(ctx, ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: name}, nil)
			cancel()
			if err != nil {
				c.Close()
				fmt.Fprintf(os.Stderr, "delete: %q is connected and could not be disconnected: %v\n", name, err)
				fmt.Fprintln(os.Stderr, "refusing to delete a live tunnel's config; disconnect it and retry.")
				return 1
			}
		}
		c.Close()
	}
	store, err := tunnelStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "delete:", err)
		return 1
	}
	if err := store.Delete(name); err != nil {
		fmt.Fprintln(os.Stderr, "delete:", err)
		return 1
	}
	// Drop the tunnel's automation rules so they don't linger and re-attach
	// to a future same-named tunnel (issue #12). Best-effort.
	if ss, err := settingsStore(); err == nil {
		if err := ss.Update(func(s *storage.Settings) error {
			s.DeleteTunnelRules(name)
			return nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, "warning: deleted the tunnel but could not remove its automation rules:", err)
		}
	}
	fmt.Printf("deleted %s\n", name)
	return 0
}

// --- settings toggles (persist to config.json + apply live via IPC) ---

func parseOnOff(v string) (bool, bool) {
	switch strings.ToLower(v) {
	case "on", "true", "1", "yes", "enable", "enabled":
		return true, true
	case "off", "false", "0", "no", "disable", "disabled":
		return false, true
	}
	return false, false
}

func cmdSet(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl set <killswitch|dns-protection|healthcheck|pin-interface|loglevel> <value>")
		return 2
	}
	setting, value := strings.ToLower(args[0]), args[1]

	ss, err := settingsStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "set:", err)
		return 1
	}

	// applyIPC persists-then-applies: the setting is already saved to
	// config.json, so a helper that isn't running just means "applies on
	// next launch" (exit 0 — nothing is live to be wrong). But if the
	// helper IS running and the live apply fails, we return nonzero: the
	// value is on disk yet NOT actually in effect, and a script that just
	// ran `set killswitch on` must not believe traffic is being blocked
	// when it isn't (issue #10).
	liveRC := 0
	applyIPC := func(method string, params interface{}) int {
		c, derr := dialHelper()
		if derr != nil {
			fmt.Println("(helper not running — saved; will take effect when the app starts)")
			return 0
		}
		defer c.Close()
		if err := c.Call(method, params, nil); err != nil {
			fmt.Fprintln(os.Stderr, "error: saved to config but live apply failed:", err)
			return 1
		}
		return 0
	}

	switch setting {
	case "killswitch", "kill-switch", "kill_switch":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.KillSwitch = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: v})
	case "dns-protection", "dnsprotection", "dns_protection":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.DNSProtection = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		// When enabling, the helper needs the active tunnel's DNS servers.
		var servers []string
		if v {
			if name := activeTunnelName(); name != "" {
				if store, e := tunnelStore(); e == nil {
					if cfg, e := store.Load(name); e == nil {
						servers = cfg.Interface.DNS
					}
				}
			}
		}
		liveRC = applyIPC(ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{Enabled: v, DNSServers: servers})
	case "healthcheck", "health-check", "health_check":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.HealthCheck = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetHealthCheck, ipc.SetHealthCheckRequest{Enabled: v})
	case "pin-interface", "pininterface", "pin_interface":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.PinInterface = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetPinInterface, ipc.SetPinInterfaceRequest{Enabled: v})
	case "loglevel", "log-level", "log_level":
		lvl := strings.ToLower(value)
		switch lvl {
		case "debug", "info", "warn", "error":
		default:
			fmt.Fprintln(os.Stderr, "loglevel must be one of: debug, info, warn, error")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.LogLevel = lvl; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: lvl})
	default:
		fmt.Fprintf(os.Stderr, "unknown setting %q (killswitch, dns-protection, healthcheck, pin-interface, loglevel)\n", setting)
		return 2
	}
	if liveRC != 0 {
		// Persisted, but the running helper rejected the live apply — the
		// value is NOT in effect right now. Exit nonzero so scripts notice.
		return liveRC
	}
	fmt.Printf("%s = %s\n", setting, value)
	return 0
}

// activeTunnelName returns the currently-active tunnel via IPC, or "".
func activeTunnelName() string {
	c, err := dialHelper()
	if err != nil {
		return ""
	}
	defer c.Close()
	var resp ipc.StringResponse
	if c.Call(ipc.MethodActiveName, nil, &resp) != nil {
		return ""
	}
	return resp.Value
}

// --- diagnostics ---

func cmdDNSLeak(_ []string) int {
	// Compare against the active tunnel's DNS servers when there is one.
	var expected []string
	if name := activeTunnelName(); name != "" {
		if store, err := tunnelStore(); err == nil {
			if cfg, err := store.Load(name); err == nil {
				expected = cfg.Interface.DNS
			}
		}
	}
	res := diag.RunDNSLeakTest(expected)
	if res == nil {
		fmt.Fprintln(os.Stderr, "dnsleak: no result")
		return 1
	}
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "dnsleak:", res.Error)
		return 1
	}
	if res.Leaked {
		fmt.Println("LEAK: DNS queries are resolving outside the tunnel")
	} else {
		fmt.Println("OK: DNS is pinned to the tunnel")
	}
	for _, srv := range res.DNSServers {
		fmt.Printf("  resolver %s\n", srv.IP)
	}
	if res.Leaked {
		return 1
	}
	return 0
}

func cmdRoutes(_ []string) int {
	rows, err := diag.GetRoutingTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "routes:", err)
		return 1
	}
	if len(rows) == 0 {
		fmt.Println("(no routes)")
		return 0
	}
	fmt.Printf("%-24s %-18s %-10s %s\n", "DESTINATION", "GATEWAY", "IFACE", "FLAGS")
	for _, r := range rows {
		fmt.Printf("%-24s %-18s %-10s %s\n", r.Destination, r.Gateway, r.Interface, r.Flags)
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
