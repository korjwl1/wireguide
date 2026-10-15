package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func cmdStatus(args []string) int {
	jsonOut := hasFlag(args, "--json")

	c, ping, err := dialHelperRaw()
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
	// No app attached: report "not running" like every other command — unless
	// a tunnel is still up. The helper deliberately keeps tunnels alive after
	// the app quits (wg-quick semantics), and hiding one would be wrong.
	if !helperWorking(ping) && len(active.Names) == 0 {
		fmt.Fprintln(os.Stderr, errAppNotRunning)
		return 1
	}
	if len(active.Names) == 0 && len(ping.WantedTunnels) > 0 {
		if jsonOut {
			var rows []domain.ConnectionStatus
			for _, name := range ping.WantedTunnels {
				rows = append(rows, domain.ConnectionStatus{TunnelName: name, State: domain.StateConnecting})
			}
			return printJSON(rows)
		}
		fmt.Println("waiting to reconnect: " + strings.Join(ping.WantedTunnels, ", "))
		return 0
	}
	if len(active.Names) == 0 {
		if jsonOut {
			return printJSON([]domain.ConnectionStatus{})
		}
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
	seen := make(map[string]bool, len(rows)+len(active.Names))
	pendingRows := make(map[string]bool)
	for _, name := range active.Names {
		seen[name] = true
	}
	for _, row := range rows {
		seen[row.TunnelName] = true
	}
	for _, name := range ping.WantedTunnels {
		if !seen[name] {
			rows = append(rows, domain.ConnectionStatus{TunnelName: name, State: domain.StateConnecting})
			seen[name] = true
			pendingRows[name] = true
		}
	}
	if jsonOut {
		return printJSON(rows)
	}
	for _, r := range rows {
		if pendingRows[r.TunnelName] {
			fmt.Printf("○ %s  waiting to reconnect\n", r.TunnelName)
			continue
		}
		if r.State == domain.StateConnecting {
			fmt.Printf("○ %s  connecting\n", r.TunnelName)
			continue
		}
		hs := r.LastHandshake
		if hs == "" {
			hs = "—"
		}
		fmt.Printf("● %s  %s  rx=%s tx=%s  handshake=%s\n",
			r.TunnelName, r.Duration, humanBytes(r.RxBytes), humanBytes(r.TxBytes), hs)
	}
	return 0
}

func cmdList(args []string) int {
	jsonOut := hasFlag(args, "--json")

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
	if jsonOut {
		entries := make([]tunnelListEntry, len(names))
		for i, n := range names {
			entries[i] = tunnelListEntry{Name: n, Active: activeSet[n]}
		}
		return printJSON(entries)
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
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		return 1
	}
	defer f.Close()
	name := ""
	if len(args) >= 2 {
		name = args[1]
	} else {
		base := filepath.Base(path)
		name = strings.TrimSuffix(base, filepath.Ext(base))
	}
	cfg, err := config.ParseReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import: %q is not a valid WireGuard config: %v\n", path, err)
		return 1
	}
	store, err := tunnelStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		return 1
	}
	if store.Exists(name) {
		fmt.Fprintf(os.Stderr, "import: tunnel %q already exists (rename or delete it before importing)\n", name)
		return 1
	}
	if _, err := store.ImportFromContent(name, config.Serialize(cfg)); err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		return 1
	}
	fmt.Printf("imported %s\n", name)
	return 0
}

func cmdRename(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl rename <old> <new>")
		return 2
	}
	old, newName := args[0], args[1]
	c, _, contactErr := dialHelperRaw()
	if contactErr == nil {
		defer c.Close()
		if err := c.Call(ipc.MethodRename, ipc.RenameRequest{OldName: old, NewName: newName}, nil); err != nil {
			fmt.Fprintln(os.Stderr, "rename:", err)
			return 1
		}
	} else {
		if !helperAbsent(contactErr) {
			fmt.Fprintln(os.Stderr, "rename: cannot verify helper state:", contactErr)
			return 1
		}
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
	c, ping, contactErr := dialHelperRaw()
	if contactErr == nil {
		if ipc.MinorOf(ping.Version) < 4 {
			c.Close()
			fmt.Fprintln(os.Stderr, "delete: reopen WireGuide to upgrade the helper before deleting a profile")
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := c.CallWithContext(ctx, ipc.MethodDelete, ipc.DeleteRequest{TunnelName: name, Disconnect: true}, nil)
		cancel()
		c.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "delete:", err)
			return 1
		}
	} else {
		// Offline editing remains available when no listener exists. A hung,
		// incompatible or unauthorized helper is not proof that a tunnel is down.
		if !helperAbsent(contactErr) {
			fmt.Fprintln(os.Stderr, "delete: cannot verify helper state:", contactErr)
			return 1
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
