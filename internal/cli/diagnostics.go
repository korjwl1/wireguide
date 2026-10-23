package cli

import (
	"fmt"
	"os"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/ipc"
)

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

// activeTunnelNames returns every connected tunnel, not only the first.
func activeTunnelNames() []string {
	c, err := dialHelper()
	if err != nil {
		return nil
	}
	defer c.Close()
	var resp ipc.ActiveTunnelsResponse
	if c.Call(ipc.MethodActiveTunnels, nil, &resp) != nil {
		return nil
	}
	return resp.Names
}

func cmdDNSLeak(_ []string) int {
	// Compare against the active tunnel's DNS servers when there is one.
	var perTunnel [][]string
	if store, err := tunnelStore(); err == nil {
		for _, name := range activeTunnelNames() {
			if cfg, err := store.Load(name); err == nil {
				perTunnel = append(perTunnel, cfg.Interface.DNS)
			}
		}
	}
	res := diag.RunDNSLeakTestForTunnels(perTunnel)
	if res == nil {
		fmt.Fprintln(os.Stderr, "dnsleak: no result")
		return 1
	}

	if res.Leaked {
		fmt.Println("LEAK: DNS queries are resolving outside the tunnel")
	} else if res.Error != "" {
		// No success verdict for an incomplete check.
	} else if res.SplitMode {
		fmt.Println("OK: split DNS resolver configuration checked (not a packet leakage test)")
	} else {
		fmt.Println("OK: DNS is pinned to the tunnel")
	}
	for _, srv := range res.DNSServers {
		fmt.Printf("  resolver %s\n", srv.IP)
	}
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "dnsleak:", res.Error)
		return 1
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
