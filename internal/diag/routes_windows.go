//go:build windows

package diag

import "github.com/korjwl1/wireguide/internal/network"

// getRoutesWindowsFull enumerates the IPv4 routing table via iphlpapi
// (GetIpForwardTable2), the same kernel API PowerShell's Get-NetRoute
// uses. We previously parsed `route print -4` output here but the GUI
// process (where this runs) silently produced an empty list on at
// least one user's machine, and the parser was also dependent on the
// console binary's locale-specific column layout. iphlpapi is
// locale-independent, allocates no console child (no conhost flash),
// and is the same code path the reconnect detector already trusts for
// default-route lookup.
func getRoutesWindowsFull() ([]RouteEntry, error) {
	rows := network.EnumerateIPv4Routes()
	out := make([]RouteEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, RouteEntry{
			Destination: r.Destination,
			Gateway:     r.Gateway,
			Interface:   r.Interface,
		})
	}
	return out, nil
}
