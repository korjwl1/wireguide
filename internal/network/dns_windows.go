//go:build windows

package network

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/korjwl1/wireguide/internal/domain"
)

// ValidateDNSConfig runs before TUN creation or route changes. Portable
// configs can still be imported and edited; unsupported activation fails early.
func (m *WindowsManager) ValidateDNSConfig(entries []string) error {
	if len(domain.ParseDNSEntries(entries).Match) > 0 {
		return ErrSplitDNSUnsupported
	}
	return nil
}

func (m *WindowsManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// Windows has no per-domain resolver routing here (that needs NRPT).
	// Bail out before any netsh call so split mode cannot become a global
	// override; global mode only ever passes IP servers to netsh.
	parsed := domain.ParseDNSEntries(servers)
	if len(parsed.Match) > 0 {
		return ErrSplitDNSUnsupported
	}
	if len(parsed.Search) > 0 {
		slog.Warn("DNS search domains are not supported on Windows", "domains", parsed.Search)
	}
	servers = parsed.Servers
	if len(servers) == 0 {
		return nil
	}

	// Set primary DNS
	if err := runWin("netsh", "interface", "ip", "set", "dns", ifaceName, "static", servers[0]); err != nil {
		return err
	}
	// Add additional DNS servers
	for i := 1; i < len(servers); i++ {
		if err := runWin("netsh", "interface", "ip", "add", "dns", ifaceName, servers[i], fmt.Sprintf("index=%d", i+1)); err != nil {
			slog.Warn("SetDNS: adding secondary DNS failed", "server", servers[i], "error", err)
		}
	}

	// Set the VPN interface metric to 1 so Windows prefers its DNS over
	// other interfaces, preventing DNS leaks through the physical adapter.
	tryRunWin("set IPv4 iface metric", "netsh", "interface", "ip", "set", "interface", ifaceName, "metric=1")
	tryRunWin("set IPv6 iface metric", "netsh", "interface", "ipv6", "set", "interface", ifaceName, "metric=1")

	return nil
}

// ResetDNSToSystemDefault resets DNS to DHCP for any WireGuard-style
// interfaces that still exist. Used by crash recovery when we have no
// per-adapter state from the previous process.
func (m *WindowsManager) ResetDNSToSystemDefault() error {
	// Enumerate interfaces and reset any that look like ours.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}
	var failures []error
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "wg") || strings.HasPrefix(iface.Name, "WireGuard") || strings.HasPrefix(iface.Name, "WireGuide") {
			// Best-effort: if the interface still exists, set DNS back to DHCP.
			if resetErr := runWin("netsh", "interface", "ip", "set", "dns", iface.Name, "dhcp"); resetErr != nil {
				failures = append(failures, fmt.Errorf("resetting DNS for %s: %w", iface.Name, resetErr))
			}
		}
	}
	return errors.Join(failures...)
}

// RestoreDNS resets only the VPN adapter. Physical DNS is never modified.
// An adapter already removed from the IP stack has nothing left to restore.
func (m *WindowsManager) RestoreDNS(ifaceName string) error {
	// Skip the netsh call when the adapter is no longer attached to the
	// IP stack — by the time Cleanup() reaches RestoreDNS, disconnectPhases
	// has already run PreCloseAdapterCleanup (which did this same dhcp
	// reset while the adapter was alive) AND engine.Close (which destroyed
	// the wintun adapter). The kernel's LUID cache lingers for a second
	// or two after the adapter detaches, so convertInterfaceAliasToLuid
	// still returns success here — but netsh's own resolution fails with
	// ERROR_INVALID_NAME because the adapter is no longer in the IP
	// stack's adapter table. We check via net.InterfaceByName which
	// goes through GetAdaptersAddresses (the same table netsh uses);
	// if the adapter isn't there, the netsh call would just produce a
	// confusing locale-encoded error.
	if _, err := net.InterfaceByName(ifaceName); err != nil {
		return nil
	}
	return runWin("netsh", "interface", "ip", "set", "dns", ifaceName, "dhcp")
}
