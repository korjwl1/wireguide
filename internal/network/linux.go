//go:build linux

package network

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// cmdTimeout bounds every external command (ip/nft/resolvectl/resolvconf).
// Without this, a hung kernel netlink reply or systemd-resolved D-Bus stall
// blocks the helper indefinitely.
const cmdTimeout = 30 * time.Second

// dnsStateFile is persisted alongside the active tunnel state so that crash
// recovery can restore /etc/resolv.conf even if the process restarts.
const dnsStateFile = "original-dns.json"

// LinuxManager implements NetworkManager for Linux using netlink/ip commands.
type LinuxManager struct {
	origDNS []string
	// origDNSCaptured latches once the real pre-VPN /etc/resolv.conf has
	// been snapshotted, so a second SetDNS (reconnect, network-change
	// re-apply) doesn't overwrite the saved original with WireGuide's own
	// nameservers and leave RestoreDNS unable to recover the real DNS.
	origDNSCaptured bool
	// dataDir is the persistent state directory (e.g. /var/lib/wireguide).
	// If empty, DNS state persistence is skipped (graceful degradation).
	dataDir string
	// fwmark and table track the values used for full-tunnel routing so
	// RemoveRoutes can clean them up correctly.
	fwmark int
	table  int
	// tableSet distinguishes "table was explicitly set to 0 (main table)"
	// from "table was never set". Without this, removeFullTunnelRoutes
	// cannot tell whether 0 means main table or uninitialised.
	tableSet bool
	// endpointThrowRoutes contains only throw routes successfully installed
	// by this manager. They must be removed explicitly; deleting the default
	// route from the policy table does not flush sibling throw routes.
	endpointThrowRoutes []string
}

func NewPlatformManager() NetworkManager {
	return &LinuxManager{}
}

func (m *LinuxManager) SetPersistentStateDir(dataDir string) {
	m.dataDir = dataDir
}

func (m *LinuxManager) AssignAddress(ifaceName string, addresses []string) error {
	for _, addr := range addresses {
		if err := runCmd("ip", "addr", "add", addr, "dev", ifaceName); err != nil {
			return fmt.Errorf("assigning address %s: %w", addr, err)
		}
	}
	return nil
}

func (m *LinuxManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		// Auto-detect: upstream MTU minus 80 (wg-quick algorithm)
		defaultIf := getDefaultInterface()
		if defaultIf != "" {
			if upMTU := getInterfaceMTU(defaultIf); upMTU > 0 {
				mtu = upMTU - 80
			}
		}
		if mtu <= 0 {
			mtu = 1420
		}
		if mtu < 1280 {
			mtu = 1280
		}
	}
	return runCmd("ip", "link", "set", "dev", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
}

func getDefaultInterface() string {
	out, err := runOut("ip", "route", "show", "default")
	if err != nil {
		return ""
	}
	// Parse "default via <gw> dev <iface> ..."
	fields := strings.Fields(strings.TrimSpace(string(out)))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func getInterfaceMTU(ifaceName string) int {
	out, err := runOut("ip", "link", "show", "dev", ifaceName)
	if err != nil {
		return 0
	}
	// Parse "... mtu <value> ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "mtu" && i+1 < len(fields) {
			if v, err := strconv.Atoi(fields[i+1]); err == nil {
				return v
			}
		}
	}
	return 0
}

func (m *LinuxManager) BringUp(ifaceName string) error {
	return runCmd("ip", "link", "set", "dev", ifaceName, "up")
}

// WireGuide-owned `ip rule` priorities. wg-quick uses dynamic priorities
// that depend on the table number; we pick fixed values out of the band
// that NetworkManager (32766+) and Docker (32767-32768) don't touch, but
// below systemd's reserved range (10000-19000). Two priorities are used:
// one for the fwmark→table rule, one for the suppress_prefixlength rule
// on the main table.
const (
	wgRulePriorityFwmark   = "29040"
	wgRulePrioritySuppress = "29050"
)

// splitRouteDeleteArgs mirrors AddRoutes' address-family selection. `ip route`
// defaults to IPv4, so omitting -6 here leaves IPv6 split routes installed
// after disconnect or a failed connect rollback.
func splitRouteDeleteArgs(ifaceName, cidr, tableStr string) []string {
	args := []string{"route", "delete", cidr, "dev", ifaceName}
	if strings.Contains(cidr, ":") {
		args = append([]string{"-6"}, args...)
	}
	if tableStr != "" {
		args = append(args, "table", tableStr)
	}
	return args
}

// RestoreRoutingState re-populates the in-memory table/fwmark fields from
// persisted values (e.g. crash recovery state). This allows removeFullTunnelRoutes
// to use the correct values even on a fresh process.
func (m *LinuxManager) RestoreRoutingState(table, fwmark string) {
	if strings.EqualFold(strings.TrimSpace(table), "off") {
		m.table = -1
		m.tableSet = true
	} else if table != "" {
		if parsed, err := strconv.Atoi(table); err == nil {
			m.table = parsed
			m.tableSet = true
		}
	}
	if fwmark != "" {
		if parsed, err := parseIntOrHex(fwmark); err == nil {
			m.fwmark = parsed
		}
	}
}

// splitDNSRunCmd is a var so tests can intercept resolvectl invocations.
var splitDNSRunCmd = runCmd

// searchDomainRegex matches an RFC 1035 hostname/domain. Anchored, so any
// embedded whitespace or newline (the injection vector) fails the match.
var searchDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)*$`)

// H10: Cleanup now removes policy rules, routing table entries, and nftables
// rules in addition to the interface itself.
func (m *LinuxManager) Cleanup(ifaceName string) error {
	dnsErr := m.RestoreDNS(ifaceName)

	// Routes are removed by RemoveRoutes before Cleanup, with the tunnel's
	// actual full/split classification. Do not remove full-tunnel policy rules
	// here: a split tunnel may coexist with a full tunnel, and deleting the
	// process-wide rules while cleaning the split tunnel breaks the survivor.
	// Firewall tables are likewise owned by firewall.Manager and may protect
	// other active tunnels; crash recovery calls that manager separately.
	//
	// Engine.Close normally deletes the TUN first. Keep this final delete as a
	// best-effort fallback for platform/engine implementations where it remains.
	if err := runCmd("ip", "link", "delete", "dev", ifaceName); err != nil {
		slog.Debug("cleanup: interface already absent or delete failed", "iface", ifaceName, "error", err)
	}
	return dnsErr
}

func runCmd(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s %s: timed out after %s (%s)", name, strings.Join(args, " "), cmdTimeout, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runOut runs a command with a bounded context and returns combined output.
// Use for parse-output commands so they can't hang the helper.
func runOut(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
