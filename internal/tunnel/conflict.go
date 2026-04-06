package tunnel

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ConflictInfo describes a routing conflict with an existing interface.
type ConflictInfo struct {
	InterfaceName  string   `json:"interface_name"`
	Owner          string   `json:"owner"`           // "WireGuide", "Tailscale", "WireGuard", "Unknown"
	OverlappingIPs []string `json:"overlapping_ips"` // CIDRs that overlap
}

// CheckConflicts scans existing interfaces for routing conflicts with the given AllowedIPs.
func CheckConflicts(newAllowedIPs []string) ([]ConflictInfo, error) {
	interfaces, err := scanWireGuardInterfaces()
	if err != nil {
		return nil, err
	}

	var conflicts []ConflictInfo
	for _, iface := range interfaces {
		overlaps := findOverlaps(newAllowedIPs, iface.Routes)
		if len(overlaps) > 0 {
			conflicts = append(conflicts, ConflictInfo{
				InterfaceName:  iface.Name,
				Owner:          iface.Owner,
				OverlappingIPs: overlaps,
			})
		}
	}
	return conflicts, nil
}

// ExistingInterface represents a detected WireGuard-like interface.
type ExistingInterface struct {
	Name   string
	Owner  string   // Identified owner
	Routes []string // Known routes via this interface
}

func scanWireGuardInterfaces() ([]ExistingInterface, error) {
	var result []ExistingInterface

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		name := iface.Name
		// Only check utun (macOS), wg (Linux), or WireGuard-like interfaces
		if !isWireGuardLike(name) {
			continue
		}

		owner := identifyOwner(name)
		routes := getInterfaceRoutes(name)

		if len(routes) > 0 {
			result = append(result, ExistingInterface{
				Name:   name,
				Owner:  owner,
				Routes: routes,
			})
		}
	}

	return result, nil
}

func isWireGuardLike(name string) bool {
	return strings.HasPrefix(name, "utun") ||
		strings.HasPrefix(name, "wg") ||
		strings.HasPrefix(name, "tun")
}

// identifyOwner determines who created this interface by checking UAPI sockets.
func identifyOwner(ifaceName string) string {
	// Check WireGuide socket
	if socketExists("/var/run/wireguide/" + ifaceName + ".sock") {
		return "WireGuide"
	}

	// Check WireGuard socket
	if socketExists("/var/run/wireguard/" + ifaceName + ".sock") {
		return "WireGuard"
	}

	// Check Tailscale — different socket path
	tailscalePaths := []string{
		"/var/run/tailscale/tailscaled.sock",
		"/var/run/tailscaled.sock",
	}
	for _, p := range tailscalePaths {
		if socketExists(p) {
			// Check if tailscaled process exists
			if processExists("tailscaled") {
				return "Tailscale"
			}
		}
	}

	// Check for known process names
	if processOwnsInterface(ifaceName, "tailscaled") {
		return "Tailscale"
	}
	if processOwnsInterface(ifaceName, "wireguard-go") {
		return "WireGuard"
	}

	return "Unknown"
}

func socketExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// Only accept actual sockets — regular files with similar names do NOT
	// indicate a running peer. Previously we OR'd with IsRegular() which
	// produced false positives on stale leftover files.
	return info.Mode()&os.ModeSocket != 0
}

func processExists(name string) bool {
	switch runtime.GOOS {
	case "darwin", "linux":
		out, _ := exec.Command("pgrep", "-x", name).CombinedOutput()
		return len(strings.TrimSpace(string(out))) > 0
	case "windows":
		out, _ := exec.Command("tasklist", "/FI", "IMAGENAME eq "+name+".exe").CombinedOutput()
		return strings.Contains(string(out), name)
	}
	return false
}

func processOwnsInterface(ifaceName, processName string) bool {
	// NOTE: This is a simplification — it checks whether the process is running
	// at all, not whether it actually owns this specific interface. A more
	// accurate implementation would inspect /proc/<pid>/fd on Linux or use
	// lsof on macOS to correlate the TUN fd with the interface. Acceptable
	// for now because false positives only produce a warning, not a hard block.
	return processExists(processName)
}

// getInterfaceRoutes returns routes via the given interface.
func getInterfaceRoutes(ifaceName string) []string {
	switch runtime.GOOS {
	case "darwin":
		return getRoutesDarwin(ifaceName)
	case "linux":
		return getRoutesLinux(ifaceName)
	default:
		// TODO: Implement Windows route enumeration via `route print` or
		// netsh to detect conflicts on Windows interfaces.
		return nil
	}
}

func getRoutesDarwin(ifaceName string) []string {
	cmd := exec.Command("netstat", "-rn", "-f", "inet")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	// Parse header dynamically. netstat column order is stable in practice,
	// but hardcoding index 3 has broken in the past when flags shifted.
	destIdx, netifIdx := -1, -1
	var routes []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if netifIdx < 0 {
			for i, f := range fields {
				switch f {
				case "Destination":
					destIdx = i
				case "Netif":
					netifIdx = i
				}
			}
			continue
		}
		if len(fields) <= netifIdx || destIdx < 0 {
			continue
		}
		if fields[netifIdx] != ifaceName {
			continue
		}
		route := fields[destIdx]
		if route == "default" {
			routes = append(routes, "0.0.0.0/0")
		} else {
			routes = append(routes, route)
		}
	}
	return routes
}

func getRoutesLinux(ifaceName string) []string {
	out, err := exec.Command("ip", "route", "show", "dev", ifaceName).CombinedOutput()
	if err != nil {
		return nil
	}
	var routes []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			route := fields[0]
			if route == "default" {
				routes = append(routes, "0.0.0.0/0")
			} else {
				routes = append(routes, route)
			}
		}
	}
	return routes
}

// findOverlaps checks if any of newIPs overlap with existingIPs.
func findOverlaps(newIPs, existingIPs []string) []string {
	var overlaps []string
	for _, newCIDR := range newIPs {
		_, newNet, err := net.ParseCIDR(normalizeCIDR(newCIDR))
		if err != nil {
			continue
		}
		for _, existCIDR := range existingIPs {
			_, existNet, err := net.ParseCIDR(normalizeCIDR(existCIDR))
			if err != nil {
				continue
			}
			if newNet.Contains(existNet.IP) || existNet.Contains(newNet.IP) {
				overlaps = append(overlaps, fmt.Sprintf("%s <> %s", newCIDR, existCIDR))
			}
		}
	}
	return overlaps
}

func normalizeCIDR(s string) string {
	// If it's just an IP without mask, add /32
	if !strings.Contains(s, "/") {
		if strings.Contains(s, ":") {
			return s + "/128"
		}
		return s + "/32"
	}
	return s
}
