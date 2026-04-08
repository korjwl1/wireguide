package diag

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// RouteEntry represents a single routing table entry.
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Flags       string `json:"flags"`
}

// GetRoutingTable returns the current OS routing table.
func GetRoutingTable() ([]RouteEntry, error) {
	switch runtime.GOOS {
	case "darwin":
		return getRoutesDarwinFull()
	case "linux":
		return getRoutesLinuxFull()
	case "windows":
		return getRoutesWindowsFull()
	default:
		return nil, nil
	}
}

func getRoutesDarwinFull() ([]RouteEntry, error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
	if err != nil {
		return nil, err
	}
	var routes []RouteEntry
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Skip header lines
		if fields[0] == "Destination" || fields[0] == "Routing" || fields[0] == "Internet:" {
			continue
		}
		entry := RouteEntry{
			Destination: fields[0],
			Gateway:     fields[1],
		}
		if len(fields) > 2 {
			entry.Flags = fields[2]
		}
		if len(fields) > 3 {
			entry.Interface = fields[3]
		}
		routes = append(routes, entry)
	}
	return routes, nil
}

func getRoutesLinuxFull() ([]RouteEntry, error) {
	out, err := exec.Command("ip", "route", "show").CombinedOutput()
	if err != nil {
		return nil, err
	}
	var routes []RouteEntry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entry := RouteEntry{}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			entry.Destination = fields[0]
		}
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				entry.Gateway = fields[i+1]
			}
			if f == "dev" && i+1 < len(fields) {
				entry.Interface = fields[i+1]
			}
		}
		routes = append(routes, entry)
	}
	return routes, nil
}

func getRoutesWindowsFull() ([]RouteEntry, error) {
	// Use PowerShell Get-NetRoute for locale-independent output instead of
	// `route print` which has localized headers.
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, InterfaceAlias | ConvertTo-Csv -NoTypeInformation`).CombinedOutput()
	if err != nil {
		// Fallback to route print parsing for older Windows versions.
		return getRoutesWindowsRoutePrint()
	}

	var routes []RouteEntry
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 { // skip CSV header
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// CSV format: "DestinationPrefix","NextHop","InterfaceAlias"
		fields := strings.Split(line, ",")
		if len(fields) >= 3 {
			dest := strings.Trim(fields[0], `"`)
			gw := strings.Trim(fields[1], `"`)
			iface := strings.Trim(fields[2], `"`)
			routes = append(routes, RouteEntry{
				Destination: dest,
				Gateway:     gw,
				Interface:   iface,
			})
		}
	}
	return routes, nil
}

// getRoutesWindowsRoutePrint is the legacy fallback using `route print`.
func getRoutesWindowsRoutePrint() ([]RouteEntry, error) {
	out, err := exec.Command("route", "print", "-4").CombinedOutput()
	if err != nil {
		return nil, err
	}
	var routes []RouteEntry
	// Look for lines that start with an IP address (locale-independent).
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 4 {
			// Check if first field looks like an IP/CIDR
			if net.ParseIP(fields[0]) != nil {
				routes = append(routes, RouteEntry{
					Destination: fields[0],
					Gateway:     fields[1],
					Interface:   fields[3],
				})
			}
		}
	}
	return routes, nil
}
