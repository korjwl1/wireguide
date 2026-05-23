package diag

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// routeCmdTimeout bounds the route-table-listing commands. These are called
// from the diagnostics UI; a hung command would freeze the helper.
const routeCmdTimeout = 10 * time.Second

func runRouteCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routeCmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

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
	// Run both `inet` and `inet6` so IPv6 routes (Tailscale, full
	// IPv6 tunnels, ULA prefixes) show up in diagnostics. Without
	// `-f inet6` an IPv6-only tunnel was completely invisible.
	v4, err := runRouteCmd("netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	v6, err := runRouteCmd("netstat", "-rn", "-f", "inet6")
	if err != nil {
		// Non-fatal: IPv6 may be disabled on this system. Return
		// just the v4 routes rather than the whole call failing.
		return parseDarwinRouteOutput(string(v4)), nil
	}
	routes := parseDarwinRouteOutput(string(v4))
	routes = append(routes, parseDarwinRouteOutput(string(v6))...)
	return routes, nil
}

func parseDarwinRouteOutput(out string) []RouteEntry {
	var routes []RouteEntry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Skip header / banner lines (`Internet:`, `Internet6:`, etc.)
		if fields[0] == "Destination" || fields[0] == "Routing" ||
			strings.HasPrefix(fields[0], "Internet") {
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
	return routes
}

func getRoutesLinuxFull() ([]RouteEntry, error) {
	out, err := runRouteCmd("ip", "route", "show")
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
	out, err := runRouteCmd("route", "print", "-4")
	if err != nil {
		return nil, err
	}
	var routes []RouteEntry
	inTable := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Network Destination") {
			inTable = true
			continue
		}
		if inTable && line == "" {
			break
		}
		if !inTable {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			routes = append(routes, RouteEntry{
				Destination: fields[0],
				Gateway:     fields[1],
				Interface:   fields[3],
			})
		}
	}
	return routes, nil
}
