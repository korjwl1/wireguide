package diag

import (
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
	out, err := exec.Command("route", "print", "-4").CombinedOutput()
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
