package diag

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PingResult holds the result of an endpoint reachability test.
type PingResult struct {
	Host      string  `json:"host"`
	IP        string  `json:"ip"`
	Reachable bool    `json:"reachable"`
	LatencyMs float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

// PingEndpoint tests if a WireGuard endpoint is reachable.
func PingEndpoint(endpoint string) *PingResult {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}

	// Resolve hostname
	ips, err := net.LookupHost(host)
	if err != nil {
		return &PingResult{Host: host, Error: fmt.Sprintf("DNS resolution failed: %v", err)}
	}
	ip := ips[0]

	// ICMP ping
	result := &PingResult{Host: host, IP: ip}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "3", "-w", "3000", ip)
	default:
		cmd = exec.Command("ping", "-c", "3", "-W", "3", ip)
	}

	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		result.Error = "Host unreachable"
		return result
	}

	result.Reachable = true

	// Parse average latency from ping output
	latency := parsePingLatency(string(out))
	if latency > 0 {
		result.LatencyMs = latency
	} else {
		result.LatencyMs = float64(elapsed.Milliseconds()) / 3
	}

	return result
}

func parsePingLatency(output string) float64 {
	// macOS/Linux: "round-trip min/avg/max/stddev = 10.123/15.456/20.789/5.123 ms"
	re := regexp.MustCompile(`= [\d.]+/([\d.]+)/`)
	matches := re.FindStringSubmatch(output)
	if len(matches) >= 2 {
		f, err := strconv.ParseFloat(matches[1], 64)
		if err == nil {
			return f
		}
	}

	// Windows: "Average = 15ms"
	re = regexp.MustCompile(`Average = (\d+)ms`)
	matches = re.FindStringSubmatch(output)
	if len(matches) >= 2 {
		f, err := strconv.ParseFloat(matches[1], 64)
		if err == nil {
			return f
		}
	}

	return 0
}

// Unused but prevents import error
var _ = strings.Contains
