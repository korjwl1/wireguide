package diag

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
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

	// ICMP ping with a hard 15-second context timeout to prevent hangs
	// when the ping binary itself doesn't respect -W on all platforms.
	result := &PingResult{Host: host, IP: ip}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "3", "-w", "3000", ip)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "3", "-W", "3", ip)
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
		// Fallback: parse individual round-trip times from ping lines
		// (e.g. "time=12.3 ms") and average them, which is more accurate
		// than dividing the total wall-clock elapsed time.
		if avg := parseIndividualPingTimes(string(out)); avg > 0 {
			result.LatencyMs = avg
		} else {
			result.LatencyMs = float64(elapsed.Milliseconds()) / 3
		}
	}

	return result
}

// Pre-compiled regexes for ping output parsing.
var (
	reUnixPingAvg    = regexp.MustCompile(`= [\d.]+/([\d.]+)/`)
	reWindowsPingAvg = regexp.MustCompile(`Average = (\d+)ms`)
	// Matches individual round-trip times: "time=12.3 ms" or "time<1ms"
	reIndividualRTT = regexp.MustCompile(`time[=<]([\d.]+)\s*ms`)
)

func parsePingLatency(output string) float64 {
	// macOS/Linux: "round-trip min/avg/max/stddev = 10.123/15.456/20.789/5.123 ms"
	if matches := reUnixPingAvg.FindStringSubmatch(output); len(matches) >= 2 {
		if f, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return f
		}
	}

	// Windows: "Average = 15ms"
	if matches := reWindowsPingAvg.FindStringSubmatch(output); len(matches) >= 2 {
		if f, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return f
		}
	}

	return 0
}

// parseIndividualPingTimes extracts per-reply round-trip times (e.g.
// "time=12.3 ms") from ping output and returns their average, or 0 if
// none were found.
func parseIndividualPingTimes(output string) float64 {
	matches := reIndividualRTT.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return 0
	}
	var total float64
	count := 0
	for _, m := range matches {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			total += f
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}

