package diag

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// PingResult holds the result of an endpoint reachability test.
type PingResult struct {
	Host      string  `json:"host"`
	IP        string  `json:"ip"`
	Reachable bool    `json:"reachable"`
	LatencyMs float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

// PingEndpoint is the context-less convenience wrapper. Bounded by an
// internal 15-second timeout so callers that don't have a context
// don't leak ping subprocesses forever.
func PingEndpoint(endpoint string) *PingResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return PingEndpointContext(ctx, endpoint)
}

// PingEndpointContext tests if a WireGuard endpoint is reachable, honouring
// the caller's context. When the user closes the diagnostics panel the
// ping subprocess is killed instead of running to completion in the
// background (previously up to 15s of orphaned subprocess + CPU).
func PingEndpointContext(ctx context.Context, endpoint string) *PingResult {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}

	// Resolve hostname honouring ctx — net.LookupHost uses
	// context.Background() internally, so against a black-holed resolver
	// it would ignore both the caller's cancellation and PingEndpoint's
	// 15s deadline, leaving the goroutine blocked past panel close.
	// LookupHost can return (nil, nil) on some resolver edge cases, so
	// the empty-slice check is mandatory before indexing.
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return &PingResult{Host: host, Error: fmt.Sprintf("DNS resolution failed: %v", err)}
	}
	if len(ips) == 0 {
		return &PingResult{Host: host, Error: "DNS returned no addresses"}
	}
	ip := ips[0]

	result := &PingResult{Host: host, IP: ip}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "3", "-w", "3000", ip)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "3", "-W", "3", ip)
		// Force canonical output so the parsers below aren't at the mercy
		// of the user's locale. No Windows equivalent: ping.exe follows
		// the system MUI language regardless of environment (see the
		// locale-agnostic parsing below, which is the real fix there).
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	}
	sysexec.Hide(cmd)

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
	// Matches a round-trip time by its ASCII skeleton only — "=33ms",
	// "<1ms", "=32.3 ms" — with no dependency on the label before it.
	// Console-less ping.exe (CREATE_NO_WINDOW, i.e. every helper probe)
	// emits the system MUI language, so on non-English Windows the label
	// is localized AND arrives as raw ANSI bytes ("시간=33ms" in CP949);
	// only the ASCII "=33ms" part is stable. An English-only "time=..."
	// prefix is what made every probe fall through to the wall-clock
	// estimate (~687ms for a 32ms link — issue #32).
	reAnyRTT = regexp.MustCompile(`[=<]\s*([\d.]+)\s*ms`)
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

// parseIndividualPingTimes extracts per-reply round-trip times from ping
// output in any locale and returns their average, or 0 if none were found.
// Reply lines are identified by their "TTL=" token, which ping keeps as
// ASCII in every language; when no line carries one (IPv6 replies have no
// TTL) it falls back to averaging every "...ms" value in the output —
// that then includes the min/max/avg summary, which averages to the same
// place.
func parseIndividualPingTimes(output string) float64 {
	var matches [][]string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToUpper(line), "TTL=") {
			matches = append(matches, reAnyRTT.FindAllStringSubmatch(line, -1)...)
		}
	}
	if len(matches) == 0 {
		matches = reAnyRTT.FindAllStringSubmatch(output, -1)
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

