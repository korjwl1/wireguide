package diag

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// DNSLeakResult holds the DNS leak test results.
type DNSLeakResult struct {
	Leaked     bool        `json:"leaked"`
	DNSServers []DNSServer `json:"dns_servers"`
	TestDomain string      `json:"test_domain"`
	Error      string      `json:"error,omitempty"`
}

// DNSServer represents a detected DNS resolver.
type DNSServer struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	IsVPN    bool   `json:"is_vpn"` // true if this is the expected VPN DNS
}

// RunDNSLeakTest is a context-less convenience wrapper for callers that
// don't have one. Bounded by a hard 10-second cap so a hung resolver
// can't lock up the diagnostic panel.
func RunDNSLeakTest(expectedDNS []string) *DNSLeakResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return RunDNSLeakTestContext(ctx, expectedDNS)
}

// RunDNSLeakTestContext checks if DNS queries are going through the VPN.
// It resolves a random subdomain via each configured system DNS server in
// PARALLEL and checks whether any non-VPN server actually handles the
// query. The whole test honours ctx — if the caller cancels (user closes
// the diagnostics panel) every in-flight resolver lookup aborts within
// its own per-request timeout slot.
//
// Parallel execution caps wall-clock at the slowest single resolver
// (typically <1s for working DNS, 3s for a dead one) instead of the sum
// (which on a machine with 8 system DNS entries could exceed a minute).
func RunDNSLeakTestContext(ctx context.Context, expectedDNS []string) *DNSLeakResult {
	result := &DNSLeakResult{}

	// Generate a fresh random subdomain so the test query can't be
	// served from any resolver's cache. crypto/rand (16 bytes hex)
	// gives 128 bits of randomness — far beyond any feasible cache
	// pre-population. .invalid is reserved by RFC 6761 for "must
	// always return NXDOMAIN" so the test can't accidentally hit a
	// real domain or load a third-party authoritative server.
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		result.Error = "cannot generate random domain"
		return result
	}
	testDomain := "wireguide-" + hex.EncodeToString(nonce[:]) + ".invalid"
	result.TestDomain = testDomain

	// Check system resolver configuration
	// On macOS: scutil --dns, on Linux: /etc/resolv.conf
	systemDNS := getSystemDNSServers()

	expectedSet := make(map[string]bool)
	for _, dns := range expectedDNS {
		expectedSet[dns] = true
	}

	type probeResult struct {
		idx     int
		hostname string
		responds bool
	}

	// Pre-fill DNSServers so each slot has at least the IP and IsVPN
	// flag even if its probe never returns. The earlier version left
	// timed-out slots zero-valued (empty IP, empty hostname, IsVPN=false),
	// so the UI rendered placeholder "!" badges with no IP next to them
	// whenever any probe hit the outer ctx deadline. The probe loop now
	// just overlays Hostname/IsVPN-promotion on top of these defaults.
	result.DNSServers = make([]DNSServer, len(systemDNS))
	for i, dns := range systemDNS {
		result.DNSServers[i] = DNSServer{
			IP:    dns,
			IsVPN: expectedSet[dns],
		}
	}

	probes := make(chan probeResult, len(systemDNS))
	for i, dns := range systemDNS {
		go func(idx int, dnsIP string) {
			// Per-resolver budget: 3s. Caller's ctx still acts as the
			// global ceiling — whichever expires first wins.
			lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			hn := ""
			if names, err := (&net.Resolver{}).LookupAddr(lookupCtx, dnsIP); err == nil && len(names) > 0 {
				hn = names[0]
			}
			responds := testDNSServerCtx(lookupCtx, dnsIP, testDomain)
			probes <- probeResult{idx: idx, hostname: hn, responds: responds}
		}(i, dns)
	}

	leaked := false
	for range systemDNS {
		select {
		case <-ctx.Done():
			result.Error = "test cancelled or timed out"
			result.Leaked = leaked
			return result
		case p := <-probes:
			result.DNSServers[p.idx].Hostname = p.hostname
			if !result.DNSServers[p.idx].IsVPN && p.responds {
				leaked = true
			}
		}
	}

	result.Leaked = leaked
	return result
}

// testDNSServerCtx is testDNSServer with caller-supplied context. The
// existing testDNSServer wraps this for the (deprecated) context-less
// callers.
func testDNSServerCtx(ctx context.Context, server, domain string) bool {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}
	_, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return true
		}
		return false
	}
	return true
}

func getSystemDNSServers() []string {
	servers, err := readSystemResolvers()
	if err != nil {
		return nil
	}
	return servers
}

// readSystemResolvers detects configured DNS servers using OS-specific methods.
func readSystemResolvers() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		return readLinuxResolvers()
	case "darwin":
		return readDarwinResolvers()
	case "windows":
		return readWindowsResolvers()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// readLinuxResolvers parses /etc/resolv.conf for nameserver entries.
func readLinuxResolvers() ([]string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var servers []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ip := fields[1]
			if !seen[ip] {
				seen[ip] = true
				servers = append(servers, ip)
			}
		}
	}
	return servers, scanner.Err()
}

// readWindowsResolvers uses PowerShell to extract DNS server addresses.
func readWindowsResolvers() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Sort-Object -Unique`)
	sysexec.Hide(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Get-DnsClientServerAddress: %w", err)
	}

	var servers []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		ip := strings.TrimSpace(line)
		if net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			servers = append(servers, ip)
		}
	}
	return servers, nil
}

// readDarwinResolvers uses `scutil --dns` to extract nameserver addresses.
func readDarwinResolvers() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return nil, fmt.Errorf("scutil --dns: %w", err)
	}

	var servers []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			// Format: "nameserver[0] : 8.8.8.8"
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[1])
				if net.ParseIP(ip) != nil && !seen[ip] {
					seen[ip] = true
					servers = append(servers, ip)
				}
			}
		}
	}
	return servers, nil
}
