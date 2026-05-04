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

// RunDNSLeakTest checks if DNS queries are going through the VPN.
// It resolves a random subdomain via each configured system DNS server and
// checks whether any non-VPN server actually handles the query.
func RunDNSLeakTest(expectedDNS []string) *DNSLeakResult {
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

	leaked := false
	for _, dns := range systemDNS {
		isVPN := expectedSet[dns]
		lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		hostname, _ := (&net.Resolver{}).LookupAddr(lookupCtx, dns)
		lookupCancel()
		hn := ""
		if len(hostname) > 0 {
			hn = hostname[0]
		}

		// Actually test whether this DNS server responds to queries.
		// A server that is configured but unreachable is not a leak risk.
		responds := testDNSServer(dns, testDomain)

		result.DNSServers = append(result.DNSServers, DNSServer{
			IP:       dns,
			Hostname: hn,
			IsVPN:    isVPN,
		})
		if !isVPN && responds {
			leaked = true
		}
	}

	result.Leaked = leaked
	return result
}

// testDNSServer performs an actual DNS lookup of domain via the given server
// to verify it handles queries. Returns true if the server responded.
func testDNSServer(server, domain string) bool {
	// Ensure host:port format for the dialer.
	// Use JoinHostPort so IPv6 addresses are bracketed correctly.
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// We don't care about the result — only whether the server responded
	// at all (NXDOMAIN is still a valid response showing the server is active).
	_, err := resolver.LookupHost(ctx, domain)
	// A timeout or connection refusal means the server didn't respond.
	// NXDOMAIN comes back as a *net.DNSError with IsNotFound=true — that
	// still means the server IS responding.
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return true // server responded with NXDOMAIN
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
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Sort-Object -Unique`).CombinedOutput()
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
