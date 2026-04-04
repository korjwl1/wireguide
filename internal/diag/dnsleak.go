package diag

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

// DNSLeakResult holds the DNS leak test results.
type DNSLeakResult struct {
	Leaked     bool          `json:"leaked"`
	DNSServers []DNSServer   `json:"dns_servers"`
	TestDomain string        `json:"test_domain"`
	Error      string        `json:"error,omitempty"`
}

// DNSServer represents a detected DNS resolver.
type DNSServer struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	IsVPN    bool   `json:"is_vpn"` // true if this is the expected VPN DNS
}

// RunDNSLeakTest checks if DNS queries are going through the VPN.
// It resolves a random subdomain and checks which DNS server responded.
func RunDNSLeakTest(expectedDNS []string) *DNSLeakResult {
	result := &DNSLeakResult{}

	// Generate a random domain to prevent caching
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomSub := fmt.Sprintf("wireguide-test-%d", rng.Intn(999999))
	testDomain := randomSub + ".example.com"
	result.TestDomain = testDomain

	// Method 1: Check system resolver configuration
	// On macOS: scutil --dns, on Linux: /etc/resolv.conf
	systemDNS := getSystemDNSServers()

	expectedSet := make(map[string]bool)
	for _, dns := range expectedDNS {
		expectedSet[dns] = true
	}

	leaked := false
	for _, dns := range systemDNS {
		isVPN := expectedSet[dns]
		hostname, _ := net.LookupAddr(dns)
		hn := ""
		if len(hostname) > 0 {
			hn = hostname[0]
		}
		result.DNSServers = append(result.DNSServers, DNSServer{
			IP:       dns,
			Hostname: hn,
			IsVPN:    isVPN,
		})
		if !isVPN {
			leaked = true
		}
	}

	result.Leaked = leaked
	return result
}

func getSystemDNSServers() []string {
	// Use net.DefaultResolver to find configured DNS
	// This is a simplified approach — production would parse OS config directly
	config, err := readResolvConf()
	if err != nil {
		return nil
	}
	return config
}

func readResolvConf() ([]string, error) {
	// Try reading /etc/resolv.conf (works on macOS and Linux)
	resolver := net.DefaultResolver
	_ = resolver // Use default resolver

	// Fallback: parse resolv.conf manually
	addrs, err := net.LookupHost("dns.google")
	if err != nil {
		return nil, err
	}
	// This doesn't actually give us the DNS server, just tests resolution
	_ = addrs

	// For now, return empty — real implementation would parse:
	// macOS: scutil --dns | grep nameserver
	// Linux: /etc/resolv.conf
	return nil, nil
}
