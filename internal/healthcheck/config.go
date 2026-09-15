// Package healthcheck implements opt-in, per-tunnel ICMP health checks.
package healthcheck

import (
	"fmt"
	"net/netip"
)

// Config lives in the tunnel's metadata, never in an exported WireGuard file.
type Config struct {
	Enabled          bool     `json:"enabled"`
	Targets          []string `json:"targets"`
	IntervalSeconds  int      `json:"interval_seconds"`
	FailureThreshold int      `json:"failure_threshold"`
}

func DefaultConfig() Config {
	return Config{IntervalSeconds: 30, FailureThreshold: 3, Targets: []string{}}
}

// Normalize rejects ambiguous destinations (DNS, ports, multicast and zones).
// Literal unicast addresses avoid sending DNS queries outside a broken tunnel.
func (c Config) Normalize() (Config, error) {
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 30
	}
	if c.FailureThreshold == 0 {
		c.FailureThreshold = 3
	}
	if c.IntervalSeconds < 10 || c.IntervalSeconds > 300 {
		return c, fmt.Errorf("ping interval must be between 10 and 300 seconds")
	}
	if c.FailureThreshold < 1 || c.FailureThreshold > 10 {
		return c, fmt.Errorf("consecutive failures must be between 1 and 10")
	}
	if len(c.Targets) > 5 {
		return c, fmt.Errorf("at most 5 ping targets are allowed")
	}
	targets := make([]string, 0, len(c.Targets))
	seen := map[netip.Addr]bool{}
	for _, target := range c.Targets {
		ip, err := netip.ParseAddr(target)
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
			return c, fmt.Errorf("ping target %q must be a unicast IPv4 or IPv6 address", target)
		}
		ip = ip.Unmap()
		if !seen[ip] {
			targets = append(targets, ip.String())
			seen[ip] = true
		}
	}
	if c.Enabled && len(targets) == 0 {
		return c, fmt.Errorf("add at least one ping target before enabling health checks")
	}
	c.Targets = targets
	return c, nil
}

func Covered(target string, allowedIPs []string) bool {
	ip, err := netip.ParseAddr(target)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, route := range allowedIPs {
		if prefix, err := netip.ParsePrefix(route); err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
