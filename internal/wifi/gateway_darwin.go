//go:build darwin

package wifi

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// GatewayMAC returns the lower-cased MAC address of the IPv4 default
// gateway (router) — a precise, medium-agnostic fingerprint of the
// specific network the machine is on. "" when it can't be determined.
//
// Two steps, both unprivileged and locale-independent (LC_ALL=C):
//   route -n get default   → the gateway IP
//   arp -n <gatewayIP>      → the gateway's MAC in the ARP cache
func GatewayMAC() string {
	gw := defaultGatewayIP()
	if gw == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "arp", "-n", gw)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return parseARPMAC(string(out))
}

func defaultGatewayIP() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "route", "-n", "get", "default")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			if net.ParseIP(gw) != nil {
				return gw
			}
		}
	}
	return ""
}

// macRegex matches a colon-separated MAC with 1- or 2-hex-digit octets
// (BSD `arp` prints "b0:38:6c:54:8b:ab" but drops leading zeros, e.g.
// "0:1e:...").
var macRegex = regexp.MustCompile(`([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}`)

// parseARPMAC extracts and normalises the MAC from an `arp -n` line like:
//
//	? (192.168.0.1) at b0:38:6c:54:8b:ab on en0 ifscope [ethernet]
func parseARPMAC(out string) string {
	m := macRegex.FindString(out)
	if m == "" {
		return ""
	}
	return normalizeMAC(m)
}

// normalizeMAC lower-cases and zero-pads each octet so BSD's "0:1e:..."
// and Linux's "00:1e:..." compare equal.
func normalizeMAC(mac string) string {
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
		parts[i] = strings.ToLower(parts[i])
	}
	return strings.Join(parts, ":")
}
