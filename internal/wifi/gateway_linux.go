//go:build linux

package wifi

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
)

// GatewayMAC returns the lower-cased MAC of the IPv4 default gateway,
// read straight from /proc (no exec, locale-independent). "" when
// unavailable.
func GatewayMAC() string {
	gw := defaultGatewayIPLinux()
	if gw == "" {
		return ""
	}
	return arpMACForIP(gw)
}

// defaultGatewayIPLinux parses /proc/net/route for the default route
// (destination 00000000) and returns its gateway as a dotted IPv4.
func defaultGatewayIPLinux() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		// fields: Iface Destination Gateway ...
		if fields[1] != "00000000" {
			continue
		}
		gwHex := fields[2]
		v, err := strconv.ParseUint(gwHex, 16, 32)
		if err != nil {
			continue
		}
		// The value is little-endian in /proc.
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(v))
		if ip.IsUnspecified() {
			continue
		}
		return ip.String()
	}
	return ""
}

// arpMACForIP looks up ip in /proc/net/arp and returns its normalised MAC.
func arpMACForIP(ip string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// fields: IPaddress HWtype Flags HWaddress Mask Device
		if len(fields) < 4 {
			continue
		}
		if fields[0] != ip {
			continue
		}
		mac := fields[3]
		if mac == "00:00:00:00:00:00" {
			return ""
		}
		return normalizeMAC(mac)
	}
	return ""
}

// normalizeMAC lower-cases and zero-pads each octet so platforms that
// drop leading zeros compare equal.
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
