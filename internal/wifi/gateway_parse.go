package wifi

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// Pure parsers for Linux /proc/net/route and /proc/net/arp, kept in an
// untagged file so their unit tests run on every development platform.
// The linux-only wrappers in gateway_linux.go feed them the real files.
//
// These replaced a first-match parser that ignored route flags, metric,
// the netmask column, and tunnel interfaces, and an ARP lookup keyed by
// IP alone (issue #22): a wg0 default route, a higher-metric secondary
// uplink, or a stale/incomplete ARP entry on the wrong device could all
// fingerprint the wrong network — and gateway-MAC is a *trust* signal
// for Automation rules.

// rtfUp is Linux's RTF_UP route flag (route is usable). The value is
// ABI-stable; defined locally so this file stays platform-untagged.
const rtfUp = 0x1

// atfCom is Linux's ATF_COM ARP flag (lookup complete). Entries without
// it are in-progress or failed resolutions whose HW address is garbage.
const atfCom = 0x2

// bestDefaultRoute picks the usable IPv4 default route with the lowest
// metric from /proc/net/route content and returns its gateway (dotted
// form) and interface. isTunnel filters interfaces that must never count
// (VPN adapters — including our own — and virtual devices).
func bestDefaultRoute(routeTable []byte, isTunnel func(string) bool) (gw, iface string) {
	sc := bufio.NewScanner(bytes.NewReader(routeTable))
	sc.Scan() // header
	bestMetric := uint64(0)
	found := false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 64)
		metric, err2 := strconv.ParseUint(f[6], 10, 64)
		if err1 != nil || err2 != nil || flags&rtfUp == 0 {
			continue
		}
		if isTunnel != nil && isTunnel(f[0]) {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(v)) // little-endian in /proc
		if ip.IsUnspecified() {
			continue
		}
		if !found || metric < bestMetric {
			found = true
			bestMetric = metric
			gw = ip.String()
			iface = f[0]
		}
	}
	return gw, iface
}

// arpMACForIPOnIface finds ip's completed ARP entry on the given device
// in /proc/net/arp content and returns its normalised MAC. Filtering by
// device matters on hosts where two networks share a gateway IP (a
// docker bridge and the LAN both using 192.168.x.1); requiring ATF_COM
// rejects incomplete/stale entries whose HW address is meaningless.
func arpMACForIPOnIface(arpTable []byte, ip, iface string) string {
	sc := bufio.NewScanner(bytes.NewReader(arpTable))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// IPaddress HWtype Flags HWaddress Mask Device
		if len(f) < 6 || f[0] != ip || f[5] != iface {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&atfCom == 0 {
			continue
		}
		mac := f[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		return normalizeMAC(mac)
	}
	return ""
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
