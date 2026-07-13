//go:build windows

package wifi

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/korjwl1/wireguide/internal/network"
)

var (
	modIphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = modIphlpapi.NewProc("SendARP")
)

// vpnAdapterAliases are the interface friendly-names to exclude when
// resolving the underlay gateway, so a full tunnel doesn't hide the
// physical network. WireGuide's adapter is "WireGuide" (see
// reconnect/network_windows.go, which uses the same constant).
var vpnAdapterAliases = []string{"WireGuide"}

// GatewayMAC returns the lower-cased MAC of the IPv4 default gateway — a
// precise, medium-agnostic fingerprint of the physical network. "" when
// it can't be determined.
//
// It resolves the PHYSICAL default gateway via the routing table while
// excluding the WireGuard adapter, then SendARP-resolves that gateway IP
// to its MAC. Using the routing table (not GetBestRoute to a public IP)
// is deliberate: once a full tunnel is up, WireGuard's 0.0.0.0/1 +
// 128.0.0.0/1 routes would make GetBestRoute return the tunnel, whose
// on-link next-hop is zero — the gateway MAC would go blank exactly when
// the tunnel connected, flapping any `mac:` automation rule. Both steps
// are unprivileged and locale-independent.
func GatewayMAC() string {
	gw := network.UnderlayDefaultGatewayV4(vpnAdapterAliases)
	if gw == "" {
		return ""
	}
	ip4 := net.ParseIP(gw).To4()
	if ip4 == nil {
		return ""
	}
	// SendARP's destination is an IPAddr (a DWORD in network byte order);
	// build it so its in-memory bytes are ip4[0..3], matching the wire order.
	dest := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	var mac [8]byte
	macLen := uint32(6)
	ret, _, _ := procSendARP.Call(
		uintptr(dest), 0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 || macLen < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
