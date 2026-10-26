//go:build windows

package wireguardnt

import (
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"
)

func TestStructOffsets(t *testing.T) {
	if got := unsafe.Offsetof(wireguardInterface{}.PrivateKey); got != 6 {
		t.Fatalf("private key offset = %d, want 6", got)
	}
	if got := unsafe.Offsetof(wireguardInterface{}.PublicKey); got != 38 {
		t.Fatalf("public key offset = %d, want 38", got)
	}
	if got := unsafe.Offsetof(wireguardInterface{}.PeersCount); got != 72 {
		t.Fatalf("peers count offset = %d, want 72", got)
	}
	if got := unsafe.Offsetof(wireguardPeer{}.PublicKey); got != 8 {
		t.Fatalf("peer public key offset = %d, want 8", got)
	}
	if got := unsafe.Offsetof(wireguardPeer{}.PresharedKey); got != 40 {
		t.Fatalf("peer preshared key offset = %d, want 40", got)
	}
	if got := unsafe.Offsetof(wireguardPeer{}.Endpoint); got != 76 {
		t.Fatalf("peer endpoint offset = %d, want 76", got)
	}
	if got := unsafe.Offsetof(wireguardPeer{}.TxBytes); got != 104 {
		t.Fatalf("peer tx offset = %d, want 104", got)
	}
	if got := unsafe.Offsetof(wireguardPeer{}.LastHandshake); got != 120 {
		t.Fatalf("peer handshake offset = %d, want 120", got)
	}
	if got := unsafe.Offsetof(wireguardPeer{}.AllowedIPsCount); got != 128 {
		t.Fatalf("peer allowed count offset = %d, want 128", got)
	}
	if got := unsafe.Offsetof(wireguardAllowedIP{}.AddressFamily); got != 16 {
		t.Fatalf("allowed IP family offset = %d, want 16", got)
	}
	if got := unsafe.Offsetof(wireguardAllowedIP{}.Cidr); got != 18 {
		t.Fatalf("allowed IP cidr offset = %d, want 18", got)
	}
	if got := unsafe.Offsetof(wireguardAllowedIP{}.Flags); got != 20 {
		t.Fatalf("allowed IP flags offset = %d, want 20", got)
	}
}

func TestConfigurationEncoding(t *testing.T) {
	var privateKey [32]byte
	var publicKey [32]byte
	for i := range privateKey {
		privateKey[i] = byte(i + 1)
		publicKey[i] = byte(i + 101)
	}
	cfg := &Configuration{
		PrivateKey: privateKey,
		ListenPort: 51820,
		Peers: []Peer{{
			PublicKey:           publicKey,
			Endpoint:            netip.MustParseAddrPort("203.0.113.7:51820"),
			PersistentKeepalive: 25,
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8::/32")},
		}},
	}
	raw, backing, err := encodeConfiguration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.KeepAlive(backing)

	iface := (*wireguardInterface)(unsafe.Pointer(&raw[0]))
	if iface.PeersCount != 1 {
		t.Fatalf("peers count = %d, want 1", iface.PeersCount)
	}
	if iface.ListenPort != 51820 || iface.Flags&interfaceHasListenPort == 0 {
		t.Fatalf("listen port not encoded: flags=%#x port=%d", iface.Flags, iface.ListenPort)
	}
	if iface.PrivateKey != privateKey {
		t.Fatal("private key mismatch")
	}

	peer := (*wireguardPeer)(unsafe.Pointer(&raw[unsafe.Sizeof(wireguardInterface{})]))
	if peer.Flags&peerHasEndpoint == 0 || peer.Flags&peerReplaceAllowedIPs == 0 {
		t.Fatalf("peer flags = %#x", peer.Flags)
	}
	if peer.AllowedIPsCount != 2 {
		t.Fatalf("allowed IP count = %d, want 2", peer.AllowedIPsCount)
	}
	if got := decodeSockaddr(peer.Endpoint); got != netip.MustParseAddrPort("203.0.113.7:51820") {
		t.Fatalf("endpoint round trip = %v", got)
	}

	// Inject live counters the way the driver does, then decode the whole
	// buffer as a Snapshot.
	peer.TxBytes = 1234
	peer.RxBytes = 5678
	peer.LastHandshake = windowsEpochOffset + 10_000_000 // one second after the Unix epoch
	snapshot, err := decodeConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Peers) != 1 {
		t.Fatalf("decoded peers = %d, want 1", len(snapshot.Peers))
	}
	state := snapshot.Peers[0]
	if state.TxBytes != 1234 || state.RxBytes != 5678 {
		t.Fatalf("counters = tx %d rx %d", state.TxBytes, state.RxBytes)
	}
	if !state.LastHandshake.Equal(time.Unix(1, 0)) {
		t.Fatalf("handshake = %v, want %v", state.LastHandshake, time.Unix(1, 0))
	}
	if !state.Endpoint.IsValid() {
		t.Fatal("decoded endpoint is invalid")
	}
	if len(state.AllowedIPs) != 2 || state.AllowedIPs[0].String() != "10.0.0.0/24" || state.AllowedIPs[1].String() != "2001:db8::/32" {
		t.Fatalf("allowed IPs = %v", state.AllowedIPs)
	}
}

func TestConfigurationPreservesMappedIPv6AllowedIPs(t *testing.T) {
	prefix := netip.MustParsePrefix("::ffff:192.0.2.0/120")
	raw, backing, err := encodeConfiguration(&Configuration{Peers: []Peer{{AllowedIPs: []netip.Prefix{prefix}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.KeepAlive(backing)
	snapshot, err := decodeConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Peers) != 1 || len(snapshot.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("mapped IPv6 AllowedIPs were lost: %+v", snapshot)
	}
	if got := snapshot.Peers[0].AllowedIPs[0]; got != prefix {
		t.Fatalf("AllowedIP = %s, want %s", got, prefix)
	}
}

func TestSockaddrIPv6(t *testing.T) {
	want := netip.MustParseAddrPort("[2001:db8::1]:51820")
	encoded, err := encodeSockaddr(want)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeSockaddr(encoded)
	if got != want {
		t.Fatalf("endpoint round trip = %v, want %v", got, want)
	}
}

func TestSockaddrIPv6Zone(t *testing.T) {
	want := netip.MustParseAddrPort("[fe80::1%7]:51820")
	encoded, err := encodeSockaddr(want)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeSockaddr(encoded); got != want {
		t.Fatalf("scoped endpoint = %s, want %s", got, want)
	}
}

func TestSockaddrIPv6NamedZone(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) == 0 {
		t.Skip("no network interfaces")
	}
	iface := interfaces[0]
	endpoint := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone(iface.Name), 51820)
	encoded, err := encodeSockaddr(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	want := netip.AddrPortFrom(endpoint.Addr().WithZone(strconv.Itoa(iface.Index)), endpoint.Port())
	if got := decodeSockaddr(encoded); got != want {
		t.Fatalf("scoped endpoint = %s, want %s", got, want)
	}
}

func TestConfigurationRejectsUnknownIPv6Zone(t *testing.T) {
	endpoint := netip.MustParseAddrPort("[fe80::1%wireguide-missing-zone-42]:51820")
	if _, _, err := encodeConfiguration(&Configuration{Peers: []Peer{{Endpoint: endpoint}}}); err == nil {
		t.Fatal("unknown IPv6 zone was silently discarded")
	}
}

func TestDecodeAllowedIPRejectsInvalidCIDR(t *testing.T) {
	aip := &wireguardAllowedIP{AddressFamily: afInet, Cidr: 33}
	if _, ok := decodeAllowedIP(aip); ok {
		t.Fatal("accepted IPv4 CIDR larger than 32")
	}
}
