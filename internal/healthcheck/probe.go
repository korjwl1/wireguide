package healthcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Probe sends one ICMP echo through the specified tunnel interface. Binding
// errors are failures; there is deliberately no fallback to the default route.
// The helper has the privileges needed for raw ICMP on all supported OSes.
func Probe(ctx context.Context, interfaceName, target string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ip := net.ParseIP(target)
	if ip == nil {
		return fmt.Errorf("invalid ping address")
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	v6 := ip.To4() == nil
	source, err := sourceAddress(iface, v6)
	if err != nil {
		return err
	}
	network := "ip4:icmp"
	protocol := 1
	var echoType icmp.Type = ipv4.ICMPTypeEcho
	if v6 {
		network = "ip6:ipv6-icmp"
		protocol = 58
		echoType = ipv6.ICMPTypeEchoRequest
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) { bindErr = bindInterface(fd, iface, v6) }); err != nil {
			return err
		}
		return bindErr
	}}
	conn, err := lc.ListenPacket(ctx, network, source.String())
	if err != nil {
		return fmt.Errorf("open bound ICMP socket: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	id := int(nonce[0])<<8 | int(nonce[1])
	seq := int(nonce[2])<<8 | int(nonce[3])
	message := icmp.Message{Type: echoType, Body: &icmp.Echo{ID: id, Seq: seq, Data: nonce}}
	var pseudo []byte
	if v6 {
		pseudo = icmp.IPv6PseudoHeader(source, ip)
	}
	packet, err := message.Marshal(pseudo)
	if err != nil {
		return err
	}
	if _, err := conn.WriteTo(packet, &net.IPAddr{IP: ip}); err != nil {
		return err
	}
	buffer := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		addr, ok := peer.(*net.IPAddr)
		if !ok || !addr.IP.Equal(ip) {
			continue
		}
		if validReply(protocol, buffer[:n], id, seq, nonce) {
			return nil
		}
	}
}

func sourceAddress(iface *net.Interface, v6 bool) (net.IP, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addresses {
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil && (ip.To4() == nil) == v6 && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("interface %s has no matching source address", iface.Name)
}

func validReply(protocol int, packet []byte, id, seq int, nonce []byte) bool {
	message, err := icmp.ParseMessage(protocol, packet)
	if err != nil || message.Code != 0 {
		return false
	}
	if protocol == 1 && message.Type != ipv4.ICMPTypeEchoReply {
		return false
	}
	if protocol == 58 && message.Type != ipv6.ICMPTypeEchoReply {
		return false
	}
	echo, ok := message.Body.(*icmp.Echo)
	return ok && echo.ID == id && echo.Seq == seq && bytes.Equal(echo.Data, nonce)
}
