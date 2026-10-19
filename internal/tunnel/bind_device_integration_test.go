package tunnel

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// These tests run actual WireGuard encryption, handshakes and UDP sockets
// over loopback. Interface-binding syscalls are simulated: exercising the
// Windows kernel's IP_UNICAST_IF still requires a Windows host.
type lifecycleSocketBind struct {
	conn.Bind
	port atomic.Uint32
	sent atomic.Uint64
}

func (b *lifecycleSocketBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err == nil {
		b.port.Store(uint32(actual))
	}
	return fns, actual, err
}
func (b *lifecycleSocketBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.sent.Add(uint64(len(bufs)))
	return b.Bind.Send(bufs, ep)
}
func (b *lifecycleSocketBind) BindSocketToInterface4(uint32, bool) error { return nil }
func (b *lifecycleSocketBind) BindSocketToInterface6(uint32, bool) error { return nil }

type observedSendBind struct {
	conn.Bind
	attempted chan struct{}
}

func (b *observedSendBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	err := b.Bind.Send(bufs, ep)
	select {
	case b.attempted <- struct{}{}:
	default:
	}
	return err
}

func TestGuardedBindsWireGuardDeviceLifecycle(t *testing.T) {
	for _, mode := range []string{"route gate", "interface gate"} {
		t.Run(mode, func(t *testing.T) {
			var keys [2]wgtypes.Key
			var devs [2]*device.Device
			var tuns [2]*tuntest.ChannelTUN
			var sockets [2]*lifecycleSocketBind
			var pause func(bool)
			var observed *observedSendBind
			for i := range devs {
				key, err := wgtypes.GeneratePrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				keys[i] = key
				tuns[i] = tuntest.NewChannelTUN()
				sockets[i] = &lifecycleSocketBind{Bind: conn.NewStdNetBind()}
				var bind conn.Bind = sockets[i]
				if i == 0 {
					if mode == "route gate" {
						guard := &routeGuardBind{Bind: bind, allowed: true}
						bind = guard
						pause = func(block bool) { guard.SetEndpointTrafficAllowed(!block) }
					} else {
						guard := &guardedBind{Bind: bind, binder: sockets[i]}
						for family := range guard.families {
							guard.families[family] = socketFamilyBinding{index: 1, configured: true}
						}
						bind = guard
						pause = func(block bool) {
							index := uint32(1)
							if block {
								index = 0
							}
							if err := guard.BindSocketToInterface4(index, block); err != nil {
								t.Fatal(err)
							}
						}
					}
					observed = &observedSendBind{Bind: bind, attempted: make(chan struct{}, 32)}
					bind = observed
				}
				devs[i] = device.NewDevice(tuns[i].TUN(), bind, device.NewLogger(device.LogLevelError, "bind lifecycle: "))
				dev := devs[i]
				t.Cleanup(dev.Close)
			}
			for i, dev := range devs {
				pub := keys[1-i].PublicKey()
				cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.0.0.%d/32\n",
					hex.EncodeToString(keys[i][:]), hex.EncodeToString(pub[:]), 2-i)
				if err := dev.IpcSet(cfg); err != nil {
					t.Fatal(err)
				}
				if err := dev.Up(); err != nil {
					t.Fatal(err)
				}
			}
			for i, dev := range devs {
				pub := keys[1-i].PublicKey()
				cfg := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\n", hex.EncodeToString(pub[:]), sockets[1-i].port.Load())
				if err := dev.IpcSet(cfg); err != nil {
					t.Fatal(err)
				}
			}
			transfer := func(from int) {
				t.Helper()
				packet := tuntest.Ping(netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", 2-from)),
					netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", from+1)))
				select {
				case tuns[from].Outbound <- packet:
				case <-time.After(3 * time.Second):
					t.Fatal("WireGuard stopped reading outbound packets")
				}
				select {
				case received := <-tuns[1-from].Inbound:
					if !bytes.Equal(received, packet) {
						t.Fatal("decrypted packet changed")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("WireGuard did not deliver the encrypted packet")
				}
			}
			transfer(0)
			transfer(1)
			pause(true)
			// Socket recreation must preserve a paused gate as well as the
			// healthy binding. WireGuard calls this on port/network changes.
			if err := devs[0].BindUpdate(); err != nil {
				t.Fatal(err)
			}
			for len(observed.attempted) > 0 {
				<-observed.attempted
			}
			sent := sockets[0].sent.Load()
			packet := tuntest.Ping(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"))
			select {
			case tuns[0].Outbound <- packet:
			case <-time.After(3 * time.Second):
				t.Fatal("paused device stopped consuming packets")
			}
			select {
			case <-observed.attempted:
			case <-time.After(3 * time.Second):
				t.Fatal("device did not attempt the paused send")
			}
			if sockets[0].sent.Load() != sent {
				t.Fatal("paused device sent a UDP packet after socket recreation")
			}
			pause(false)
			transfer(0)
			transfer(1)
			if err := devs[0].BindUpdate(); err != nil {
				t.Fatal(err)
			}
			transfer(0)
		})
	}
}
