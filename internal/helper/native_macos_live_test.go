//go:build darwin && cgo

package helper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/healthcheck"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Opt-in native integration. The client uses production helper handlers,
// real utun interfaces/routes, scutil, networksetup, PF, IPC and system
// launchd. Only the remote peer is a controlled userspace packet responder.
// Run with scripts/macos_native_live_test.py; never against an active VPN.
func nativeLiveRoot(t *testing.T) string {
	t.Helper()
	if os.Getenv("WIREGUIDE_TEST_MACOS_LIVE") != "1" {
		t.Skip("opt-in privileged macOS integration")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native network integration requires administrator authorization")
	}
	dir := os.Getenv("WIREGUIDE_MACOS_LIVE_DIR")
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatal("isolated evidence directory required")
	}
	return dir
}

func TestMacOSLiveHelperChild(t *testing.T) {
	dir := nativeLiveRoot(t)
	if os.Getenv("WIREGUIDE_MACOS_LIVE_CHILD") != "1" {
		t.Skip("launchd fixture only")
	}
	addr := filepath.Join(dir, "h.sock")
	ln, _, activated, err := acquireListener(addr, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	fw := firewall.NewPlatformFirewall()
	data := filepath.Join(dir, "helper")
	tunnel.RecoverFromCrash(data, fw)
	fw.RecoverFromCrash()
	h := &Helper{server: ipc.NewServer(ln, 0), activated: activated, manager: tunnel.NewManager(data), firewall: fw, dataDir: data,
		activeCfgs: map[string]*domain.WireGuardConfig{}, pendingDesired: map[string]struct{}{}, watchdogBlocked: loadWatchdogBlocked(data),
		autoConnectedBy: map[string]string{}, latencyByTunnel: map[string]float64{}, logLevel: new(slog.LevelVar), done: make(chan struct{}),
		guiSeenCh: make(chan struct{}), userAppSupport: filepath.Join(dir, "config"), restoreOnStart: true}
	h.userTunnelStore = storage.NewTunnelStore(filepath.Join(h.userAppSupport, "tunnels"))
	h.monitor = reconnect.NewMonitor(h.manager, h.reconnectFn, h.onReconnectState, reconnect.DefaultConfig())
	h.monitor.SetFirewallCallbacks(h.suspendFirewall, h.resumeFirewall)
	h.manager.SetOnForcedDisconnect(h.handleForcedDisconnect)
	h.restoreUserSettings()
	h.registerHandlers()
	// These test-only event injections exercise real teardown and reconnect;
	// they do not claim to reproduce detection of a physical routing loop.
	h.server.Handle("Live.Reconnect", func(raw json.RawMessage) (interface{}, error) {
		var name string
		json.Unmarshal(raw, &name)
		return ipc.Empty{}, h.reconnectFn(context.Background(), name)
	})
	h.server.Handle("Live.ForcedDisconnect", func(raw json.RawMessage) (interface{}, error) {
		var name string
		json.Unmarshal(raw, &name)
		h.handleForcedDisconnect(tunnel.NewForcedDisconnect(name, "", "native fixture", nil))
		return ipc.Empty{}, nil
	})
	h.server.OnConnect(func() { h.markGUISeen(); h.cancelShutdownTimer() })
	h.server.OnDisconnect(h.startShutdownTimer)
	h.restoreInProgress = true
	h.armStartupGrace()
	h.goSafe("desiredStateRestore", h.restoreDesiredTunnels)
	h.goSafe("dnsReconcileLoop", h.dnsReconcileLoop)
	if err := os.WriteFile(filepath.Join(dir, "child.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	err = h.server.Serve()
	h.cleanup()
	if err != nil {
		t.Fatal(err)
	}
}

func TestMacOSLiveEmergencyCleanup(t *testing.T) {
	dir := nativeLiveRoot(t)
	fw := firewall.NewPlatformFirewall()
	tunnel.RecoverFromCrash(filepath.Join(dir, "helper"), fw)
	fw.RecoverFromCrash()
	if err := fw.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func liveCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return string(out)
}
func liveWait(t *testing.T, what string, budget time.Duration, fn func() bool) {
	t.Helper()
	end := time.Now().Add(budget)
	for time.Now().Before(end) {
		if fn() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}
func liveCall(t *testing.T, c *ipc.Client, method string, arg, result interface{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.CallWithContext(ctx, method, arg, result); err != nil {
		t.Fatalf("%s: %v", method, err)
	}
}

func liveChecksum(p []byte) uint16 {
	var s uint32
	for len(p) > 1 {
		s += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		s += uint32(p[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func liveReply(p []byte) []byte {
	if len(p) < 20 {
		return nil
	}
	r := append([]byte(nil), p...)
	if p[0]>>4 == 6 {
		if len(p) < 48 || p[6] != 58 || p[40] != 128 {
			return nil
		}
		copy(r[8:24], p[24:40])
		copy(r[24:40], p[8:24])
		msg, err := icmp.ParseMessage(58, p[40:])
		if err != nil {
			return nil
		}
		msg.Type = ipv6.ICMPTypeEchoReply
		body, err := msg.Marshal(icmp.IPv6PseudoHeader(net.IP(r[8:24]), net.IP(r[24:40])))
		if err != nil {
			return nil
		}
		return append(r[:40], body...)
	}
	if p[0]>>4 != 4 {
		return nil
	}
	h := int(p[0]&15) * 4
	if len(p) < h+8 {
		return nil
	}
	copy(r[12:16], p[16:20])
	copy(r[16:20], p[12:16])
	switch p[9] {
	case 1:
		if p[h] != 8 {
			return nil
		}
		r[h] = 0
		r[h+2], r[h+3] = 0, 0
		binary.BigEndian.PutUint16(r[h+2:], liveChecksum(r[h:]))
	case 17:
		if binary.BigEndian.Uint16(p[h+2:]) != 53 {
			return nil
		}
		var q dnsmessage.Message
		if q.Unpack(p[h+8:]) != nil {
			return nil
		}
		answer := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}, Questions: q.Questions}
		for _, question := range q.Questions {
			if question.Type == dnsmessage.TypeA {
				answer.Answers = append(answer.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 42}}})
			}
		}
		body, err := answer.Pack()
		if err != nil {
			return nil
		}
		r = append(r[:h+8], body...)
		copy(r[h:h+2], p[h+2:h+4])
		copy(r[h+2:h+4], p[h:h+2])
		binary.BigEndian.PutUint16(r[h+4:], uint16(8+len(body)))
		r[h+6], r[h+7] = 0, 0
	default:
		return nil
	}
	binary.BigEndian.PutUint16(r[2:], uint16(len(r)))
	r[10], r[11] = 0, 0
	binary.BigEndian.PutUint16(r[10:], liveChecksum(r[:h]))
	return r
}
func livePeer(t *testing.T, idx int) *domain.WireGuardConfig {
	t.Helper()
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ch := tuntest.NewChannelTUN()
	dev := device.NewDevice(ch.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "live-peer: "))
	clientPublic := clientKey.PublicKey()
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=198.18.%d.2/32\nallowed_ip=fd42:5747:%d::2/128\n", hex.EncodeToString(serverKey[:]), hex.EncodeToString(clientPublic[:]), idx, idx)); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	go func() {
		for p := range ch.Inbound {
			if reply := liveReply(p); reply != nil {
				select {
				case ch.Outbound <- reply:
				case <-time.After(time.Second):
				}
			}
		}
	}()
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatal("peer has no UDP listener")
	}
	cfg := &domain.WireGuardConfig{Name: fmt.Sprintf("NativeLive-%d", idx), Interface: domain.InterfaceConfig{PrivateKey: clientKey.String(), Address: []string{fmt.Sprintf("198.18.%d.2/24", idx), fmt.Sprintf("fd42:5747:%d::2/64", idx)}, DNS: []string{fmt.Sprintf("198.18.%d.1", idx)}}, Peers: []domain.PeerConfig{{PublicKey: serverKey.PublicKey().String(), Endpoint: net.JoinHostPort("127.0.0.1", port), AllowedIPs: []string{fmt.Sprintf("198.18.%d.0/24", idx), fmt.Sprintf("fd42:5747:%d::/64", idx)}}}}
	return cfg
}
func liveDNS(t *testing.T, server string, want bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	}}
	ips, err := r.LookupHost(ctx, "fixture.wg-live.invalid")
	ok := err == nil && len(ips) > 0 && ips[0] == "198.51.100.42"
	if ok != want {
		t.Fatalf("DNS %s: success=%v want=%v error=%v", server, ok, want, err)
	}
}
func livePing(t *testing.T, c *ipc.Client, cfg *domain.WireGuardConfig) {
	t.Helper()
	var response domain.ConnectionStatus
	liveCall(t, c, ipc.MethodStatus, nil, &response)
	rows := response.Tunnels
	if len(rows) == 0 {
		rows = []domain.ConnectionStatus{response}
	}
	for _, st := range rows {
		if st.TunnelName == cfg.Name {
			for _, target := range []string{fmt.Sprintf("198.18.%s.1", strings.TrimPrefix(cfg.Name, "NativeLive-")), fmt.Sprintf("fd42:5747:%s::1", strings.TrimPrefix(cfg.Name, "NativeLive-"))} {
				if err := healthcheck.Probe(context.Background(), st.InterfaceName, target); err != nil {
					t.Fatalf("native ICMP %s (%s): %v", target, st.InterfaceName, err)
				}
			}
			return
		}
	}
	t.Fatalf("tunnel absent from status: %s", cfg.Name)
}

func liveWaitConnected(t *testing.T, c *ipc.Client, names ...string) {
	t.Helper()
	liveWait(t, "connected tunnels: "+strings.Join(names, ", "), 30*time.Second, func() bool {
		var status domain.ConnectionStatus
		if err := c.Call(ipc.MethodStatus, nil, &status); err != nil {
			return false
		}
		rows := status.Tunnels
		if len(rows) == 0 {
			rows = []domain.ConnectionStatus{status}
		}
		if len(rows) != len(names) {
			return false
		}
		for _, name := range names {
			found := false
			for _, row := range rows {
				found = found || (row.TunnelName == name && row.State == domain.StateConnected && row.InterfaceName != "")
			}
			if !found {
				return false
			}
		}
		return true
	})
}

func liveServicePreferences(t *testing.T) string {
	t.Helper()
	services := strings.Split(liveCommand(t, "/usr/sbin/networksetup", "-listallnetworkservices"), "\n")
	state := map[string][]string{}
	for _, row := range services[1:] {
		name := strings.TrimPrefix(strings.TrimSpace(row), "*")
		if name == "" {
			continue
		}
		state[name] = []string{liveCommand(t, "/usr/sbin/networksetup", "-getdnsservers", name), liveCommand(t, "/usr/sbin/networksetup", "-getsearchdomains", name)}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

type livePFReference struct {
	Token    string `json:"token"`
	OwnerPID int    `json:"owner_pid"`
}

func livePFLease() (livePFReference, error) {
	var lease livePFReference
	raw, err := os.ReadFile("/Library/Application Support/wireguide/pf-was-enabled")
	if err != nil {
		return lease, err
	}
	if err := json.Unmarshal(raw, &lease); err != nil {
		return lease, err
	}
	if lease.Token == "" || lease.OwnerPID <= 0 {
		return lease, fmt.Errorf("PF journal has no reference identity")
	}
	return lease, nil
}

func livePFReferenceHeld(ref livePFReference) bool {
	out, err := exec.Command("/sbin/pfctl", "-s", "References").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[len(fields)-2] == "days" && fields[len(fields)-4] == ref.Token && fields[0] == strconv.Itoa(ref.OwnerPID) {
			return true
		}
	}
	return false
}

func livePFCoowner(t *testing.T, dir string) livePFReference {
	t.Helper()
	cmd := exec.Command("/sbin/pfctl", "-E")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`Token\s*:\s*([0-9]+)`).FindSubmatch(out)
	if len(match) != 2 {
		t.Fatal("other PF owner returned no token")
	}
	ref := livePFReference{Token: string(match[1]), OwnerPID: cmd.Process.Pid}
	t.Cleanup(func() {
		if livePFReferenceHeld(ref) {
			exec.Command("/sbin/pfctl", "-X", ref.Token).Run()
		}
	})
	raw, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other-pf-token"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestMacOSLiveProductionNetworking(t *testing.T) {
	dir := nativeLiveRoot(t)
	beforeDNS := liveCommand(t, "/usr/sbin/scutil", "--dns")
	beforeServices := liveServicePreferences(t)
	beforeRoute := liveCommand(t, "/sbin/route", "-n", "get", "default")
	pfBefore := liveCommand(t, "/sbin/pfctl", "-si")
	for _, anchor := range []string{"com.apple/wireguide", "com.apple/wireguide/dns"} {
		if strings.TrimSpace(liveCommand(t, "/sbin/pfctl", "-a", anchor, "-sr")) != "" {
			t.Fatal("existing WireGuide PF rules: refusing to overwrite active protection")
		}
	}
	a, b := livePeer(t, 241), livePeer(t, 242)
	b.Interface.DNS = append(b.Interface.DNS, "~wg-live.invalid")
	if err := os.MkdirAll(filepath.Join(dir, "config", "tunnels"), 0700); err != nil {
		t.Fatal(err)
	}
	store := storage.NewTunnelStore(filepath.Join(dir, "config", "tunnels"))
	for _, cfg := range []*domain.WireGuardConfig{a, b} {
		if err := store.Save(cfg); err != nil {
			t.Fatal(err)
		}
	}
	saveSettings := func(dns, ks bool) {
		raw, _ := json.Marshal(storage.Settings{DNSProtection: dns, KillSwitch: ks})
		if err := os.WriteFile(filepath.Join(dir, "config", "config.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	saveSettings(false, false)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("com.wireguide.native-live.%d", os.Getpid())
	job := "system/" + label
	if err := os.WriteFile(filepath.Join(dir, "label"), []byte(label), 0600); err != nil {
		t.Fatal(err)
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>%s</string><key>ProgramArguments</key><array><string>%s</string><string>-test.run=^TestMacOSLiveHelperChild$</string><string>-test.v</string></array><key>EnvironmentVariables</key><dict><key>WIREGUIDE_TEST_MACOS_LIVE</key><string>1</string><key>WIREGUIDE_MACOS_LIVE_CHILD</key><string>1</string><key>WIREGUIDE_MACOS_LIVE_DIR</key><string>%s</string><key>TMPDIR</key><string>/tmp</string></dict><key>RunAtLoad</key><false/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/><key>AfterInitialDemand</key><true/></dict><key>ThrottleInterval</key><integer>1</integer><key>Sockets</key><dict><key>Listeners</key><dict><key>SockPathName</key><string>%s/h.sock</string><key>SockType</key><string>stream</string><key>SockPathMode</key><integer>384</integer></dict></dict><key>StandardOutPath</key><string>%s/child.log</string><key>StandardErrorPath</key><string>%s/child.log</string></dict></plist>`, label, exe, dir, dir, dir, dir)
	plistPath := filepath.Join(dir, "job.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0600); err != nil {
		t.Fatal(err)
	}
	liveCommand(t, "/bin/launchctl", "bootstrap", "system", plistPath)
	t.Cleanup(func() { exec.Command("/bin/launchctl", "bootout", job).Run() })
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "child.pid")); !os.IsNotExist(err) {
		t.Fatal("helper ran before socket demand")
	}
	dial := func() *ipc.Client {
		var c *ipc.Client
		liveWait(t, "compatible helper RPC", 20*time.Second, func() bool { var err error; c, err = ipc.NewClient(filepath.Join(dir, "h.sock")); return err == nil })
		return c
	}
	c := dial()
	defer func() { c.Close() }()
	liveCall(t, c, ipc.MethodConnect, ipc.ConnectRequest{Config: b}, nil)
	livePing(t, c, b)
	dns := liveCommand(t, "/usr/sbin/scutil", "--dns")
	if !strings.Contains(dns, "wg-live.invalid") {
		t.Fatal("real supplemental resolver missing")
	}
	liveDNS(t, "198.18.242.1", true)
	systemAnswer := liveCommand(t, "/usr/bin/dscacheutil", "-q", "host", "-a", "name", fmt.Sprintf("native-%d.wg-live.invalid", time.Now().UnixNano()))
	if !strings.Contains(systemAnswer, "198.51.100.42") {
		t.Fatalf("macOS system resolver did not dispatch to supplemental DNS: %s", systemAnswer)
	}
	if result := diag.RunDNSLeakTestForTunnels([][]string{b.Interface.DNS}); result.Leaked || result.Error != "" {
		t.Fatalf("native split DNS diagnostic: %+v", result)
	}
	t.Log("PASS actual macOS system resolver dispatches matching domain to supplemental tunnel resolver")
	t.Log("PASS native utun IPv4/IPv6, encrypted WireGuard UDP, split scutil resolver and DNS reply")
	liveCall(t, c, ipc.MethodConnect, ipc.ConnectRequest{Config: a}, nil)
	livePing(t, c, a)
	liveDNS(t, "198.18.241.3", true)
	saveSettings(true, false)
	liveCall(t, c, ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{Enabled: true}, nil)
	liveDNS(t, "198.18.241.1", true)
	liveDNS(t, "198.18.242.1", true)
	liveDNS(t, "198.18.241.3", false)
	for _, plans := range [][][]string{{a.Interface.DNS}, {a.Interface.DNS, b.Interface.DNS}} {
		if result := diag.RunDNSLeakTestForTunnels(plans); result.Leaked || result.Error != "" {
			t.Fatalf("native global/mixed DNS diagnostic: %+v", result)
		}
	}
	t.Log("PASS real scutil split-only/global/mixed diagnostics agree with resolver ownership")
	t.Log("PASS native DNS protection permits both configured resolvers and blocks unconfigured reachable resolver")
	physicalProbe := func() error {
		conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 2*time.Second)
		if err == nil {
			conn.Close()
		}
		return err
	}
	if err := physicalProbe(); err != nil {
		t.Fatalf("physical TCP baseline unavailable: %v", err)
	}
	saveSettings(true, true)
	liveCall(t, c, ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: true}, nil)
	livePing(t, c, a)
	livePing(t, c, b)
	liveDNS(t, "198.18.241.1", true)
	liveDNS(t, "198.18.242.1", true)
	if err := physicalProbe(); err == nil {
		t.Fatal("kill switch allowed a fresh off-tunnel TCP connection")
	}
	t.Log("PASS kill switch blocks a fresh physical-network TCP connection that succeeds before activation")
	t.Log("PASS multi-tunnel kill-switch permits preserve IPv4/IPv6 and DNS")
	liveDNS(t, "198.18.241.3", false)
	t.Log("PASS unconfigured reachable DNS remains blocked with DNS protection and kill switch both enabled")
	if strings.Contains(pfBefore, "Status: Disabled") && os.Getenv("WIREGUIDE_LIVE_PF_DISABLE") == "1" {
		stopOwnPF := func() livePFReference {
			t.Helper()
			ref, err := livePFLease()
			if err != nil {
				t.Fatal(err)
			}
			refs := liveCommand(t, "/sbin/pfctl", "-s", "References")
			tokens := regexp.MustCompile(`[0-9]{12,}`).FindAllString(refs, -1)
			if len(tokens) != 1 || tokens[0] != ref.Token || !livePFReferenceHeld(ref) {
				t.Fatal("external PF stop refused: sole ownership not proven")
			}
			liveCommand(t, "/sbin/pfctl", "-d")
			return ref
		}
		stopOwnPF()
		liveWait(t, "periodic native PF repair", 15*time.Second, func() bool {
			out, _ := exec.Command("/sbin/pfctl", "-si").Output()
			return strings.Contains(string(out), "Status: Enabled")
		})
		livePing(t, c, a)
		liveDNS(t, "198.18.241.1", true)
		t.Log("PASS actual external PF stop, invalidated reference and production 5-second repair loop")
		liveDNS(t, "198.18.241.3", false)

		oldRef := stopOwnPF()
		otherRef := livePFCoowner(t, dir)
		if ref, err := livePFLease(); err != nil || ref != oldRef {
			t.Fatal("fixture missed the stale-token window before periodic repair")
		}
		t.Logf("PF restart evidence: stale reference=%+v; other owner=%+v", oldRef, otherRef)
		t.Cleanup(func() {
			if t.Failed() {
				ref, err := livePFLease()
				refs, refsErr := exec.Command("/sbin/pfctl", "-s", "References").CombinedOutput()
				t.Logf("PF failure evidence: journal=%+v (%v); references=%s (%v)", ref, err, refs, refsErr)
			}
		})
		// PF is already running for another owner. Only a new, live reference
		// proves that our periodic repair has recovered independent ownership.
		liveWait(t, "own PF reference after another owner restarts PF", 15*time.Second, func() bool {
			ref, err := livePFLease()
			if err != nil || ref == oldRef || ref == otherRef {
				return false
			}
			return livePFReferenceHeld(ref) && livePFReferenceHeld(otherRef)
		})
		liveCommand(t, "/sbin/pfctl", "-X", otherRef.Token)
		if err := os.Remove(filepath.Join(dir, "other-pf-token")); err != nil {
			t.Fatal(err)
		}
		if out := liveCommand(t, "/sbin/pfctl", "-si"); !strings.Contains(out, "Status: Enabled") {
			t.Fatal("PF stopped when the other owner released its reference")
		}
		livePing(t, c, a)
		liveDNS(t, "198.18.241.1", true)
		if err := physicalProbe(); err == nil {
			t.Fatal("recovered PF ownership failed to enforce the kill switch")
		}
		t.Log("PASS external PF stop/start by another owner: periodic repair reacquires a live independent reference and retains enforcement after that owner exits")
	}
	liveCall(t, c, "Live.Reconnect", a.Name, nil)
	livePing(t, c, a)
	livePing(t, c, b)
	t.Log("PASS native cached reconnect preserves sibling and reapplies firewall")
	liveDNS(t, "198.18.241.3", false)
	// Actual SIGKILL + system launchd restart, followed by production journal
	// recovery and async desired restoration. No transport is mocked.
	crash := func() {
		raw, err := os.ReadFile(filepath.Join(dir, "child.pid"))
		if err != nil {
			t.Fatal(err)
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		liveCommand(t, "/bin/kill", "-KILL", strconv.Itoa(pid))
		c.Close()
		liveWait(t, "launchd crash restart", 20*time.Second, func() bool {
			raw, _ := os.ReadFile(filepath.Join(dir, "child.pid"))
			return strings.TrimSpace(string(raw)) != "" && strings.TrimSpace(string(raw)) != strconv.Itoa(pid)
		})
		c = dial()
	}
	crash()
	liveWaitConnected(t, c, a.Name, b.Name)
	livePing(t, c, a)
	livePing(t, c, b)
	liveDNS(t, "198.18.241.1", true)
	t.Log("PASS actual SIGKILL, system launchd respawn, same-boot desired restore and protected packets")
	liveDNS(t, "198.18.241.3", false)
	liveCall(t, c, "Live.ForcedDisconnect", a.Name, nil)
	livePing(t, c, b)
	liveDNS(t, "198.18.242.1", true)
	raw, err := os.ReadFile(filepath.Join(dir, "helper", desiredStateFile))
	if err != nil {
		t.Fatal(err)
	}
	var intent desiredStateJSON
	if json.Unmarshal(raw, &intent) != nil || len(intent.WatchdogBlocked) != 1 {
		t.Fatal("watchdog block not persisted")
	}
	crash()
	liveWaitConnected(t, c, b.Name)
	livePing(t, c, b)
	liveDNS(t, "198.18.242.1", true)
	liveCall(t, c, ipc.MethodConnect, ipc.ConnectRequest{Config: a}, nil)
	livePing(t, c, a)
	t.Log("PASS forced-disconnect cleanup preserves sibling, crash retains block, manual connect clears it")
	otherRef := livePFCoowner(t, dir)
	saveSettings(false, false)
	liveCall(t, c, ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{Enabled: false}, nil)
	liveCall(t, c, ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: false}, nil)
	if err := physicalProbe(); err != nil {
		t.Fatalf("product Off did not restore physical TCP: %v", err)
	}
	liveCall(t, c, ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: a.Name}, nil)
	liveCall(t, c, ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: b.Name}, nil)
	liveWait(t, "DNS restoration", 10*time.Second, func() bool {
		out, _ := exec.Command("/usr/sbin/scutil", "--dns").Output()
		return string(out) == beforeDNS
	})
	afterRoute := liveCommand(t, "/sbin/route", "-n", "get", "default")
	for _, field := range []string{"gateway:", "interface:"} {
		extract := func(s string) string {
			for _, line := range strings.Split(s, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), field) {
					return strings.TrimSpace(line)
				}
			}
			return ""
		}
		if extract(beforeRoute) != extract(afterRoute) {
			t.Fatalf("default %s changed", field)
		}
	}
	for _, anchor := range []string{"com.apple/wireguide", "com.apple/wireguide/dns"} {
		if strings.TrimSpace(liveCommand(t, "/sbin/pfctl", "-a", anchor, "-sr")) != "" {
			t.Fatal("PF rules remain after product Off")
		}
	}
	if out := liveCommand(t, "/sbin/pfctl", "-si"); !strings.Contains(out, "Status: Enabled") {
		t.Fatal("WireGuide Off disabled another owner's PF reference")
	}
	liveCommand(t, "/sbin/pfctl", "-X", otherRef.Token)
	if err := os.Remove(filepath.Join(dir, "other-pf-token")); err != nil {
		t.Fatal(err)
	}
	if got := liveServicePreferences(t); got != beforeServices {
		t.Fatal("product Off changed original per-service DNS/search preferences")
	}
	if got := liveCommand(t, "/sbin/pfctl", "-si"); strings.Contains(got, "Status: Enabled") != strings.Contains(pfBefore, "Status: Enabled") {
		t.Fatal("PF enabled state differs before emergency recovery")
	}
	t.Log("PASS product cleanup restores exact per-service DNS/search preferences and original PF status before emergency fallback")
	t.Log("PASS real PF reference coexistence: product Off preserves another owner, explicit release restores baseline")

	globalB := *b
	globalB.Interface.DNS = []string{"198.18.242.1"}
	if err := store.Save(&globalB); err != nil {
		t.Fatal(err)
	}
	liveCall(t, c, ipc.MethodConnect, ipc.ConnectRequest{Config: a}, nil)
	liveCall(t, c, ipc.MethodConnect, ipc.ConnectRequest{Config: &globalB}, nil)
	livePing(t, c, a)
	livePing(t, c, &globalB)
	crash()
	liveWaitConnected(t, c, a.Name, b.Name)
	livePing(t, c, a)
	livePing(t, c, &globalB)
	liveCall(t, c, ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: a.Name}, nil)
	livePing(t, c, &globalB)
	liveDNS(t, "198.18.242.1", true)
	liveCall(t, c, ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: b.Name}, nil)
	liveWait(t, "original DNS after two global tunnels and crash", 10*time.Second, func() bool {
		out, _ := exec.Command("/usr/sbin/scutil", "--dns").Output()
		return string(out) == beforeDNS
	})
	if got := liveServicePreferences(t); got != beforeServices {
		t.Fatal("two global DNS tunnels or crash restoration replaced the original DNS/search baseline")
	}
	t.Log("PASS two global DNS tunnels survive actual SIGKILL/restore; disconnect preserves the sibling and finally restores original per-service DNS/search preferences")
	liveCall(t, c, ipc.MethodShutdown, nil, nil)
	c.Close()
	liveWait(t, "clean helper exit", 10*time.Second, func() bool {
		out, _ := exec.Command("/bin/launchctl", "print", job).Output()
		return strings.Contains(string(out), "state = not running")
	})
	time.Sleep(2 * time.Second)
	if out := liveCommand(t, "/bin/launchctl", "print", job); !strings.Contains(out, "state = not running") {
		t.Fatal("clean exit restarted without demand")
	}
	t.Log("PASS product Off restores exact scutil snapshot/default gateway and removes PF rules; clean launchd exit stays stopped")
}
