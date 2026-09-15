package healthcheck

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestNormalize(t *testing.T) {
	for _, tt := range []struct {
		target string
		valid  bool
	}{
		{"10.0.0.1", true}, {"fd00::1", true}, {"::ffff:10.0.0.1", true},
		{"example.com", false}, {"10.0.0.1:80", false}, {"-I en0", false},
		{"127.0.0.1", false}, {"0.0.0.0", false}, {"224.0.0.1", false}, {"fe80::1%en0", false},
	} {
		c, err := (Config{Enabled: true, Targets: []string{tt.target}}).Normalize()
		if (err == nil) != tt.valid {
			t.Errorf("%s: %v", tt.target, err)
		}
		if err == nil && (c.IntervalSeconds != 30 || c.FailureThreshold != 3) {
			t.Fatal("defaults lost")
		}
	}
	c, err := (Config{Enabled: true, Targets: []string{"10.0.0.1", "::ffff:10.0.0.1"}}).Normalize()
	if err != nil || len(c.Targets) != 1 {
		t.Fatalf("deduplication: %+v %v", c, err)
	}
	for _, c := range []Config{{Enabled: true}, {IntervalSeconds: 1}, {FailureThreshold: 11}, {Targets: make([]string, 6)}} {
		if _, err := c.Normalize(); err == nil {
			t.Errorf("accepted invalid config: %+v", c)
		}
	}
	if !Covered("10.0.0.1", []string{"10.0.0.0/24"}) || Covered("10.1.0.1", []string{"10.0.0.0/24"}) || !Covered("fd00::1", []string{"::/0"}) {
		t.Fatal("AllowedIPs check failed")
	}
}

func TestPolicyFailuresRecoveryAndCooldown(t *testing.T) {
	var state State
	now := time.Unix(1000, 0)
	session := now
	config := Config{Enabled: true, Targets: []string{"10.0.0.1"}, IntervalSeconds: 10, FailureThreshold: 3}
	if state.Due(now, session, config) {
		t.Fatal("no startup grace")
	}
	for i, reachable := range []bool{false, false, true, false, false, false} {
		now = now.Add(10 * time.Second)
		if !state.Due(now, session, config) {
			t.Fatal("missed interval")
		}
		if got := state.Observe(now, reachable); got != (i == 5) {
			t.Fatalf("round %d reconnect=%t", i, got)
		}
	}
	// A new session resets consecutive failures but preserves the cooldown.
	if state.Due(now, now, config) {
		t.Fatal("new session must warm up")
	}
	if state.Due(now.Add(50*time.Second), now, config) {
		t.Fatal("cooldown lost on reconnect")
	}
	if !state.Due(now.Add(60*time.Second), now, config) {
		t.Fatal("cooldown did not expire")
	}
	config.Enabled = false
	if state.Due(now.Add(time.Hour), now, config) {
		t.Fatal("disabled health check ran")
	}
}

func TestConfigChangeResetsFailures(t *testing.T) {
	var state State
	now := time.Unix(1000, 0)
	session := now
	config := Config{Enabled: true, Targets: []string{"10.0.0.1"}, IntervalSeconds: 10, FailureThreshold: 2}
	state.Due(now, session, config)
	state.Observe(now.Add(10*time.Second), false)
	config.Targets = []string{"10.0.0.2"}
	state.Due(now.Add(20*time.Second), session, config)
	if state.Observe(now.Add(30*time.Second), false) {
		t.Fatal("old target failures carried over")
	}
}

func TestAnyReplyWinsAndCancelsOthers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := Check(ctx, "test-tunnel", []string{"10.0.0.1", "10.0.0.2"}, func(ctx context.Context, iface, target string) error {
		if iface != "test-tunnel" {
			t.Error("interface lost")
		}
		if target == "10.0.0.1" {
			return nil
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if !result || err != nil {
		t.Fatalf("result=%t err=%v", result, err)
	}
	result, err = Check(ctx, "test", []string{"10.0.0.1"}, func(context.Context, string, string) error { return errors.New("no reply") })
	if result || err != nil {
		t.Fatalf("failure round: %t %v", result, err)
	}
	cancel()
	_, err = Check(ctx, "test", []string{"10.0.0.1"}, func(ctx context.Context, _, _ string) error { return ctx.Err() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation became a failed round: %v", err)
	}
}

func TestRepliesMustMatchRequest(t *testing.T) {
	nonce := []byte("unique-request-payload")
	for _, protocol := range []int{1, 58} {
		var replyType icmp.Type = ipv4.ICMPTypeEchoReply
		if protocol == 58 {
			replyType = ipv6.ICMPTypeEchoReply
		}
		m := icmp.Message{Type: replyType, Body: &icmp.Echo{ID: 7, Seq: 9, Data: nonce}}
		b, _ := m.Marshal(nil)
		if !validReply(protocol, b, 7, 9, nonce) {
			t.Fatal("valid reply rejected")
		}
		if validReply(protocol, b, 8, 9, nonce) || validReply(protocol, b, 7, 8, nonce) || validReply(protocol, b, 7, 9, []byte("other")) {
			t.Fatal("unrelated reply accepted")
		}
		b[0] = 3
		if validReply(protocol, b, 7, 9, nonce) {
			t.Fatal("ICMP error accepted as a reply")
		}
	}
}

// This tests the real OS socket path without changing routes or creating a VPN.
func TestNativeBoundICMP(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_ICMP") != "1" {
		t.Skip("requires raw ICMP privileges")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loopback string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			loopback = iface.Name
			break
		}
	}
	if loopback == "" {
		t.Fatal("no loopback interface")
	}
	for _, target := range []string{"127.0.0.1", "::1"} {
		if err := Probe(context.Background(), loopback, target); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
	if err := Probe(context.Background(), "wg-nonexistent", "127.0.0.1"); err == nil {
		t.Fatal("missing interface fell back to default")
	}
}
