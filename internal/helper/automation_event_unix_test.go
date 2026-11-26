//go:build !windows

package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestAutomationEventRefreshesSameSSIDNetworkCountdown(t *testing.T) {
	probe := wifiProbe()
	stubNetwork(t, probe)
	h, clock := newAutomationHelper(t, "CafeWiFi")
	h.done = make(chan struct{})
	writeAutomation(t, h, map[string][]automation.Rule{
		"vpn": {{When: automation.Condition{Type: automation.CondSSID, SSID: "CafeWiFi", Negate: true}, Do: automation.ActionConnect}},
	})
	dir, err := os.MkdirTemp("/tmp", "wge-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "s")
	listener, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	h.server = ipc.NewServer(listener)
	h.server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil
	})
	go h.server.Serve()
	t.Cleanup(func() { h.server.Shutdown() })
	client, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	changed := make(chan struct{}, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.SubscribeContext(ctx, func(method string, _ json.RawMessage) {
		if method == ipc.EventAutomationChanged {
			changed <- struct{}{}
		}
	}); err != nil {
		t.Fatal(err)
	}
	wait := func() {
		t.Helper()
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("automation change event was not delivered")
		}
	}
	h.currentNetworkState()
	clock.Advance(automation.NegationSettleWindow + time.Second)
	h.reevaluateAutomation("settled")
	wait()
	probe.GatewayMAC = "aa:bb:cc:dd:ee:ff"
	probe.Subnets = []string{"10.42.0.0/24"}
	h.reevaluateAutomation("network-change")
	wait()
	v, err := h.handleAutomationPreview(nil)
	if err != nil {
		t.Fatal(err)
	}
	preview := v.(ipc.AutomationPreviewResponse)
	if preview.SSID != "CafeWiFi" || preview.Settled || preview.SettleRemainingSec != 15 {
		t.Fatalf("same-SSID network change must immediately expose the countdown: %+v", preview)
	}
	clock.Advance(automation.NegationSettleWindow + time.Second)
	h.reevaluateAutomation("settled")
	wait()
	v, err = h.handleAutomationPreview(nil)
	if err != nil || !v.(ipc.AutomationPreviewResponse).Settled {
		t.Fatalf("settlement must refresh the preview: %+v %v", v, err)
	}
}
