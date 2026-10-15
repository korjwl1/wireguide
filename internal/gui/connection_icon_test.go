package gui

import (
	"bytes"
	"errors"
	"image/color"
	"image/png"
	"math"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestConnectionIndicatorsRequireConnectedTunnels(t *testing.T) {
	for _, state := range []domain.State{domain.StateDisconnected, domain.StateConnecting, domain.StateError} {
		names, _ := connectedStatusIndicators(domain.ConnectionStatus{State: state, TunnelName: "pending", ActiveTunnels: []string{"pending"}})
		if len(names) != 0 {
			t.Fatalf("%s work displayed as connected", state)
		}
	}
	names, handshakes := connectedStatusIndicators(domain.ConnectionStatus{State: domain.StateConnected, TunnelName: "solo"})
	if !reflect.DeepEqual(names, []string{"solo"}) || handshakes["solo"] {
		t.Fatal("single connected tunnel without a handshake was lost")
	}
	status := domain.ConnectionStatus{Tunnels: []domain.ConnectionStatus{
		{State: domain.StateConnected, TunnelName: "a", LastHandshake: "1s"},
		{State: domain.StateConnecting, TunnelName: "b"},
		{State: domain.StateConnected, TunnelName: "c"},
	}}
	names, handshakes = connectedStatusIndicators(status)
	if !reflect.DeepEqual(names, []string{"a", "c"}) || !handshakes["a"] || handshakes["c"] {
		t.Fatalf("mixed states: %v, %v", names, handshakes)
	}
	status.Tunnels[0].State = domain.StateDisconnected
	names, _ = connectedStatusIndicators(status)
	if !reflect.DeepEqual(names, []string{"c"}) {
		t.Fatal("disconnect removed the surviving sibling's indication")
	}
}

func TestConnectionIconBuffersAndCoalescesLatestState(t *testing.T) {
	var queued []func()
	var applied []bool
	i := newConnectionIcon(func(f func()) { queued = append(queued, f) }, func(active bool) error {
		applied = append(applied, active)
		return nil
	})
	i.SetConnected(true)
	if len(queued) != 0 {
		t.Fatal("native icon touched before runtime readiness")
	}
	i.Ready()
	i.SetConnected(false)
	i.SetConnected(true)
	if len(queued) != 1 {
		t.Fatal("status bursts created multiple GUI callbacks")
	}
	queued[0]()
	queued = nil
	for range 100 {
		i.SetConnected(true)
	}
	if len(queued) != 0 || !reflect.DeepEqual(applied, []bool{true}) {
		t.Fatal("steady-state status reloaded the icon")
	}
	i.SetConnected(false)
	queued[0]()
	if !reflect.DeepEqual(applied, []bool{true, false}) {
		t.Fatal("last disconnect did not clear the indication")
	}
}

func TestConnectionIconRefreshesAfterShellRecreation(t *testing.T) {
	var queued []func()
	calls := 0
	i := newConnectionIcon(func(f func()) { queued = append(queued, f) }, func(bool) error {
		calls++
		return errors.New("shell unavailable")
	})
	i.SetConnected(true)
	i.Ready()
	queued[0]()
	queued = nil
	for range 10 {
		i.SetConnected(true)
	}
	if len(queued) != 0 || calls != 1 {
		t.Fatal("failed shell update retried on every status tick")
	}
	i.Refresh()
	queued[0]()
	if calls != 2 {
		t.Fatal("shell/window recreation did not reapply the current state")
	}
}

func TestConnectionIconShutdownDropsPendingUpdate(t *testing.T) {
	var queued []func()
	var applied []bool
	i := newConnectionIcon(func(f func()) { queued = append(queued, f) }, func(connected bool) error {
		applied = append(applied, connected)
		return nil
	})
	i.Ready()
	i.SetConnected(true)
	i.Close()
	i.Close()
	i.Refresh()
	for _, callback := range queued {
		callback()
	}
	if !reflect.DeepEqual(applied, []bool{false}) {
		t.Fatalf("shutdown must only reset the icon once: %v", applied)
	}
}

func TestConnectionIconDoesNotLoseStateDuringNativeApply(t *testing.T) {
	queued := make(chan func(), 4)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var applied []bool
	i := newConnectionIcon(func(f func()) { queued <- f }, func(active bool) error {
		applied = append(applied, active)
		if len(applied) == 1 {
			close(entered)
			<-release
		}
		return nil
	})
	i.SetConnected(true)
	i.Ready()
	go func() { (<-queued)(); close(finished) }()
	<-entered
	var wg sync.WaitGroup
	for range 30 {
		wg.Add(1)
		go func() { defer wg.Done(); i.SetConnected(false) }()
	}
	wg.Wait()
	i.Refresh()
	close(release)
	<-finished
	(<-queued)()
	if !reflect.DeepEqual(applied, []bool{true, false}) {
		t.Fatalf("latest disconnected state lost: %v", applied)
	}
}

func TestHelperOutageClearsIndicatorsWithoutHistoryMutation(t *testing.T) {
	cleared := false
	b := &eventBridge{
		onStatusChange: func(names []string, handshakes map[string]bool) {
			cleared = len(names) == 0 && len(handshakes) == 0
		},
		onReconcileHistory: func([]string, map[string]int64, map[string]int64, string) {
			t.Fatal("outage invented a history disconnect")
		},
	}
	b.clearConnectionIndicators()
	if !cleared {
		t.Fatal("outage retained a connected indicator")
	}
}

func TestConnectionIconRenderingPreservesBaseOutsideBadge(t *testing.T) {
	source, err := os.ReadFile("../../build/appicon.png")
	if err != nil {
		t.Fatal(err)
	}
	icons, err := buildConnectionIconImages(source)
	if err != nil {
		t.Fatal(err)
	}
	base, err := png.Decode(bytes.NewReader(icons.base))
	if err != nil {
		t.Fatal(err)
	}
	connected, err := png.Decode(bytes.NewReader(icons.connected))
	if err != nil {
		t.Fatal(err)
	}
	for y := range 256 {
		for x := range 256 {
			if math.Hypot(float64(x)+0.5-211, float64(y)+0.5-211) > 35 && base.At(x, y) != connected.At(x, y) {
				t.Fatalf("base icon changed outside badge at %d,%d", x, y)
			}
		}
	}
	wantGreen := color.NRGBA{R: 52, G: 199, B: 89, A: 255}
	if color.NRGBAModel.Convert(connected.At(211, 211)) != wantGreen {
		t.Fatal("connection dot is not the tray's green")
	}
	overlay, err := png.Decode(bytes.NewReader(icons.overlay))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, alpha := overlay.At(0, 0).RGBA(); alpha != 0 {
		t.Fatal("taskbar overlay background is not transparent")
	}
	if dir := os.Getenv("WIREGUIDE_TEST_ICON_EVIDENCE"); dir != "" {
		if err := os.WriteFile(dir+"/application-connected.png", icons.connected, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
