package app

import (
	"reflect"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

func fixedActions(t0 time.Time) *UserActions {
	u := NewUserActions()
	u.now = func() time.Time { return t0 }
	return u
}

func TestShouldNotify(t *testing.T) {
	t0 := time.Unix(1000, 0)
	u := fixedActions(t0)
	u.Begin("a", true)
	u.Begin(AnyTunnel, false)

	cases := []struct {
		name    string
		enabled bool
		ev      NotifyEvent
		want    bool
	}{
		{"user connect suppressed", true, NotifyEvent{NotifyTunnelUp, "a"}, false},
		{"other tunnel up notifies", true, NotifyEvent{NotifyTunnelUp, "b"}, true},
		{"user disconnect-all suppressed", true, NotifyEvent{NotifyTunnelDown, "a"}, false},
		{"wildcard disconnect covers any tunnel", true, NotifyEvent{NotifyTunnelDown, "zzz"}, false},
		{"auto_connected always", true, NotifyEvent{NotifyAutoConnected, "a"}, true},
		{"critical", true, NotifyEvent{NotifyCriticalError, ""}, true},
		{"forced disconnect", true, NotifyEvent{NotifyForcedDisconnect, "a"}, true},
		{"toggle off", false, NotifyEvent{NotifyCriticalError, ""}, false},
		{"toggle off auto", false, NotifyEvent{NotifyTunnelUp, "b"}, false},
	}
	for _, c := range cases {
		if got := ShouldNotify(c.enabled, c.ev, u, t0.Add(time.Second)); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestUserActionWindowExpires(t *testing.T) {
	t0 := time.Unix(1000, 0)
	u := fixedActions(t0)
	u.Begin("a", false)
	if !u.Recent("a", false, t0.Add(time.Minute)) {
		t.Fatal("in-flight action should still cover a status 1 min later")
	}
	u.End("a", false)
	if !u.Recent("a", false, t0.Add(5*time.Second)) {
		t.Fatal("linger window should cover a lagging status event")
	}
	if u.Recent("a", false, t0.Add(userActionLinger+time.Second)) {
		t.Fatal("window must expire so a later automatic disconnect notifies")
	}
	var nilActions *UserActions
	if nilActions.Recent("a", true, t0) {
		t.Fatal("nil record means nothing is user-initiated")
	}
}

func TestStatusDiffer(t *testing.T) {
	var d StatusDiffer
	if ev := d.Observe([]string{"a"}); ev != nil {
		t.Fatalf("first observation must only seed the baseline, got %v", ev)
	}
	if ev := d.Observe([]string{"a"}); len(ev) != 0 {
		t.Fatalf("steady state: %v", ev)
	}
	got := d.Observe([]string{"b", "c"})
	want := []NotifyEvent{
		{NotifyTunnelDown, "a"},
		{NotifyTunnelUp, "b"},
		{NotifyTunnelUp, "c"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	d.Reset()
	if ev := d.Observe(nil); ev != nil {
		t.Fatalf("after reset: %v", ev)
	}
}

func TestShouldNotifyFailedUserConnect(t *testing.T) {
	t0 := time.Unix(1000, 0)
	u := fixedActions(t0)
	u.Begin("a", true)
	u.End("a", true)
	if ShouldNotify(true, NotifyEvent{NotifyTunnelDown, "a"}, u, t0.Add(2*time.Second)) {
		t.Fatal("down right after a user connect (failed attempt) must not notify")
	}
	if !ShouldNotify(true, NotifyEvent{NotifyTunnelDown, "a"}, u, t0.Add(time.Minute)) {
		t.Fatal("window expired: a later down is automatic")
	}
}

func TestConnectedTunnels(t *testing.T) {
	st := domain.ConnectionStatus{
		ActiveTunnels: []string{"a", "b", "c"},
		Tunnels: []domain.ConnectionStatus{
			{TunnelName: "a", State: domain.StateConnected},
			{TunnelName: "b", State: domain.StateConnecting},
			{TunnelName: "c", State: domain.StateConnected},
		},
	}
	if got := ConnectedTunnels(st); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("got %v", got)
	}
	single := domain.ConnectionStatus{State: domain.StateConnected, TunnelName: "x", ActiveTunnels: []string{"x"}}
	if got := ConnectedTunnels(single); !reflect.DeepEqual(got, []string{"x"}) {
		t.Fatalf("single: %v", got)
	}
	connecting := domain.ConnectionStatus{State: domain.StateConnecting, TunnelName: "x", ActiveTunnels: []string{"x"}}
	if got := ConnectedTunnels(connecting); len(got) != 0 {
		t.Fatalf("connecting must not count: %v", got)
	}
}
