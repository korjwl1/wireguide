package app

import (
	"sort"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// AnyTunnel is the wildcard tunnel name for a user "disconnect whatever is
// active" action.
const AnyTunnel = "*"

const (
	// userActionInFlight bounds how long a connect/disconnect call may be
	// outstanding (callLong's timeout is 60 s) before we stop attributing
	// status changes to it.
	userActionInFlight = 90 * time.Second
	// userActionLinger is how long after the call returns status changes
	// are still attributed to the user (the 1 Hz status stream lags).
	userActionLinger = 10 * time.Second
)

// UserActions is the GUI process's own record of connects and disconnects
// the user made from the window or tray. Both go through TunnelService, so
// recording there covers them; CLI and helper-driven (automation, wake,
// health-check) changes never pass through and so count as automatic.
type UserActions struct {
	mu    sync.Mutex
	until map[string]time.Time
	now   func() time.Time
}

// NewUserActions returns an empty record.
func NewUserActions() *UserActions {
	return &UserActions{until: map[string]time.Time{}, now: time.Now}
}

func actionKey(name string, up bool) string {
	if up {
		return "up|" + name
	}
	return "down|" + name
}

// Begin marks a user connect (up) or disconnect (down) of name as started.
// A nil receiver is a no-op so zero-value services (tests) stay safe.
func (u *UserActions) Begin(name string, up bool) {
	if u == nil || name == "" {
		return
	}
	u.mu.Lock()
	u.until[actionKey(name, up)] = u.now().Add(userActionInFlight)
	u.mu.Unlock()
}

// End shortens the attribution window once the call has returned.
func (u *UserActions) End(name string, up bool) {
	if u == nil || name == "" {
		return
	}
	u.mu.Lock()
	u.until[actionKey(name, up)] = u.now().Add(userActionLinger)
	u.mu.Unlock()
}

// Recent reports whether a user action of that direction covers name at
// now. A down action on AnyTunnel covers every tunnel.
func (u *UserActions) Recent(name string, up bool, now time.Time) bool {
	if u == nil {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	check := func(k string) bool {
		t, ok := u.until[k]
		if ok && !now.Before(t) {
			delete(u.until, k)
			return false
		}
		return ok
	}
	if check(actionKey(name, up)) {
		return true
	}
	return !up && check(actionKey(AnyTunnel, false))
}

// NotifyKind classifies something the GUI might notify about.
type NotifyKind int

const (
	// NotifyTunnelUp: a tunnel appeared in the active set.
	NotifyTunnelUp NotifyKind = iota
	// NotifyTunnelDown: a tunnel left the active set.
	NotifyTunnelDown
	// NotifyAutoConnected: the helper's auto_connected event (automation).
	NotifyAutoConnected
	// NotifyCriticalError: the helper reported a dead background goroutine.
	NotifyCriticalError
	// NotifyForcedDisconnect: the helper tore a tunnel down on its own
	// (routing-loop watchdog).
	NotifyForcedDisconnect
)

// NotifyEvent is one candidate notification.
type NotifyEvent struct {
	Kind   NotifyKind
	Tunnel string
}

// ShouldNotify is the pure notification decision. enabled is the Settings
// toggle. Up/down changes the user just made here never notify; the helper
// events are automatic by construction.
func ShouldNotify(enabled bool, ev NotifyEvent, actions *UserActions, now time.Time) bool {
	if !enabled {
		return false
	}
	switch ev.Kind {
	case NotifyTunnelUp:
		return !actions.Recent(ev.Tunnel, true, now)
	case NotifyTunnelDown:
		// A recent user connect also covers a "down": a failed user
		// connect drops the tunnel again and must not read as automatic.
		return !actions.Recent(ev.Tunnel, false, now) && !actions.Recent(ev.Tunnel, true, now)
	case NotifyAutoConnected, NotifyCriticalError, NotifyForcedDisconnect:
		return true
	}
	return false
}

// StatusDiffer turns the 1 Hz stream of active-tunnel sets into up/down
// events. The first observation after creation or Reset only seeds the
// baseline, so tunnels already up at launch (or after a helper restart)
// never notify.
type StatusDiffer struct {
	mu   sync.Mutex
	prev map[string]bool
	seen bool
}

// Reset forgets the baseline (helper restart: state is unknown again).
func (d *StatusDiffer) Reset() {
	d.mu.Lock()
	d.prev, d.seen = nil, false
	d.mu.Unlock()
}

// Observe records the current active set and returns the changes against
// the previous one, sorted by name with downs first for stable output.
func (d *StatusDiffer) Observe(active []string) []NotifyEvent {
	cur := make(map[string]bool, len(active))
	for _, n := range active {
		cur[n] = true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	prev, seen := d.prev, d.seen
	d.prev, d.seen = cur, true
	if !seen {
		return nil
	}
	var downs, ups []string
	for n := range prev {
		if !cur[n] {
			downs = append(downs, n)
		}
	}
	for n := range cur {
		if !prev[n] {
			ups = append(ups, n)
		}
	}
	sort.Strings(downs)
	sort.Strings(ups)
	var out []NotifyEvent
	for _, n := range downs {
		out = append(out, NotifyEvent{Kind: NotifyTunnelDown, Tunnel: n})
	}
	for _, n := range ups {
		out = append(out, NotifyEvent{Kind: NotifyTunnelUp, Tunnel: n})
	}
	return out
}

// ConnectedTunnels returns the names of tunnels whose own state is
// connected. Unlike ActiveTunnels it excludes connecting and disconnecting
// tunnels, so a connect attempt that fails (health-check retries, an
// unresolvable endpoint) never appears as an up or down change.
func ConnectedTunnels(st domain.ConnectionStatus) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, t := range st.Tunnels {
		if t.State == domain.StateConnected {
			add(t.TunnelName)
		}
	}
	if st.State == domain.StateConnected {
		add(st.TunnelName)
	}
	if len(st.Tunnels) == 0 && st.TunnelName == "" {
		for _, n := range st.ActiveTunnels {
			add(n)
		}
	}
	return out
}
