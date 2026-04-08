package domain

import (
	"fmt"
	"time"
)

// State represents the tunnel connection state.
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateError        State = "error"
)

// ConnectionStatus is the single source of truth for tunnel connection state
// across the whole application. It carries both wire-safe fields (strings,
// JSON-tagged) that are sent to the frontend, and internal fields (time.Time,
// `json:"-"`) that the reconnect monitor and other backend services use for
// duration math.
//
// Note that `LastHandshake` is the *formatted age string* (e.g. "5s", "2m 10s")
// that the frontend displays, while `LastHandshakeTime` is the absolute
// timestamp used internally. Wire callers see only the former.
type ConnectionStatus struct {
	State             State     `json:"state"`
	TunnelName        string    `json:"tunnel_name"`
	InterfaceName     string    `json:"interface_name,omitempty"`
	ConnectedAt       time.Time `json:"-"`
	Duration          string    `json:"duration,omitempty"`
	RxBytes           int64     `json:"rx_bytes"`
	TxBytes           int64     `json:"tx_bytes"`
	LastHandshakeTime time.Time `json:"-"`
	LastHandshake     string    `json:"last_handshake,omitempty"`
	Endpoint          string    `json:"endpoint,omitempty"`
	ErrorMessage      string    `json:"error_message,omitempty"`

	// ActiveTunnels lists the names of all currently connected (or connecting)
	// tunnels. Populated by the multi-tunnel manager so the frontend can show
	// which tunnels are active.
	ActiveTunnels []string `json:"active_tunnels,omitempty"`

	// Tunnels carries per-tunnel status for multi-tunnel setups. The frontend
	// uses this to show stats for the selected tunnel rather than the "primary".
	Tunnels []ConnectionStatus `json:"tunnels,omitempty"`
}

// FormatDuration renders a duration in a compact "1h 2m 3s" form used by the
// UI. Negative durations (possible if the system clock jumps backward relative
// to a stored timestamp) are clamped to "0s" rather than producing a
// confusing "-5s" in the UI.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
