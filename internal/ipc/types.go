package ipc

import "github.com/korjwl1/wireguide/internal/domain"

// Empty is used for requests/responses with no payload.
type Empty struct{}

// PingResponse is returned from Helper.Ping.
type PingResponse struct {
	Version string `json:"version"`
	PID     int    `json:"pid"`
}

// ConnectRequest is the parameter for Tunnel.Connect.
type ConnectRequest struct {
	Config         *domain.WireGuardConfig `json:"config"`
	ScriptsAllowed bool                    `json:"scripts_allowed"`
}

// ApproveScriptsRequest is sent by the GUI after the user explicitly approves
// the scripts in a tunnel config. The helper adds the script fingerprint to
// its persistent allowlist so subsequent connects auto-approve.
type ApproveScriptsRequest struct {
	Config *domain.WireGuardConfig `json:"config"`
}

// ScriptsNotApprovedDetail is included in the ErrCodeScriptsNotApproved error
// response so the GUI knows which scripts need user approval.
type ScriptsNotApprovedDetail struct {
	TunnelName  string          `json:"tunnel_name"`
	Scripts     []domain.Script `json:"scripts"`
	Fingerprint string          `json:"fingerprint"`
}

// ConnectionStatus is the wire representation of the tunnel connection state.
// It is a direct alias of the domain type — there used to be a separate
// `ConnectionStatusDTO` here that drifted from the tunnel package's Status
// struct and caused a `handshake_age` vs `last_handshake` field-name bug in
// the frontend. Unifying on the domain type prevents that class of bug.
type ConnectionStatus = domain.ConnectionStatus

// KillSwitchRequest is the parameter for Firewall.SetKillSwitch.
type KillSwitchRequest struct {
	Enabled bool `json:"enabled"`
}

// DNSProtectionRequest is the parameter for Firewall.SetDNSProtection.
type DNSProtectionRequest struct {
	Enabled    bool     `json:"enabled"`
	DNSServers []string `json:"dns_servers,omitempty"`
}

// ReconnectStateDTO describes ongoing reconnection.
type ReconnectStateDTO struct {
	Reconnecting bool   `json:"reconnecting"`
	Attempt      int    `json:"attempt"`
	MaxAttempts  int    `json:"max_attempts"`
	NextRetry    string `json:"next_retry,omitempty"`
}

// LogEntry is a single structured log record forwarded from the helper
// to the GUI (and from the GUI to the frontend LogViewer). We keep it flat
// — no nested attrs — because the viewer just renders a one-line per entry.
type LogEntry struct {
	Time    string `json:"time"`    // RFC3339
	Level   string `json:"level"`   // "debug" | "info" | "warn" | "error"
	Source  string `json:"source"`  // "helper" | "gui"
	Message string `json:"message"` // human-readable text (already includes attrs)
}

// SetLogLevelRequest is the parameter for Helper.SetLogLevel.
type SetLogLevelRequest struct {
	Level string `json:"level"` // "debug" | "info" | "warn" | "error"
}

// BoolResponse wraps a single bool.
type BoolResponse struct {
	Value bool `json:"value"`
}

// StringResponse wraps a single string.
type StringResponse struct {
	Value string `json:"value"`
}
