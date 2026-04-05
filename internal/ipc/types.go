package ipc

import "github.com/korjwl1/wireguide/internal/config"

// Empty is used for requests/responses with no payload.
type Empty struct{}

// PingResponse is returned from Helper.Ping.
type PingResponse struct {
	Version string `json:"version"`
	PID     int    `json:"pid"`
}

// ConnectRequest is the parameter for Tunnel.Connect.
type ConnectRequest struct {
	Config         *config.WireGuardConfig `json:"config"`
	ScriptsAllowed bool                    `json:"scripts_allowed"`
}

// ConnectionStatusDTO is the wire representation of tunnel.ConnectionStatus.
// We duplicate the struct here to avoid coupling the wire protocol to the
// internal tunnel package's time.Time fields (which serialize verbosely).
type ConnectionStatusDTO struct {
	State         string `json:"state"`
	TunnelName    string `json:"tunnel_name"`
	InterfaceName string `json:"interface_name"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	LastHandshake string `json:"last_handshake"` // human-readable age
	Duration      string `json:"duration"`
	Endpoint      string `json:"endpoint"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

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

// BoolResponse wraps a single bool.
type BoolResponse struct {
	Value bool `json:"value"`
}

// StringResponse wraps a single string.
type StringResponse struct {
	Value string `json:"value"`
}
