// Package ipc provides JSON-RPC 2.0 IPC between GUI and helper processes.
package ipc

import "encoding/json"

// Protocol version uses simple major.minor semver:
//   - MAJOR bumps when fields are RENAMED or REMOVED, or a method's
//     semantics change incompatibly. Helper and GUI with different
//     MAJOR versions refuse to talk.
//   - MINOR bumps when fields are ADDED to existing requests/responses
//     or NEW methods are introduced. Older clients ignore the extra
//     fields; newer clients tolerate older servers via optional
//     handling.
//
// The on-the-wire format is "major.minor" so this stays trivial to
// compare in protocol_test.go.
const (
	ProtocolMajor = 1
	ProtocolMinor = 0
)

// ProtocolVersion is the canonical "major.minor" string used in
// PingResponse.Version. Mismatched majors abort the handshake.
var ProtocolVersion = "1.0"

// MajorVersionMatches reports whether two "major.minor" version strings
// share the same MAJOR. A missing dot is treated as MAJOR-only
// (backward-compatible with the legacy "1" wire format from old helpers).
func MajorVersionMatches(a, b string) bool {
	return majorOf(a) == majorOf(b)
}

func majorOf(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			return v[:i]
		}
	}
	return v
}

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id,omitempty"` // 0 for notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC 2.0 error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// Error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
	ErrCodeAppError = -32000
)

// RPC method names
const (
	MethodPing             = "Helper.Ping"
	MethodShutdown         = "Helper.Shutdown"
	// MethodForceShutdown is the escalation when MethodShutdown is ignored
	// or replied to with an error. The helper handler immediately
	// terminates the process (os.Exit) without running the graceful
	// teardown — used by the GUI's upgrade path when a wedged helper
	// must be cleared. The GUI cannot kill the helper from outside
	// because the helper runs as root/SYSTEM and the GUI is a normal
	// user, so cross-privilege kill is the helper's job.
	MethodForceShutdown    = "Helper.ForceShutdown"
	MethodSubscribe        = "Helper.Subscribe"
	MethodSetLogLevel      = "Helper.SetLogLevel"
	MethodConnect          = "Tunnel.Connect"
	MethodDisconnect       = "Tunnel.Disconnect"
	MethodStatus           = "Tunnel.Status"
	MethodIsConnected      = "Tunnel.IsConnected"
	MethodActiveName       = "Tunnel.ActiveName"
	MethodActiveTunnels    = "Tunnel.ActiveTunnels"
	// MethodRename runs inside the helper because it has to take connectMu
	// to make "is the tunnel active?" + file rename atomic with respect to
	// Connect / Disconnect / wifi-rule auto-connect. Splitting it into
	// GUI-side file ops + helper-side lock/unlock IPC creates a TOCTOU
	// window the helper-only design avoids. The architectural cost
	// (helper imports storage) is accepted; the helper's storage usage is
	// confined to this single method + read-only Load for wifi rules.
	MethodRename = "Tunnel.Rename"
	MethodSetKillSwitch    = "Firewall.SetKillSwitch"
	MethodSetDNSProtection = "Firewall.SetDNSProtection"
	MethodSetHealthCheck   = "Monitor.SetHealthCheck"
	MethodSetPinInterface  = "Network.SetPinInterface"
	MethodReportSSID       = "Wifi.ReportSSID"
)

// Event names (server → client notifications)
const (
	EventStatus      = "event.status"
	EventReconnect   = "event.reconnect"
	EventLog         = "event.log"
	EventWifiSSID    = "event.wifi_ssid"
	EventAutoConnect = "event.auto_connect"
	// EventCriticalError signals that a background goroutine inside the
	// helper has died permanently (e.g. exceeded goSafe restart budget).
	// The GUI is expected to surface this via a banner/toast so the user
	// knows tunnels may no longer reflect real state.
	EventCriticalError = "event.critical_error"
)

// CodedError is an error that carries a specific JSON-RPC error code.
// Handlers can return this to override the default ErrCodeAppError.
type CodedError struct {
	Code    int
	Message string
}

func (e *CodedError) Error() string { return e.Message }

// NewRequest creates a request with auto-serialized params.
func NewRequest(id uint64, method string, params interface{}) (*Request, error) {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return &Request{JSONRPC: "2.0", ID: id, Method: method, Params: raw}, nil
}

// NewNotification creates a notification (no ID, no response expected).
func NewNotification(method string, params interface{}) (*Request, error) {
	req, err := NewRequest(0, method, params)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// NewResponse creates a successful response.
func NewResponse(id uint64, result interface{}) (*Response, error) {
	var raw json.RawMessage
	if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return &Response{JSONRPC: "2.0", ID: id, Result: raw}, nil
}

// NewErrorResponse creates an error response.
func NewErrorResponse(id uint64, code int, message string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &Error{Code: code, Message: message},
	}
}

// IsNotification returns true if this is a notification (no ID).
func (r *Request) IsNotification() bool {
	return r.ID == 0
}
