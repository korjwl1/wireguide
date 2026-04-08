// Package ipc provides JSON-RPC 2.0 IPC between GUI and helper processes.
package ipc

import "encoding/json"

// Protocol version — both sides must match.
const ProtocolVersion = "1"

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
	MethodSubscribe        = "Helper.Subscribe"
	MethodSetLogLevel      = "Helper.SetLogLevel"
	MethodConnect          = "Tunnel.Connect"
	MethodDisconnect       = "Tunnel.Disconnect"
	MethodStatus           = "Tunnel.Status"
	MethodIsConnected      = "Tunnel.IsConnected"
	MethodActiveName    = "Tunnel.ActiveName"
	MethodSetKillSwitch    = "Firewall.SetKillSwitch"
	MethodSetDNSProtection = "Firewall.SetDNSProtection"
	MethodSetHealthCheck   = "Monitor.SetHealthCheck"
	MethodSetPinInterface  = "Network.SetPinInterface"
)

// Event names (server → client notifications)
const (
	EventStatus    = "event.status"
	EventReconnect = "event.reconnect"
	EventLog       = "event.log"
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
