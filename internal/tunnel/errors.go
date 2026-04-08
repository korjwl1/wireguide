package tunnel

import "fmt"

// TunnelError represents a typed tunnel operation error. Frontend code
// can type-assert or check the Kind field to decide how to handle
// specific failure modes (e.g. show different UI for "already connected"
// vs "engine creation failed").
type TunnelError struct {
	Kind    ErrorKind
	Message string
	Cause   error
}

// ErrorKind categorizes tunnel errors for programmatic handling.
type ErrorKind int

const (
	// ErrAlreadyConnected: Connect called while tunnel is already up.
	ErrAlreadyConnected ErrorKind = iota + 1
	// ErrTransitionInProgress: another Connect or Disconnect is running.
	ErrTransitionInProgress
	// ErrNotConnected: Disconnect called with no active tunnel.
	ErrNotConnected
	// ErrEngineCreation: TUN device or wireguard-go setup failed.
	ErrEngineCreation
	// ErrNetwork: route, DNS, MTU, or address assignment failed.
	ErrNetwork
	// ErrResolution: peer endpoint DNS resolution failed.
	ErrResolution
	// ErrConfig: invalid WireGuard config (bad keys, etc.).
	ErrConfig
	// ErrStateCorrupt: internal state inconsistency detected.
	ErrStateCorrupt
	// ErrTimeout: operation timed out (e.g. disconnect wait).
	ErrTimeout
	// ErrFullTunnelConflict: a full-tunnel (0.0.0.0/0) is already connected.
	ErrFullTunnelConflict
)

func (e *TunnelError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *TunnelError) Unwrap() error { return e.Cause }

// newTunnelError creates a TunnelError with the given kind.
func newTunnelError(kind ErrorKind, msg string, cause error) error {
	return &TunnelError{Kind: kind, Message: msg, Cause: cause}
}
