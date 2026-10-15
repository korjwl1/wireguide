package tunnel

import "github.com/korjwl1/wireguide/internal/domain"

// Keep the engine API compatible while shared operation errors live in domain.
type TunnelError = domain.TunnelError
type ErrorKind = domain.ErrorKind

const (
	ErrAlreadyConnected     = domain.ErrAlreadyConnected
	ErrTransitionInProgress = domain.ErrTransitionInProgress
	ErrNotConnected         = domain.ErrNotConnected
	ErrEngineCreation       = domain.ErrEngineCreation
	ErrNetwork              = domain.ErrNetwork
	ErrResolution           = domain.ErrResolution
	ErrConfig               = domain.ErrConfig
	ErrStateCorrupt         = domain.ErrStateCorrupt
	ErrTimeout              = domain.ErrTimeout
	ErrFullTunnelConflict   = domain.ErrFullTunnelConflict
	ErrCancelled            = domain.ErrCancelled
)

// newTunnelError creates a TunnelError with the given kind.
func newTunnelError(kind ErrorKind, msg string, cause error) error {
	return &TunnelError{Kind: kind, Message: msg, Cause: cause}
}
