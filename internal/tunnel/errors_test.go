package tunnel

import (
	"errors"
	"fmt"
	"testing"
)

func TestTunnelErrorWithCause(t *testing.T) {
	cause := fmt.Errorf("connection refused")
	te := &TunnelError{Kind: ErrNetwork, Message: "dial failed", Cause: cause}
	want := "dial failed: connection refused"
	if got := te.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestTunnelErrorWithoutCause(t *testing.T) {
	te := &TunnelError{Kind: ErrAlreadyConnected, Message: "already connected"}
	want := "already connected"
	if got := te.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestTunnelErrorUnwrap(t *testing.T) {
	cause := fmt.Errorf("root cause")
	te := &TunnelError{Kind: ErrConfig, Message: "bad config", Cause: cause}
	if te.Unwrap() != cause {
		t.Errorf("Unwrap() returned %v, want %v", te.Unwrap(), cause)
	}
}

func TestTunnelErrorUnwrapNil(t *testing.T) {
	te := &TunnelError{Kind: ErrTimeout, Message: "timed out"}
	if te.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil", te.Unwrap())
	}
}

func TestErrorsIsThroughChain(t *testing.T) {
	sentinel := fmt.Errorf("sentinel")
	te := &TunnelError{Kind: ErrResolution, Message: "dns failed", Cause: sentinel}
	wrapped := fmt.Errorf("outer: %w", te)

	if !errors.Is(wrapped, sentinel) {
		t.Error("errors.Is did not find sentinel through TunnelError chain")
	}
}

func TestErrorsAsExtractsTunnelError(t *testing.T) {
	te := &TunnelError{Kind: ErrEngineCreation, Message: "engine failed"}
	wrapped := fmt.Errorf("wrapper: %w", te)

	var target *TunnelError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As failed to extract *TunnelError")
	}
	if target.Kind != ErrEngineCreation {
		t.Errorf("Kind = %d, want %d", target.Kind, ErrEngineCreation)
	}
	if target.Message != "engine failed" {
		t.Errorf("Message = %q, want %q", target.Message, "engine failed")
	}
}

func TestErrorKindsDistinct(t *testing.T) {
	kinds := []ErrorKind{
		ErrAlreadyConnected,
		ErrTransitionInProgress,
		ErrNotConnected,
		ErrEngineCreation,
		ErrNetwork,
		ErrResolution,
		ErrConfig,
		ErrStateCorrupt,
		ErrTimeout,
	}

	seen := make(map[ErrorKind]bool)
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("duplicate ErrorKind value: %d", k)
		}
		seen[k] = true
	}

	if len(seen) != 9 {
		t.Errorf("expected 9 distinct ErrorKind values, got %d", len(seen))
	}
}

func TestNewTunnelError(t *testing.T) {
	cause := fmt.Errorf("underlying")
	err := newTunnelError(ErrStateCorrupt, "state corrupt", cause)

	var te *TunnelError
	if !errors.As(err, &te) {
		t.Fatal("newTunnelError did not return a *TunnelError")
	}
	if te.Kind != ErrStateCorrupt {
		t.Errorf("Kind = %d, want %d", te.Kind, ErrStateCorrupt)
	}
	if te.Message != "state corrupt" {
		t.Errorf("Message = %q, want %q", te.Message, "state corrupt")
	}
	if te.Cause != cause {
		t.Errorf("Cause = %v, want %v", te.Cause, cause)
	}
}

func TestNewTunnelErrorNilCause(t *testing.T) {
	err := newTunnelError(ErrNotConnected, "not connected", nil)

	var te *TunnelError
	if !errors.As(err, &te) {
		t.Fatal("newTunnelError did not return a *TunnelError")
	}
	if te.Cause != nil {
		t.Errorf("Cause = %v, want nil", te.Cause)
	}
}
