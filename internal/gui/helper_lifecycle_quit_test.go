package gui

import (
	"context"
	"errors"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// Once a quit has started, background recovery must not touch the helper
// socket: on macOS the connect itself would start the helper again.
func TestRecoverHelperAfterQuitDoesNothing(t *testing.T) {
	orig := recoveryDial
	t.Cleanup(func() { recoveryDial = orig })
	recoveryDial = func(context.Context, string) (*ipc.Client, error) {
		t.Error("recoverHelper dialled the helper after quit")
		return nil, errors.New("must not dial")
	}
	done := make(chan struct{})
	close(done)
	if recoverHelper(&ipc.ClientHolder{}, nil, "", done) {
		t.Fatal("recoverHelper reported success after quit")
	}
}
