package launchd

import (
	"errors"
	"syscall"
	"testing"
)

func TestMapActivateError(t *testing.T) {
	if err := mapActivateError(0); err != nil {
		t.Errorf("rc 0 = %v, want nil", err)
	}
	if err := mapActivateError(int(syscall.ESRCH)); !errors.Is(err, ErrNotManaged) {
		t.Errorf("ESRCH = %v, want ErrNotManaged", err)
	}
	if err := mapActivateError(int(syscall.ENOENT)); !errors.Is(err, ErrNoSocketEntry) {
		t.Errorf("ENOENT = %v, want ErrNoSocketEntry", err)
	}
	err := mapActivateError(int(syscall.EALREADY))
	if err == nil || errors.Is(err, ErrNotManaged) || errors.Is(err, ErrNoSocketEntry) {
		t.Errorf("EALREADY = %v, want a distinct fatal error", err)
	}
	if !errors.Is(err, syscall.EALREADY) {
		t.Errorf("EALREADY error does not wrap the errno: %v", err)
	}
}
