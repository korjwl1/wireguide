//go:build !(darwin && cgo)

package launchd

import (
	"errors"
	"testing"
)

func TestListenersStubNotManaged(t *testing.T) {
	ls, err := Listeners()
	if !errors.Is(err, ErrNotManaged) || len(ls) != 0 {
		t.Fatalf("Listeners() = %v, %v; want ErrNotManaged", ls, err)
	}
}
