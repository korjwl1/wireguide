package gui

import (
	"testing"

	"github.com/wailsapp/wails/v3/pkg/w32"
)

func TestCancelledSessionEndDoesNotReachWails(t *testing.T) {
	forwarded := 0
	handler := sessionEndMessages(func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
		forwarded++
		return 0, false
	})
	if _, consumed := handler(0, w32.WM_ENDSESSION, 0, 0); !consumed {
		t.Fatal("cancelled WM_ENDSESSION reached Wails, which would quit the app")
	}
	if forwarded != 0 {
		t.Fatal("cancelled WM_ENDSESSION was forwarded to the next hook")
	}
	if _, consumed := handler(0, w32.WM_ENDSESSION, 1, 0); consumed {
		t.Fatal("real session end was swallowed; Wails must still quit")
	}
	if _, consumed := handler(0, w32.WM_QUERYENDSESSION, 0, 0); consumed {
		t.Fatal("WM_QUERYENDSESSION was swallowed")
	}
	if forwarded != 2 {
		t.Fatalf("forwarded %d messages, want 2", forwarded)
	}
}
