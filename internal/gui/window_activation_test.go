package gui

import (
	"github.com/wailsapp/wails/v3/pkg/application"
	"slices"
	"testing"
)

type activationWindow struct {
	minimised bool
	calls     []string
}

func (w *activationWindow) IsMinimised() bool { return w.minimised }
func (w *activationWindow) Restore()          { w.calls = append(w.calls, "restore"); w.minimised = false }
func (w *activationWindow) SetFrameless(b bool) application.Window {
	if b {
		w.calls = append(w.calls, "undecorate")
	} else {
		w.calls = append(w.calls, "decorate")
	}
	return nil
}
func (w *activationWindow) Show() application.Window { w.calls = append(w.calls, "show"); return nil }
func (w *activationWindow) Focus()                   { w.calls = append(w.calls, "focus") }

func TestRelaunchRestoresMinimisedWindowBeforeShowingAndFocusing(t *testing.T) {
	w := &activationWindow{minimised: true}
	restoreMainWindow(w, false)
	if !slices.Equal(w.calls, []string{"restore", "show", "focus"}) {
		t.Fatalf("activation: %v", w.calls)
	}
}
func TestRelaunchPreservesNormalOrMaximisedWindow(t *testing.T) {
	w := &activationWindow{}
	restoreMainWindow(w, false)
	if !slices.Equal(w.calls, []string{"show", "focus"}) {
		t.Fatalf("unnecessary restore changed window state: %v", w.calls)
	}
}
func TestLinuxWindowActivationPreservesDecorationRecovery(t *testing.T) {
	w := &activationWindow{}
	restoreMainWindow(w, true)
	if !slices.Equal(w.calls, []string{"undecorate", "decorate", "show", "focus"}) {
		t.Fatalf("decoration recovery: %v", w.calls)
	}
}
