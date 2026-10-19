package gui

import "github.com/wailsapp/wails/v3/pkg/application"

type activatableWindow interface {
	IsMinimised() bool
	Restore()
	SetFrameless(bool) application.Window
	Show() application.Window
	Focus()
}

func restoreMainWindow(w activatableWindow, restoreDecorations bool) {
	if w.IsMinimised() {
		w.Restore()
	}
	if restoreDecorations {
		// GTK can retain a stale decoration hint after close-to-tray.
		w.SetFrameless(true)
		w.SetFrameless(false)
	}
	w.Show()
	w.Focus()
}
