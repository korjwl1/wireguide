package gui

import "github.com/wailsapp/wails/v3/pkg/w32"

// sessionEndMessages keeps a cancelled Windows shutdown or logoff from
// quitting the app. Wails calls Quit on every WM_ENDSESSION, including
// wParam == FALSE (another app blocked the shutdown and the session goes
// on); that Quit runs the full GUI shutdown, which disconnects the tunnels
// and stops the helper mid-session. A real session end still reaches Wails.
func sessionEndMessages(next func(uintptr, uint32, uintptr, uintptr) (uintptr, bool)) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	return func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (uintptr, bool) {
		if msg == w32.WM_ENDSESSION && wParam == 0 {
			return 0, true
		}
		if next != nil {
			return next(hwnd, msg, wParam, lParam)
		}
		return 0, false
	}
}
