package gui

import (
	"fmt"
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/w32"
)

func applyConnectionIcon(window unsafe.Pointer, connected bool, icons connectionIconImages) error {
	if window == nil {
		return fmt.Errorf("taskbar window is unavailable")
	}
	// Creation, use and Release stay in the same UI-thread COM apartment.
	taskbar, err := w32.NewTaskbarList3()
	if err != nil {
		return err
	}
	defer taskbar.Release()
	var icon w32.HICON
	var description *uint16
	if connected {
		icon, err = w32.CreateSmallHIconFromImage(icons.overlay)
		if err != nil {
			return err
		}
		// SetOverlayIcon copies the image; the caller still owns this HICON.
		defer w32.DestroyIcon(icon)
		description = w32.MustStringToUTF16Ptr("WireGuide VPN connected")
	}
	return taskbar.SetOverlayIcon(w32.HWND(uintptr(window)), icon, description)
}

func connectionIconMessages(refresh func()) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	created := w32.RegisterWindowMessage(w32.MustStringToUTF16Ptr("TaskbarButtonCreated"))
	restarted := w32.RegisterWindowMessage(w32.MustStringToUTF16Ptr("TaskbarCreated"))
	return func(_ uintptr, msg uint32, _, _ uintptr) (uintptr, bool) {
		if (created != 0 && msg == created) || (restarted != 0 && msg == restarted) {
			refresh()
		}
		return 0, false
	}
}
