package gui

import (
	"fmt"
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/w32"
)

// Accessed only on the GUI thread. WM_SETICON retains the supplied handles,
// so keep our icons alive until replacement and never destroy Wails' originals.
var windowConnectionIcons = make(map[w32.HWND]windowConnectionIcon)

type windowConnectionIcon struct {
	originalSmall, originalLarge w32.HICON
	small, large                 w32.HICON
}

func applyConnectionIcon(window unsafe.Pointer, connected bool, icons connectionIconImages) error {
	if window == nil {
		return fmt.Errorf("taskbar window is unavailable")
	}
	return applyWindowsConnectionIcon(w32.HWND(uintptr(window)), connected, icons)
}

func applyWindowsConnectionIcon(hwnd w32.HWND, connected bool, icons connectionIconImages) error {
	previous, exists := windowConnectionIcons[hwnd]
	if !connected {
		if exists {
			w32.SendMessage(hwnd, w32.WM_SETICON, w32.ICON_SMALL, uintptr(previous.originalSmall))
			w32.SendMessage(hwnd, w32.WM_SETICON, w32.ICON_BIG, uintptr(previous.originalLarge))
			w32.DestroyIcon(previous.small)
			w32.DestroyIcon(previous.large)
			delete(windowConnectionIcons, hwnd)
		}
		return nil
	}
	// Compose the badge into the application icon: the shell's overlay is
	// too large and fixes its position instead of following our lower-left dot.
	small, err := w32.CreateSmallHIconFromImage(icons.connected)
	if err != nil {
		return err
	}
	large, err := w32.CreateLargeHIconFromImage(icons.connected)
	if err != nil {
		w32.DestroyIcon(small)
		return err
	}
	originalSmall := w32.HICON(w32.SendMessage(hwnd, w32.WM_SETICON, w32.ICON_SMALL, uintptr(small)))
	originalLarge := w32.HICON(w32.SendMessage(hwnd, w32.WM_SETICON, w32.ICON_BIG, uintptr(large)))
	if exists {
		originalSmall, originalLarge = previous.originalSmall, previous.originalLarge
		w32.DestroyIcon(previous.small)
		w32.DestroyIcon(previous.large)
	}
	windowConnectionIcons[hwnd] = windowConnectionIcon{originalSmall, originalLarge, small, large}
	return nil
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
