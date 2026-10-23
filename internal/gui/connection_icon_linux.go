//go:build linux && cgo && !gtk4

package gui

/*
#cgo pkg-config: gtk+-3.0
#include "connection_icon_linux.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// X11 window managers can use this window icon in their taskbar. Wayland
// shells may instead use a fixed desktop-file icon and ignore GTK3's image.
func applyConnectionIcon(window unsafe.Pointer, connected bool, icons connectionIconImages) error {
	icon := icons.base
	if connected {
		icon = icons.connected
	}
	if len(icon) == 0 || C.wgSetWindowConnectionIcon(window, unsafe.Pointer(&icon[0]), C.size_t(len(icon))) == 0 {
		return fmt.Errorf("cannot update GTK window icon")
	}
	return nil
}

func connectionIconMessages(_ func()) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	return nil
}
