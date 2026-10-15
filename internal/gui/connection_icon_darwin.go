package gui

/*
#cgo LDFLAGS: -framework Cocoa
#include "connection_icon_darwin.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func applyConnectionIcon(_ unsafe.Pointer, connected bool, icons connectionIconImages) error {
	if !connected {
		if C.wgSetApplicationConnectionIcon(nil, 0, 0) == 0 {
			return fmt.Errorf("Dock icon reset requires the AppKit thread")
		}
		return nil
	}
	if len(icons.connected) == 0 || C.wgSetApplicationConnectionIcon(unsafe.Pointer(&icons.connected[0]), C.size_t(len(icons.connected)), 1) == 0 {
		return fmt.Errorf("cannot set connected Dock icon")
	}
	return nil
}

func connectionIconMessages(_ func()) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	return nil
}
