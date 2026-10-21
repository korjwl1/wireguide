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

func applyConnectionIcon(_ unsafe.Pointer, connected bool, _ connectionIconImages) error {
	var active C.int
	if connected {
		active = 1
	}
	if C.wgSetApplicationConnectionIcon(active) == 0 {
		return fmt.Errorf("cannot update Dock icon outside the AppKit thread or without a base icon")
	}
	return nil
}

func connectionIconMessages(_ func()) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	return nil
}
