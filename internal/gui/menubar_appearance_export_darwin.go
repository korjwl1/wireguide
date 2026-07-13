package gui

// This file only hosts the cgo //export bridge. Per cgo rules a file
// containing //export may only DECLARE things in its preamble, so the
// Objective-C implementation lives in menubar_appearance_darwin.go.

/*
#include <stdbool.h>
*/
import "C"

import "sync/atomic"

var menuBarAppearanceCB atomic.Pointer[func(dark bool)]

//export wgMenuBarAppearanceChanged
func wgMenuBarAppearanceChanged(dark C.bool) {
	if cb := menuBarAppearanceCB.Load(); cb != nil {
		(*cb)(bool(dark))
	}
}
