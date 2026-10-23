package gui

/*
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
#include "native_tray_darwin.h"
*/
import "C"

import (
	"encoding/json"
	"sync/atomic"
	"unsafe"
)

var nativeTrayAction atomic.Pointer[func(string)]

func createNativeTray(icon []byte, action func(string)) {
	nativeTrayAction.Store(&action)
	if len(icon) > 0 {
		C.wgNativeTrayCreate(unsafe.Pointer(&icon[0]), C.size_t(len(icon)))
	}
}
func setNativeTrayConnected(connected bool) { C.wgNativeTraySetConnected(C.bool(connected)) }
func setNativeTrayMenu(items []nativeTrayItem) {
	data, _ := json.Marshal(items)
	value := C.CString(string(data))
	defer C.free(unsafe.Pointer(value))
	C.wgNativeTraySetMenu(value)
}
func setNativeTrayTooltip(text string) {
	value := C.CString(text)
	defer C.free(unsafe.Pointer(value))
	C.wgNativeTraySetTooltip(value)
}
func destroyNativeTray() { nativeTrayAction.Store(nil); C.wgNativeTrayDestroy() }

//export wgNativeTrayAction
func wgNativeTrayAction(value *C.char) {
	action := C.GoString(value)
	if callback := nativeTrayAction.Load(); callback != nil {
		// AppKit invokes on its main thread. RPCs and shutdown must run
		// elsewhere, even if the helper has stopped responding.
		go (*callback)(action)
	}
}

func preferredGUILanguage() string {
	value := C.wgPreferredGUILanguage()
	if value == nil {
		return "en"
	}
	defer C.free(unsafe.Pointer(value))
	return C.GoString(value)
}
