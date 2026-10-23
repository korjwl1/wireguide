package gui

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func ShowStartupError(err error) {
	title, _ := windows.UTF16PtrFromString("WireGuide")
	message, e := windows.UTF16PtrFromString(err.Error())
	if e != nil {
		return
	}
	_, _, _ = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x10)
}
