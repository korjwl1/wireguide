//go:build !windows

package gui

func sessionEndMessages(next func(uintptr, uint32, uintptr, uintptr) (uintptr, bool)) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	return next
}
