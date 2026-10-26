//go:build !windows && !darwin && (!linux || !cgo || gtk3)

package gui

import "unsafe"

func applyConnectionIcon(_ unsafe.Pointer, _ bool, _ connectionIconImages) error { return nil }

func connectionIconMessages(_ func()) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	return nil
}
