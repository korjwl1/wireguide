//go:build linux && cgo && !gtk3

package gui

/*
#cgo pkg-config: gtk4
#include "connection_icon_linux.h"
#include <stdlib.h>
*/
import "C"

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/korjwl1/wireguide/internal/atomicfile"
)

// GTK4 accepts named theme icons rather than per-window pixbufs. Cache each
// generated image under a content-derived name so GTK never reuses a stale
// texture after an application update. Some Wayland shells still prefer the
// desktop-file icon; the tray indicator remains independent of this hint.
var linuxConnectionIcons struct {
	sync.Once
	dir, base, connected string
	err                  error
}

func applyConnectionIcon(window unsafe.Pointer, connected bool, icons connectionIconImages) error {
	linuxConnectionIcons.Do(func() {
		cache, err := os.UserCacheDir()
		if err != nil {
			linuxConnectionIcons.err = err
			return
		}
		linuxConnectionIcons.dir = filepath.Join(cache, "wireguide", "icons")
		if err := os.MkdirAll(linuxConnectionIcons.dir, 0700); err != nil {
			linuxConnectionIcons.err = err
			return
		}
		write := func(image []byte) (string, error) {
			if len(image) == 0 {
				return "", fmt.Errorf("empty connection icon")
			}
			sum := sha256.Sum256(image)
			name := fmt.Sprintf("wireguide-%x", sum[:12])
			err := atomicfile.WriteFile(filepath.Join(linuxConnectionIcons.dir, name+".png"), image, 0600)
			return name, err
		}
		linuxConnectionIcons.base, linuxConnectionIcons.err = write(icons.base)
		if linuxConnectionIcons.err == nil {
			linuxConnectionIcons.connected, linuxConnectionIcons.err = write(icons.connected)
		}
	})
	if linuxConnectionIcons.err != nil {
		return linuxConnectionIcons.err
	}
	name := linuxConnectionIcons.base
	if connected {
		name = linuxConnectionIcons.connected
	}
	dir, icon := C.CString(linuxConnectionIcons.dir), C.CString(name)
	defer C.free(unsafe.Pointer(dir))
	defer C.free(unsafe.Pointer(icon))
	if C.wgSetWindowConnectionIcon(window, dir, icon) == 0 {
		return fmt.Errorf("cannot update GTK window icon")
	}
	return nil
}

func connectionIconMessages(_ func()) func(uintptr, uint32, uintptr, uintptr) (uintptr, bool) {
	return nil
}
