//go:build windows

package wifi

import (
	"log/slog"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// startWindowsWlanWatcher subscribes to Wlanapi connect/disconnect
// notifications and invokes onChange on every transition. Returns a stop
// function. Falls back to no-op (returns nil stop) when wlanapi.dll is
// unavailable (server SKUs without WLAN service, headless containers).
func startWindowsWlanWatcher(onChange func()) (stop func()) {
	noop := func() {}

	if err := wlanLazyOpenHandle(); err != nil {
		slog.Debug("wifi: wlanapi.dll OpenHandle failed", "error", err)
		return noop
	}

	cb := syscall.NewCallback(func(notif uintptr, _ uintptr) uintptr {
		// We don't filter on notification source/code because the cost
		// of running CurrentSSID() and comparing in monitor.checkNow is
		// trivial. Any wlan event = "re-check SSID".
		onChange()
		return 0
	})

	var prevSource uint32
	ret, _, _ := procWlanRegisterNotification.Call(
		uintptr(wlanHandle),
		uintptr(wlanNotificationSourceACM),
		1, // ignoreDuplicate=TRUE
		cb,
		0, // CallerContext
		0, // Reserved
		uintptr(unsafe.Pointer(&prevSource)),
	)
	if ret != 0 {
		slog.Debug("wifi: WlanRegisterNotification failed", "status", ret)
		return noop
	}
	slog.Info("wifi: Wlanapi notification subscribed")

	var once sync.Once
	return func() {
		once.Do(func() {
			// Unregister by passing source=0.
			var prev uint32
			procWlanRegisterNotification.Call(
				uintptr(wlanHandle),
				0,
				0,
				0,
				0,
				0,
				uintptr(unsafe.Pointer(&prev)),
			)
		})
	}
}

var (
	modWlanapi                      = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle              = modWlanapi.NewProc("WlanOpenHandle")
	procWlanRegisterNotification    = modWlanapi.NewProc("WlanRegisterNotification")

	wlanHandle uintptr
	wlanOpenOnce sync.Once
	wlanOpenErr  error
)

const (
	// WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008 covers connect/disconnect/scan.
	wlanNotificationSourceACM = 0x00000008
)

func wlanLazyOpenHandle() error {
	wlanOpenOnce.Do(func() {
		// WlanOpenHandle wants: DWORD dwClientVersion, PVOID pReserved,
		//                       PDWORD pdwNegotiatedVersion, PHANDLE phClientHandle
		var negotiated uint32
		var handle uintptr
		ret, _, _ := procWlanOpenHandle.Call(
			2, // client version 2 (Vista+)
			0,
			uintptr(unsafe.Pointer(&negotiated)),
			uintptr(unsafe.Pointer(&handle)),
		)
		if ret != 0 {
			wlanOpenErr = syscall.Errno(ret)
			return
		}
		wlanHandle = handle
	})
	return wlanOpenErr
}
