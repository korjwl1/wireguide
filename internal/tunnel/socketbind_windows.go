//go:build windows

package tunnel

// Windows uses WireGuard's native BindSocketToInterface API. The guarded
// wrapper keeps sends blocked until binding succeeds and across socket
// reopen. Notifications accelerate recovery; periodic checks cover missed
// notifications and registration failures.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"syscall"
	"unsafe"

	"github.com/korjwl1/wireguide/internal/network"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
)

func newPlatformBind(ifaceName string) (conn.Bind, error) {
	base := conn.NewDefaultBind()
	binder, ok := base.(conn.BindSocketToInterface)
	if !ok {
		return nil, fmt.Errorf("WireGuard bind cannot protect UDP sockets")
	}
	// Configure the initial underlay before Open returns to wireguard-go,
	// so the first handshake is protected without waiting for a retry.
	guard := &guardedBind{Bind: base, binder: binder}
	resolve := underlayResolver(ifaceName)
	for family := range guard.families {
		index := resolve(family == 1)
		guard.families[family] = socketFamilyBinding{index: index, blackhole: index == 0, configured: true}
	}
	return guard, nil
}

func underlayResolver(tunnelName string) func(bool) uint32 {
	return func(ipv6 bool) uint32 {
		if ipv6 {
			_, index, _ := network.DefaultRouteV6LuidAndIndex([]string{tunnelName})
			return index
		}
		_, index, _ := network.DefaultRouteV4LuidAndIndex([]string{tunnelName})
		return index
	}
}

func pinSocketToPhysical(bind conn.Bind, tunnelName string) (uint32, uint32, error) {
	binder, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return 0, 0, fmt.Errorf("WireGuard bind cannot bind sockets to an interface")
	}
	resolve := underlayResolver(tunnelName)
	v4, err4 := bindSocketFamily(binder, resolve, false)
	v6, err6 := bindSocketFamily(binder, resolve, true)
	return v4, v6, errors.Join(err4, err6)
}

func startSocketBindMonitor(ctx context.Context, bind conn.Bind, tunnelName string, initialV4, initialV6 uint32) {
	binder, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return
	}
	mon := &socketBindMonitor{binder: binder, resolve: underlayResolver(tunnelName),
		kick: make(chan struct{}, 1), last: [2]uint32{initialV4, initialV6}}
	unregister, err := registerSocketBindCallbacks(mon)
	if err != nil {
		slog.Warn("socket bind notifications unavailable; periodic protection remains active", "error", err)
	}
	go mon.run(ctx, socketBindPollInterval, unregister)
}

var (
	procNotifyRouteChange2      = modIphlpapiSocketbind.NewProc("NotifyRouteChange2")
	procNotifyIpInterfaceChange = modIphlpapiSocketbind.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modIphlpapiSocketbind.NewProc("CancelMibChangeNotify2")
	modIphlpapiSocketbind       = windows.NewLazySystemDLL("iphlpapi.dll")
	socketBindRegistry          = struct {
		sync.Mutex
		next     uintptr
		monitors map[uintptr]*socketBindMonitor
	}{monitors: make(map[uintptr]*socketBindMonitor)}
	// NewCallback allocations are permanent on Windows. Allocate once,
	// not twice per tunnel reconnect, and pass integer registry IDs.
	socketRouteCallback = windows.NewCallback(func(id, row uintptr, kind uint32) uintptr {
		signalSocketBindMonitor(id)
		return 0
	})
	socketInterfaceCallback = windows.NewCallback(func(id, row uintptr, kind uint32) uintptr {
		if kind == 0 {
			signalSocketBindMonitor(id)
		}
		return 0
	})
)

func signalSocketBindMonitor(id uintptr) {
	socketBindRegistry.Lock()
	mon := socketBindRegistry.monitors[id]
	socketBindRegistry.Unlock()
	if mon != nil {
		select {
		case mon.kick <- struct{}{}:
		default:
		}
	}
}

func registerSocketBindCallbacks(mon *socketBindMonitor) (func(), error) {
	socketBindRegistry.Lock()
	socketBindRegistry.next++
	id := socketBindRegistry.next
	socketBindRegistry.monitors[id] = mon
	socketBindRegistry.Unlock()
	var routeHandle, interfaceHandle windows.Handle
	unregister := func() {
		socketBindRegistry.Lock()
		delete(socketBindRegistry.monitors, id)
		socketBindRegistry.Unlock()
		if routeHandle != 0 {
			_ = cancelMibChangeNotify2(routeHandle)
		}
		if interfaceHandle != 0 {
			_ = cancelMibChangeNotify2(interfaceHandle)
		}
	}
	if err := notifyRouteChange2(windows.AF_UNSPEC, socketRouteCallback, id, false, &routeHandle); err != nil {
		unregister()
		return func() {}, err
	}
	if err := notifyIpInterfaceChange(windows.AF_UNSPEC, socketInterfaceCallback, id, false, &interfaceHandle); err != nil {
		unregister()
		return func() {}, err
	}
	return unregister, nil
}

// notifyRouteChange2 wraps iphlpapi!NotifyRouteChange2. Returns nil on
// success (status 0); otherwise the Win32 error as an errno-equivalent.
func notifyRouteChange2(family uint16, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) error {
	var initial uint32
	if initialNotification {
		initial = 1
	}
	r0, _, _ := syscall.SyscallN(procNotifyRouteChange2.Addr(),
		uintptr(family),
		callback,
		callerContext,
		uintptr(initial),
		uintptr(unsafe.Pointer(notificationHandle)))
	if r0 != 0 {
		return errors.New("NotifyRouteChange2 failed: " + windows.Errno(r0).Error())
	}
	return nil
}

// notifyIpInterfaceChange wraps iphlpapi!NotifyIpInterfaceChange.
func notifyIpInterfaceChange(family uint16, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) error {
	var initial uint32
	if initialNotification {
		initial = 1
	}
	r0, _, _ := syscall.SyscallN(procNotifyIpInterfaceChange.Addr(),
		uintptr(family),
		callback,
		callerContext,
		uintptr(initial),
		uintptr(unsafe.Pointer(notificationHandle)))
	if r0 != 0 {
		return errors.New("NotifyIpInterfaceChange failed: " + windows.Errno(r0).Error())
	}
	return nil
}

// cancelMibChangeNotify2 wraps iphlpapi!CancelMibChangeNotify2.
func cancelMibChangeNotify2(handle windows.Handle) error {
	r0, _, _ := syscall.SyscallN(procCancelMibChangeNotify2.Addr(), uintptr(handle))
	if r0 != 0 {
		return errors.New("CancelMibChangeNotify2 failed: " + windows.Errno(r0).Error())
	}
	return nil
}
