//go:build windows

package tunnel

// Socket-level loop protection — IP_UNICAST_IF binding for the WireGuard
// UDP sockets, mirroring what the official wireguard-windows client does
// in tunnel/defaultroutemonitor.go (v0.1.1).
//
// Why this exists ALONGSIDE the WFP block + iphlpapi bypass routes the
// rest of this branch added:
//
//   - The /32 bypass + WFP BLOCK protect against the loop AT THE ROUTING
//     TABLE / FILTERING LAYER. Both depend on the kernel making a routing
//     decision and either (a) finding the /32 first or (b) hitting our
//     filter when it doesn't. Both have correctness invariants we have to
//     defend continuously (route ordering on install, filter ordering on
//     network state changes, etc.).
//
//   - IP_UNICAST_IF tells the WG UDP socket "regardless of the route
//     table, send through THIS specific interface index." It moves the
//     decision OUT of the route table entirely — the kernel skips its
//     routing lookup for traffic on the bound socket. The wintun adapter
//     can be the longest-prefix match for the peer endpoint and our WG
//     send still goes out the physical NIC. That's the same trick the
//     official client uses as its PRIMARY anti-loop measure.
//
// We keep all three defenses because they fail differently:
//
//   bind miss → routing decision picks wintun → /32 bypass catches it
//   /32 bypass missing or stale → WFP BLOCK at OUTBOUND_TRANSPORT drops it
//   WFP layer disabled by a third-party security driver → watchdog trips
//
// Three layers in series. The official client gets away with one mostly
// because Donenfeld owns the BFE filter weight space; we're an uncertified
// app, so belt-and-suspenders is the right call.
//
// Change detection — NotifyRouteChange2 + NotifyIpInterfaceChange push
// notifications, ported from wireguard-windows v0.1.1
// tunnel/defaultroutemonitor.go + tunnel/winipcfg/route_change_handler.go.
// Latency: ~150 ms from kernel route change to re-pin, vs the ~5 s a
// polling design would deliver. Worth porting because the difference is
// the user-visible "tunnel stuck for 5 s after Wi-Fi → Ethernet handoff"
// gap.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/korjwl1/wireguide/internal/network"
)

// debounce timing — ported verbatim from wireguard-windows
// tunnel/defaultroutemonitor.go. 150 ms coalesces the typical burst of
// route/interface events Windows fires during a network handoff; the
// 2 s burst-escape forces a re-evaluation even if the events never
// stop arriving (e.g., a third-party VPN spamming routes).
const (
	socketBindDebounce     = 150 * time.Millisecond
	socketBindBurstEscape  = 2 * time.Second
)

// pinSocketToPhysical does one pass of (find best non-tunnel default,
// call BindSocketToInterface). Used at connect time before the monitor
// is started, and as the implementation of every monitor re-evaluation.
// Returns the (v4, v6) ifIndex pair actually bound (0 = blackhole/no
// underlay for that family).
func pinSocketToPhysical(bind conn.Bind, tunnelInterfaceName string) (uint32, uint32) {
	binder, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return 0, 0
	}
	v4 := pinFamily(binder, tunnelInterfaceName, false)
	v6 := pinFamily(binder, tunnelInterfaceName, true)
	return v4, v6
}

// pinFamily resolves one address family's best non-tunnel default route
// and binds the corresponding socket. Returns the bound ifIndex (0 if
// no usable underlay was found and blackhole was applied).
func pinFamily(binder conn.BindSocketToInterface, tunnelInterfaceName string, ipv6 bool) uint32 {
	excludedAliases := []string{tunnelInterfaceName}
	var ifIndex uint32
	if ipv6 {
		_, ifIndex, _ = network.DefaultRouteV6LuidAndIndex(excludedAliases)
	} else {
		_, ifIndex, _ = network.DefaultRouteV4LuidAndIndex(excludedAliases)
	}
	blackhole := ifIndex == 0
	var err error
	if ipv6 {
		err = binder.BindSocketToInterface6(ifIndex, blackhole)
	} else {
		err = binder.BindSocketToInterface4(ifIndex, blackhole)
	}
	if err != nil {
		slog.Warn("socket pin failed",
			"family", familyName(ipv6),
			"ifIndex", ifIndex,
			"blackhole", blackhole,
			"error", err)
		return 0
	}
	slog.Info("WG socket pinned to underlay",
		"family", familyName(ipv6),
		"ifIndex", ifIndex,
		"blackhole", blackhole,
		"tunnel_excluded", tunnelInterfaceName)
	return ifIndex
}

func familyName(ipv6 bool) string {
	if ipv6 {
		return "v6"
	}
	return "v4"
}

// startSocketBindMonitor wires NotifyRouteChange2 + NotifyIpInterfaceChange
// kernel callbacks. Any route or interface-parameter change pumps the
// debounce timer; the timer fires re-evaluation in pinSocketToPhysical's
// idempotent path (which is a no-op when the best underlay hasn't moved).
//
// initialV4/V6 are kept on the closure's atomic.Uint32 so the next pass's
// pinFamily logs only when the index actually changes (via slog.Info
// "WG socket pinned to underlay" — repeat for the same ifIndex is fine,
// the kernel setsockopt is idempotent, but the log line is noisy if every
// burst event re-fires it).
//
// Cleanup: ctx cancellation unregisters both callbacks and stops the
// debounce timer. The callbacks themselves are guarded by sync.WaitGroup
// so concurrent goroutines spawned by the kernel callback drain before
// the manager calls engine.Close.
func startSocketBindMonitor(ctx context.Context, bind conn.Bind, tunnelInterfaceName string, initialV4, initialV6 uint32) {
	if bind == nil {
		return
	}
	binder, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return
	}

	mon := &socketBindMonitor{
		binder:              binder,
		tunnelInterfaceName: tunnelInterfaceName,
	}
	mon.lastV4.Store(initialV4)
	mon.lastV6.Store(initialV6)

	// Burst-debounce timer. Reset on every bump; fires reevaluate() once
	// the burst quiets down for socketBindDebounce. Initial reset to a
	// very long duration so it doesn't fire before the first bump.
	mon.burstTimer = time.AfterFunc(time.Hour*200, mon.reevaluate)
	mon.burstTimer.Stop()

	// Register kernel callbacks. We unify both notifications onto one
	// bump() path because the action we'd take (re-evaluate underlay
	// and re-pin) is the same either way.
	if err := mon.registerCallbacks(); err != nil {
		slog.Warn("WG socket bind monitor: callback registration failed; reverting to no monitor",
			"error", err)
		return
	}

	// Tie lifecycle to ctx. When ctx is cancelled (DisconnectTunnel),
	// unregister and stop the timer.
	go func() {
		<-ctx.Done()
		mon.stop()
		slog.Info("WG socket bind monitor stopped", "tunnel", tunnelInterfaceName)
	}()
}

// socketBindMonitor holds the runtime state for one tunnel's bind monitor.
// Lifecycle: created in startSocketBindMonitor, torn down via stop()
// when ctx is cancelled.
type socketBindMonitor struct {
	binder              conn.BindSocketToInterface
	tunnelInterfaceName string

	lastV4 atomic.Uint32
	lastV6 atomic.Uint32

	burstMu     sync.Mutex
	burstTimer  *time.Timer
	firstBurst  time.Time // first event of the current burst; zero between bursts

	cbMu       sync.Mutex
	routeHnd   windows.Handle
	ifaceHnd   windows.Handle
	pending    sync.WaitGroup // tracks in-flight callback goroutines
	stopped    atomic.Bool
}

// bump is called from kernel notification callbacks. Resets the
// debounce timer; if the current burst has lasted > burstEscape,
// force-fires reevaluate immediately so a continuously-noisy network
// doesn't permanently postpone the re-pin.
func (mon *socketBindMonitor) bump() {
	mon.burstMu.Lock()
	defer mon.burstMu.Unlock()
	mon.burstTimer.Reset(socketBindDebounce)
	if mon.firstBurst.IsZero() {
		mon.firstBurst = time.Now()
		return
	}
	if time.Since(mon.firstBurst) > socketBindBurstEscape {
		mon.firstBurst = time.Time{}
		mon.burstTimer.Stop()
		// Reevaluate inline so we don't lose a re-pin opportunity while
		// the burst continues forever.
		go mon.reevaluate()
	}
}

// reevaluate fires after the debounce timer has gone quiet, or
// (force-path) from bump() when a burst has exceeded its escape budget.
// Re-runs pinFamily for both address families; pinFamily logs only on
// state change so calling it on every reevaluate is cheap and correct.
func (mon *socketBindMonitor) reevaluate() {
	if mon.stopped.Load() {
		return
	}
	mon.burstMu.Lock()
	mon.firstBurst = time.Time{}
	mon.burstMu.Unlock()

	newV4 := evaluateOneFamily(mon.binder, mon.tunnelInterfaceName, false, mon.lastV4.Load())
	mon.lastV4.Store(newV4)
	newV6 := evaluateOneFamily(mon.binder, mon.tunnelInterfaceName, true, mon.lastV6.Load())
	mon.lastV6.Store(newV6)
}

// evaluateOneFamily resolves the best non-tunnel default for one
// address family and (re-)binds. Logs "WG socket re-pinned" on a real
// change; silent no-op when the index is unchanged so we don't spam
// during noisy bursts. Returns the ifIndex now in force (caller updates
// its lastV4/V6 atomic).
func evaluateOneFamily(binder conn.BindSocketToInterface, tunnelInterfaceName string, ipv6 bool, previous uint32) uint32 {
	excludedAliases := []string{tunnelInterfaceName}
	var ifIndex uint32
	if ipv6 {
		_, ifIndex, _ = network.DefaultRouteV6LuidAndIndex(excludedAliases)
	} else {
		_, ifIndex, _ = network.DefaultRouteV4LuidAndIndex(excludedAliases)
	}
	if ifIndex == previous {
		return previous
	}
	blackhole := ifIndex == 0
	var err error
	if ipv6 {
		err = binder.BindSocketToInterface6(ifIndex, blackhole)
	} else {
		err = binder.BindSocketToInterface4(ifIndex, blackhole)
	}
	if err != nil {
		slog.Warn("socket re-pin failed",
			"family", familyName(ipv6),
			"new_ifIndex", ifIndex,
			"previous_ifIndex", previous,
			"blackhole", blackhole,
			"error", err)
		return previous
	}
	slog.Info("WG socket re-pinned (underlay changed)",
		"family", familyName(ipv6),
		"previous_ifIndex", previous,
		"new_ifIndex", ifIndex,
		"blackhole", blackhole)
	return ifIndex
}

// --- Kernel callback wiring ----------------------------------------

var (
	procNotifyRouteChange2          = modIphlpapiSocketbind.NewProc("NotifyRouteChange2")
	procNotifyIpInterfaceChange     = modIphlpapiSocketbind.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2      = modIphlpapiSocketbind.NewProc("CancelMibChangeNotify2")
	modIphlpapiSocketbind           = windows.NewLazySystemDLL("iphlpapi.dll")
)

// registerCallbacks subscribes to NotifyRouteChange2 + NotifyIpInterfaceChange.
// Both share a single bump() target — the action is the same regardless of
// which event class fired. AF_UNSPEC subscribes to both v4 and v6 in one
// registration each (cheaper than two registrations per family).
//
// The kernel callbacks run on an arbitrary OS thread. We immediately spawn
// a Go goroutine to do the actual bump (via mon.pending so stop() can
// wait for in-flight handlers to drain). The callback itself returns
// quickly so the kernel doesn't see a slow notifier.
func (mon *socketBindMonitor) registerCallbacks() error {
	routeCB := windows.NewCallback(func(callerContext uintptr, row uintptr, notificationType uint32) uintptr {
		// We don't need to read the row — any default-prefix change is
		// a reason to re-pin, and over-eager re-pins are no-ops via
		// the unchanged-ifIndex guard in evaluateOneFamily.
		if mon.stopped.Load() {
			return 0
		}
		mon.pending.Add(1)
		go func() {
			defer mon.pending.Done()
			mon.bump()
		}()
		return 0
	})
	ifaceCB := windows.NewCallback(func(callerContext uintptr, row uintptr, notificationType uint32) uintptr {
		// Only parameter changes are interesting (metric flipped, AdminStatus
		// toggled, etc.). MibParameterNotification == 0; add/delete are
		// already covered by the route handler when they cause a default-
		// route table mutation.
		const mibParameterNotification uint32 = 0
		if notificationType != mibParameterNotification {
			return 0
		}
		if mon.stopped.Load() {
			return 0
		}
		mon.pending.Add(1)
		go func() {
			defer mon.pending.Done()
			mon.bump()
		}()
		return 0
	})

	mon.cbMu.Lock()
	defer mon.cbMu.Unlock()
	var rh windows.Handle
	if err := notifyRouteChange2(windows.AF_UNSPEC, routeCB, 0, false, &rh); err != nil {
		return err
	}
	mon.routeHnd = rh

	var ih windows.Handle
	if err := notifyIpInterfaceChange(windows.AF_UNSPEC, ifaceCB, 0, false, &ih); err != nil {
		// Roll back the route subscription on partial failure so we don't
		// leak a kernel callback handle on next attempt.
		_ = cancelMibChangeNotify2(mon.routeHnd)
		mon.routeHnd = 0
		return err
	}
	mon.ifaceHnd = ih
	return nil
}

func (mon *socketBindMonitor) stop() {
	if !mon.stopped.CompareAndSwap(false, true) {
		return
	}
	mon.cbMu.Lock()
	rh, ih := mon.routeHnd, mon.ifaceHnd
	mon.routeHnd, mon.ifaceHnd = 0, 0
	mon.cbMu.Unlock()
	if rh != 0 {
		_ = cancelMibChangeNotify2(rh)
	}
	if ih != 0 {
		_ = cancelMibChangeNotify2(ih)
	}
	mon.burstMu.Lock()
	if mon.burstTimer != nil {
		mon.burstTimer.Stop()
	}
	mon.burstMu.Unlock()
	mon.pending.Wait()
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
