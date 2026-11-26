//go:build darwin

package wifi

/*
#cgo LDFLAGS: -framework CoreWLAN -framework CoreLocation -framework Foundation
#include <stdlib.h>

// Implemented in detect_cw_darwin.m (compiled as Objective-C by the Go toolchain).
const char* cwCurrentSSID(void);
const char* cwInterfaceName(void);
void cwRequestLocationAuthorization(void);
int  cwLocationAuthorizationStatus(void);
int  cwStartSSIDMonitor(void);
void cwStopSSIDMonitor(void);
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// currentSSIDCoreWLAN queries CoreWLAN for the current SSID.
// On macOS 14+ this is the only API that (a) reliably returns the SSID and
// (b) triggers a CoreLocation authorisation prompt so WireGuide appears in
// System Settings → Privacy & Security → Location Services.
func currentSSIDCoreWLAN() string {
	cs := C.cwCurrentSSID()
	if cs == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}

// RequestLocationAuthorization calls CLLocationManager.requestWhenInUseAuthorization
// on the main thread. This registers the app with macOS Location Services so the
// user can grant SSID access in System Settings → Privacy & Security → Location Services.
func RequestLocationAuthorization() {
	C.cwRequestLocationAuthorization()
}

// locationAuthorizationRaw returns the raw CLAuthorizationStatus of this
// process (-1 when unavailable). Read-only: never prompts.
func locationAuthorizationRaw() int {
	return int(C.cwLocationAuthorizationStatus())
}

// wifiInterfaceNameCoreWLAN returns the BSD name of the Wi-Fi interface via CoreWLAN.
func wifiInterfaceNameCoreWLAN() string {
	cs := C.cwInterfaceName()
	if cs == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}

// ---------- Event-driven SSID monitor ----------
//
// The Obj-C side exposes a singleton delegate; we wrap it with a Go
// channel so callers consume SSID changes idiomatically. Designed to
// fall back gracefully when CoreWLAN refuses to start the subscription
// (location permission denied, sandbox restriction, etc.) — the
// wrapper returns an error and the caller stays on the polling path.

var (
	ssidEventMu sync.Mutex
	ssidEventCh chan string // nil when monitor not started
)

//export goSSIDChanged
func goSSIDChanged(cstr *C.char) {
	// Obj-C strdup'd the c-string — we own freeing it.
	defer C.free(unsafe.Pointer(cstr))
	s := C.GoString(cstr)

	ssidEventMu.Lock()
	ch := ssidEventCh
	ssidEventMu.Unlock()
	if ch == nil {
		return
	}
	// Non-blocking send — if the consumer is slow we drop the event
	// rather than block the Obj-C main-thread delegate callback.
	select {
	case ch <- s:
	default:
	}
}

// StartCoreWLANSSIDMonitor subscribes to CoreWLAN SSID/link change events
// and returns a channel emitting the new SSID (or "" when disconnected)
// for each event. Returns an error if the Obj-C subscription fails — in
// that case the caller should fall back to polling via CurrentSSID().
//
// Calling this more than once without an intervening Stop is a no-op
// (returns the existing channel). Buffer size 16 — far more than enough
// for realistic SSID churn; extras are dropped to keep the delegate
// callback non-blocking.
func StartCoreWLANSSIDMonitor() (<-chan string, error) {
	ssidEventMu.Lock()
	if ssidEventCh != nil {
		ch := ssidEventCh
		ssidEventMu.Unlock()
		return ch, nil
	}
	ch := make(chan string, 16)
	ssidEventCh = ch
	ssidEventMu.Unlock()

	rc := C.cwStartSSIDMonitor()
	if rc != 0 {
		ssidEventMu.Lock()
		ssidEventCh = nil
		ssidEventMu.Unlock()
		return nil, fmt.Errorf("cwStartSSIDMonitor failed (rc=%d)", int(rc))
	}
	return ch, nil
}

// StopCoreWLANSSIDMonitor tears down the subscription. Safe to call when
// the monitor was never started.
func StopCoreWLANSSIDMonitor() {
	ssidEventMu.Lock()
	ch := ssidEventCh
	ssidEventCh = nil
	ssidEventMu.Unlock()
	if ch == nil {
		return
	}
	C.cwStopSSIDMonitor()
	// Don't close ch — a delegate callback racing teardown could still
	// be in flight (we check ssidEventCh==nil but the read+send isn't
	// atomic). Letting the channel be GC'd is safer than risking
	// "send on closed channel" from a stale Obj-C dispatch.
}
