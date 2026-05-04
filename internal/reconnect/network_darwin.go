//go:build darwin

package reconnect

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation

#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>

// fetchPrimaryInterface reads State:/Network/Global/IPv4 from the
// SCDynamicStore and copies the PrimaryInterface name into the
// caller's buffer. Returns 1 on success, 0 if the key is missing or
// truncation occurred. This is the canonical way macOS networking
// code answers "which interface is currently the default route?":
// Wi-Fi → Ethernet handovers and Ethernet plug/unplug both change
// this value, while a wildcard SCNetworkReachability target reports
// the same "reachable" flag for any non-zero set of active interfaces.
static int fetchPrimaryInterface(char *out, int out_len) {
    SCDynamicStoreRef store = SCDynamicStoreCreate(NULL,
        CFSTR("io.github.korjwl1.wireguide.netmon"), NULL, NULL);
    if (store == NULL) {
        return 0;
    }
    CFTypeRef value = SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/IPv4"));
    CFRelease(store);
    if (value == NULL) {
        // No IPv4 default route configured at all.
        if (out_len > 0) {
            out[0] = '\0';
        }
        return 1;
    }
    if (CFGetTypeID(value) != CFDictionaryGetTypeID()) {
        CFRelease(value);
        return 0;
    }
    CFStringRef iface = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)value,
        CFSTR("PrimaryInterface"));
    int ok = 0;
    if (iface != NULL && CFGetTypeID(iface) == CFStringGetTypeID()) {
        ok = CFStringGetCString(iface, out, out_len, kCFStringEncodingUTF8) ? 1 : 0;
    } else {
        if (out_len > 0) {
            out[0] = '\0';
        }
        ok = 1;
    }
    CFRelease(value);
    return ok;
}
*/
import "C"

import (
	"log/slog"
	"sync"
	"time"
	"unsafe"
)

// darwinNetworkChangeDetector polls the SCDynamicStore once per
// second for the system's PrimaryInterface and fires when it changes.
//
// We chose primary-interface tracking over SCNetworkReachability for
// two reasons:
//
//  1. SCNetworkReachability against the wildcard 0.0.0.0 target
//     answers "is any interface up?", not "did the default route
//     change?". Empirically, Ethernet plug/unplug while Wi-Fi is up
//     keeps the wildcard target's flags constant at "reachable",
//     missing exactly the transitions we care about for reconnect.
//
//  2. Primary-interface changes are exactly the events that require
//     WireGuard to rebind its source endpoint. Tracking that signal
//     directly avoids spurious reconnects when, e.g., a
//     non-default-route interface flaps.
//
// We use polling rather than the SCDynamicStore notification callback
// because the callback API requires CFRunLoopRun, which combined with
// LockOSThread + cross-thread CFRunLoopStop ran into reproducible
// hangs in tests. Polling once per second is cheap (~one syscall) and
// gives a 1-second worst-case detection latency, which is well within
// our reconnect-window budget.
type darwinNetworkChangeDetector struct {
	mu       sync.Mutex
	changeCh chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
}

const networkPollInterval = 1 * time.Second

func NewNetworkChangeDetector() NetworkChangeDetector {
	return &darwinNetworkChangeDetector{
		changeCh: make(chan struct{}, 1),
	}
}

func (d *darwinNetworkChangeDetector) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.stopCh = make(chan struct{})
	d.mu.Unlock()

	d.wg.Add(1)
	go d.poll()
}

func (d *darwinNetworkChangeDetector) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	close(d.stopCh)
	d.mu.Unlock()
	d.wg.Wait()
}

func (d *darwinNetworkChangeDetector) ChangeChan() <-chan struct{} {
	return d.changeCh
}

func (d *darwinNetworkChangeDetector) sendChange() {
	select {
	case d.changeCh <- struct{}{}:
	default:
	}
}

// fetchPrimaryInterface returns the current PrimaryInterface name,
// or an empty string if none is configured. Returns ok=false on
// API failure (logged once by the caller).
func fetchPrimaryInterface() (string, bool) {
	const bufLen = 64 // BSD interface names are at most ~16 chars
	buf := make([]byte, bufLen)
	if C.fetchPrimaryInterface((*C.char)(unsafe.Pointer(&buf[0])), C.int(bufLen)) == 0 {
		return "", false
	}
	// Find the null terminator written by CFStringGetCString.
	n := 0
	for n < bufLen && buf[n] != 0 {
		n++
	}
	return string(buf[:n]), true
}

// fireCooldown is the minimum interval between two sendChange()
// calls. Without it, a rapid Wi-Fi flap (none→en0→none in <2s when
// the user briefly toggles Wi-Fi) fires two reconnect cycles whose
// backoffs pile up. With it, the second transition is logged as
// "suppressed" and only the next stable change after the cooldown
// triggers a fresh reconnect.
const fireCooldown = 2 * time.Second

func (d *darwinNetworkChangeDetector) poll() {
	defer d.wg.Done()

	slog.Info("network change detector started", "poll_interval", networkPollInterval)

	ticker := time.NewTicker(networkPollInterval)
	defer ticker.Stop()

	var lastIface string
	var hasInitial bool
	var heartbeat int
	var lastFire time.Time

	for {
		select {
		case <-d.stopCh:
			slog.Info("network change detector stopped")
			return
		case <-ticker.C:
			iface, ok := fetchPrimaryInterface()
			if !ok {
				slog.Warn("SCDynamicStoreCopyValue failed")
				continue
			}
			if !hasInitial {
				hasInitial = true
				lastIface = iface
				slog.Info("network primary interface initial", "iface", iface)
				continue
			}
			heartbeat++
			if heartbeat%30 == 0 {
				slog.Debug("network polling heartbeat", "iface", iface)
			}
			if iface == lastIface {
				continue
			}
			prev := lastIface
			lastIface = iface

			if !lastFire.IsZero() && time.Since(lastFire) < fireCooldown {
				slog.Info("network primary interface changed (suppressed by cooldown)",
					"prev", prev, "now", iface,
					"since_last_fire", time.Since(lastFire).Round(time.Millisecond))
				continue
			}

			lastFire = time.Now()
			slog.Info("network primary interface changed",
				"prev", prev, "now", iface)
			d.sendChange()
		}
	}
}
