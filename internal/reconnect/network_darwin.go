//go:build darwin

package reconnect

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>

static int primaryInterfaceFromValue(CFTypeRef value, char *out, int out_len) {
    if (out_len <= 0) return 0;
    out[0] = '\0';
    if (value == NULL) return 1;
    if (CFGetTypeID(value) != CFDictionaryGetTypeID()) return 0;
    CFTypeRef iface = CFDictionaryGetValue((CFDictionaryRef)value, CFSTR("PrimaryInterface"));
    if (iface == NULL || CFGetTypeID(iface) != CFStringGetTypeID()) return 1;
    return CFStringGetCString((CFStringRef)iface, out, out_len, kCFStringEncodingUTF8) ? 1 : 0;
}

static int fetchPrimaryInterfaces(char *out4, int len4, char *out6, int len6, int *ok6) {
    *ok6 = 0;
    SCDynamicStoreRef store = SCDynamicStoreCreate(NULL,
        CFSTR("io.github.korjwl1.wireguide.netmon"), NULL, NULL);
    if (store == NULL) return 0;
    const void *keys[] = { CFSTR("State:/Network/Global/IPv4"), CFSTR("State:/Network/Global/IPv6") };
    CFArrayRef wanted = CFArrayCreate(NULL, keys, 2, &kCFTypeArrayCallBacks);
    if (wanted == NULL) {
        CFRelease(store);
        return 0;
    }
    CFDictionaryRef snapshot = SCDynamicStoreCopyMultiple(store, wanted, NULL);
    CFRelease(wanted);
    CFRelease(store);
    if (snapshot == NULL) return 0;
    int ok4 = primaryInterfaceFromValue(CFDictionaryGetValue(snapshot, keys[0]), out4, len4);
    *ok6 = primaryInterfaceFromValue(CFDictionaryGetValue(snapshot, keys[1]), out6, len6);
    CFRelease(snapshot);
    return ok4;
}
*/
import "C"

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
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
	// offline is set by poll (never under mu: Stop holds mu across the
	// poller's exit) when the last successful read found no primary
	// IPv4 or IPv6 interface (see onlineFromPrimaries). False until the
	// first read, so the detector reports online until it knows otherwise.
	offline atomic.Bool
}

// Online reports whether a primary network interface exists (see
// OnlineReporter). True until the first poll has completed.
func (d *darwinNetworkChangeDetector) Online() bool {
	return !d.offline.Load()
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
	// wg.Add MUST be inside the lock. Per sync.WaitGroup docs: "calls
	// with a positive delta that occur when the counter is zero must
	// happen before a Wait". If Stop() races past the running guard
	// and reaches wg.Wait() before Start's Add(1) lands, the Wait
	// returns immediately and the subsequent Add(1) is a use-after-
	// release. Adding inside the lock makes Stop()'s "if !running"
	// branch the only path that can observe a zero counter — and
	// that branch returns without waiting.
	d.wg.Add(1)
	d.mu.Unlock()

	go d.poll()
}

func (d *darwinNetworkChangeDetector) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running {
		return
	}
	close(d.stopCh)
	// poll does not acquire mu. Keep Start out until the old poller exits,
	// so it cannot replace stopCh or Add to the WaitGroup during this Wait.
	d.wg.Wait()
	d.running = false
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
func fetchPrimaryInterfaces() (iface4, iface6 string, ok4, ok6 bool) {
	var buf4, buf6 [64]C.char
	var rc6 C.int
	rc4 := C.fetchPrimaryInterfaces(&buf4[0], C.int(len(buf4)), &buf6[0], C.int(len(buf6)), &rc6)
	if rc4 != 0 {
		iface4, ok4 = C.GoString(&buf4[0]), true
	}
	if rc6 != 0 {
		iface6, ok6 = C.GoString(&buf6[0]), true
	}
	return
}

const fireCooldown = 2 * time.Second

func (d *darwinNetworkChangeDetector) poll() {
	defer d.wg.Done()

	slog.Info("network change detector started", "poll_interval", networkPollInterval)

	ticker := time.NewTicker(networkPollInterval)
	defer ticker.Stop()

	gate := interfaceChangeGate{cooldown: fireCooldown}
	var heartbeat int

	for {
		select {
		case <-d.stopCh:
			slog.Info("network change detector stopped")
			return
		case <-ticker.C:
			iface, iface6, ok, ok6 := fetchPrimaryInterfaces()
			if !ok {
				slog.Warn("SCDynamicStoreCopyValue failed")
				continue
			}
			d.offline.Store(!onlineFromPrimaries(iface, iface6, ok6))
			if !gate.initialized {
				gate.observe(iface, time.Now())
				slog.Info("network primary interface initial", "iface", iface)
				continue
			}
			heartbeat++
			if heartbeat%30 == 0 {
				slog.Debug("network polling heartbeat", "iface", iface)
			}
			previous := gate.deliveredIface
			if !gate.observe(iface, time.Now()) {
				continue
			}
			gate.deliveredIface = iface
			slog.Info("network primary interface changed", "prev", previous, "now", iface)
			d.sendChange()
		}
	}
}
