//go:build darwin

package reconnect

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>

// C callback type — invoked from the Objective-C notification observer.
extern void goWakeCallback(void *ctx);

// Registers an NSWorkspace didWakeNotification observer. Returns an opaque
// handle (the observer object pointer) so we can unregister later.
static void* registerWakeNotification(void *ctx) {
	id observer = [[[NSWorkspace sharedWorkspace] notificationCenter]
		addObserverForName:NSWorkspaceDidWakeNotification
		object:nil
		queue:nil
		usingBlock:^(NSNotification *note) {
			goWakeCallback(ctx);
		}];
	return (void *)observer;
}

// Unregisters a previously registered observer.
static void unregisterWakeNotification(void *observer) {
	if (observer == NULL) return;
	id obs = (id)observer;
	[[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver:obs];
}
*/
import "C"

import (
	"log/slog"
	"sync"
	"time"
	"unsafe"
)

// darwinSleepDetector detects sleep/wake on macOS using two mechanisms:
//  1. NSWorkspace didWakeNotification via cgo — immediate notification on wake.
//  2. Wall-clock polling as fallback — catches wake events if the notification
//     doesn't fire (e.g. if the NSRunLoop isn't pumped in this process).
type darwinSleepDetector struct {
	mu       sync.Mutex
	wakeCh   chan struct{}
	stopCh   chan struct{}
	observer unsafe.Pointer // opaque NSObject observer handle
	handle   uintptr        // numeric handle for cgo callback lookup
}

func NewSleepDetector() SleepDetector {
	return &darwinSleepDetector{
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (d *darwinSleepDetector) Start() {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Reinitialize stopCh so the detector is reusable after Stop().
	d.stopCh = make(chan struct{})

	// Register in the lookup table and pass the numeric handle to C.
	// We use a uintptr handle (cast to void*) instead of a Go pointer,
	// which satisfies cgo's pointer-passing rules.
	d.handle = registerDetector(d)
	// The handle is a small integer (not a Go pointer), so casting it to
	// unsafe.Pointer for the C call is safe — it's an opaque token the C
	// side passes back to goWakeCallback unchanged.
	//nolint:govet // uintptr->unsafe.Pointer is intentional: handle is not a Go pointer
	ctx := *(*unsafe.Pointer)(unsafe.Pointer(&d.handle))
	d.observer = C.registerWakeNotification(ctx)

	// Start polling fallback.
	go d.poll()
}

func (d *darwinSleepDetector) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopCh:
		// Already closed; nothing to do.
	default:
		close(d.stopCh)
	}
	if d.observer != nil {
		C.unregisterWakeNotification(d.observer)
		d.observer = nil
	}
	if d.handle != 0 {
		unregisterDetector(d.handle)
		d.handle = 0
	}
}

func (d *darwinSleepDetector) WakeChan() <-chan struct{} {
	return d.wakeCh
}

// sendWake sends a wake event to the channel (non-blocking).
func (d *darwinSleepDetector) sendWake() {
	select {
	case d.wakeCh <- struct{}{}:
	default:
	}
}

func (d *darwinSleepDetector) poll() {
	// Fallback: detect sleep by checking if wall clock advanced much more than
	// expected between iterations.
	lastCheck := time.Now()
	const pollInterval = 10 * time.Second
	const sleepThreshold = 30 * time.Second // if 30s+ gap, assume sleep

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastCheck)
			lastCheck = now

			if elapsed > pollInterval+sleepThreshold {
				slog.Info("sleep/wake detected via polling fallback",
					"expected", pollInterval,
					"actual", elapsed.Round(time.Second))
				d.sendWake()
			}
		}
	}
}

// wakeDetectors maps numeric handles to their darwinSleepDetector. Numeric
// handles (uintptr cast to void*) are used instead of Go pointers to satisfy
// cgo's pointer-passing rules.
var (
	wakeDetectorsMu  sync.Mutex
	wakeDetectors    = make(map[uintptr]*darwinSleepDetector)
	wakeDetectorNext uintptr
)

func registerDetector(d *darwinSleepDetector) uintptr {
	wakeDetectorsMu.Lock()
	wakeDetectorNext++
	h := wakeDetectorNext
	wakeDetectors[h] = d
	wakeDetectorsMu.Unlock()
	return h
}

func unregisterDetector(h uintptr) {
	wakeDetectorsMu.Lock()
	delete(wakeDetectors, h)
	wakeDetectorsMu.Unlock()
}

//export goWakeCallback
func goWakeCallback(ctx unsafe.Pointer) {
	h := uintptr(ctx)
	wakeDetectorsMu.Lock()
	d, ok := wakeDetectors[h]
	wakeDetectorsMu.Unlock()
	if !ok {
		return
	}
	slog.Info("sleep/wake detected via NSWorkspace notification")
	d.sendWake()
}

