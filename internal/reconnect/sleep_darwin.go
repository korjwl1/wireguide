//go:build darwin

package reconnect

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation

#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

extern void goWakeCallback(void *ctx);

// wake_monitor_t holds the IOKit handles + run loop captured for shutdown.
typedef struct {
    io_connect_t          root_port;
    IONotificationPortRef notify_port;
    io_object_t           notifier;
    CFRunLoopRef          run_loop;
    void                 *handle;
} wake_monitor_t;

// wakeMonitorCallback is invoked by IOKit on power state transitions.
// IOKit IPC works in any bootstrap context (system or user) — unlike
// NSWorkspace, it reaches root LaunchDaemons.
static void wakeMonitorCallback(void *refcon, io_service_t service,
                                natural_t messageType, void *messageArgument) {
    wake_monitor_t *m = (wake_monitor_t *)refcon;
    switch (messageType) {
        case kIOMessageSystemWillSleep:
        case kIOMessageCanSystemSleep:
            // Must acknowledge or macOS forces sleep after a 30s timeout —
            // delaying every sleep transition unnecessarily.
            IOAllowPowerChange(m->root_port, (long)messageArgument);
            break;
        case kIOMessageSystemHasPoweredOn:
            // System fully woken; networking is up. Trigger reconnect.
            goWakeCallback(m->handle);
            break;
    }
}

// startWakeMonitor registers IOKit power notifications on the calling
// thread and adds the source to that thread's run loop. Caller must
// then invoke runWakeMonitor() to enter the loop. Returns NULL if
// registration fails (e.g. sandboxing prevents IORegisterForSystemPower).
static wake_monitor_t* startWakeMonitor(void *handle) {
    wake_monitor_t *m = (wake_monitor_t *)calloc(1, sizeof(wake_monitor_t));
    if (m == NULL) {
        return NULL;
    }
    m->handle = handle;

    m->root_port = IORegisterForSystemPower(m, &m->notify_port,
                                            wakeMonitorCallback, &m->notifier);
    if (m->root_port == MACH_PORT_NULL) {
        free(m);
        return NULL;
    }

    m->run_loop = CFRunLoopGetCurrent();
    CFRunLoopAddSource(m->run_loop,
                       IONotificationPortGetRunLoopSource(m->notify_port),
                       kCFRunLoopCommonModes);
    return m;
}

// runWakeMonitor blocks until stopWakeMonitor causes CFRunLoopStop.
static void runWakeMonitor(wake_monitor_t *m) {
    (void)m;
    CFRunLoopRun();
}

// stopWakeMonitor signals the run loop to exit. Safe to call from any
// thread. The freeing happens on the run-loop thread after exit.
static void stopWakeMonitor(wake_monitor_t *m) {
    if (m == NULL || m->run_loop == NULL) {
        return;
    }
    CFRunLoopStop(m->run_loop);
}

// freeWakeMonitor releases IOKit resources. Must be called from the
// same thread that ran the run loop, after runWakeMonitor returned.
static void freeWakeMonitor(wake_monitor_t *m) {
    if (m == NULL) {
        return;
    }
    IODeregisterForSystemPower(&m->notifier);
    IOServiceClose(m->root_port);
    IONotificationPortDestroy(m->notify_port);
    free(m);
}
*/
import "C"

import (
	"log/slog"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// darwinSleepDetector detects sleep/wake on macOS using two mechanisms:
//  1. IOKit IORegisterForSystemPower — primary path. Apple QA1340 documents
//     this as the only wake API that reaches root LaunchDaemons (NSWorkspace
//     distributed notifications never cross the user→system bootstrap
//     namespace boundary, so they were silently dead in our prior helper).
//  2. Wall-clock polling — fallback that catches wake events if IOKit
//     registration fails (sandboxing, kernel quirk) or the callback is lost.
type darwinSleepDetector struct {
	mu         sync.Mutex
	wakeCh     chan struct{}
	stopCh     chan struct{}
	monitor    *C.wake_monitor_t
	handle     uintptr
	threadDone chan struct{}
}

func NewSleepDetector() SleepDetector {
	return &darwinSleepDetector{
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (d *darwinSleepDetector) Start() {
	d.mu.Lock()
	d.stopCh = make(chan struct{})
	d.threadDone = make(chan struct{})
	d.handle = registerDetector(d)
	d.mu.Unlock()

	started := make(chan struct{})

	go func() {
		// CFRunLoop is per-thread. We must lock to a single OS thread so
		// the run loop set up by startWakeMonitor is the one we then run
		// and stop. Without LockOSThread the goroutine could migrate and
		// the source we added would never be serviced.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(d.threadDone)

		ctx := *(*unsafe.Pointer)(unsafe.Pointer(&d.handle))
		m := C.startWakeMonitor(ctx)
		if m == nil {
			slog.Warn("IORegisterForSystemPower failed — relying on polling fallback for wake detection")
			close(started)
			return
		}

		d.mu.Lock()
		d.monitor = m
		d.mu.Unlock()
		close(started)

		// Blocks until Stop() → CFRunLoopStop.
		C.runWakeMonitor(m)
		C.freeWakeMonitor(m)
	}()

	<-started

	// Polling fallback (safety net — runs alongside IOKit, so a missed
	// IOKit wake event still gets caught).
	go d.poll()
}

func (d *darwinSleepDetector) Stop() {
	d.mu.Lock()
	select {
	case <-d.stopCh:
		d.mu.Unlock()
		return
	default:
		close(d.stopCh)
	}
	m := d.monitor
	d.monitor = nil
	threadDone := d.threadDone
	handle := d.handle
	d.handle = 0
	d.mu.Unlock()

	if m != nil {
		C.stopWakeMonitor(m)
	}
	if threadDone != nil {
		<-threadDone
	}
	if handle != 0 {
		unregisterDetector(handle)
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
	slog.Info("sleep/wake detected via IOKit notification")
	d.sendWake()
}
