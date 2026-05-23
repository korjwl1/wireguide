//go:build windows

package reconnect

import (
	"log/slog"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsSleepDetector uses PowerRegisterSuspendResumeNotification to get an
// instant signal on wake. The previous wall-clock-gap heuristic had up to
// 40s detection latency, which felt broken to users opening their laptop
// and watching the tunnel stay dead.
//
// Falls back to wall-clock polling if the notification can't be registered
// (older Windows, restricted token, etc.).
type windowsSleepDetector struct {
	mu                 sync.Mutex
	running            bool
	wakeCh             chan struct{}
	stopCh             chan struct{}
	notifyHandle       uintptr
	callbackTrampoline uintptr
}

func NewSleepDetector() SleepDetector {
	return &windowsSleepDetector{}
}

var (
	modPowrprof = windows.NewLazySystemDLL("powrprof.dll")

	procPowerRegisterSuspendResumeNotification   = modPowrprof.NewProc("PowerRegisterSuspendResumeNotification")
	procPowerUnregisterSuspendResumeNotification = modPowrprof.NewProc("PowerUnregisterSuspendResumeNotification")
)

const (
	// DEVICE_NOTIFY_CALLBACK = 2 — recipient is a struct with a callback pointer.
	deviceNotifyCallback = 2

	// PBT_APMSUSPEND = 4, PBT_APMRESUMEAUTOMATIC = 18, PBT_APMRESUMESUSPEND = 7.
	// We treat anything but APMSUSPEND as a wake signal, since some systems
	// only fire RESUMEAUTOMATIC (no UI session) on a lid-open.
	pbtApmSuspend = 4
)

// deviceNotifySubscribeParams matches DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS:
//
//	typedef struct _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
//	  PDEVICE_NOTIFY_CALLBACK_ROUTINE Callback;
//	  PVOID                            Context;
//	} DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS;
type deviceNotifySubscribeParams struct {
	Callback uintptr
	Context  uintptr
}

func (d *windowsSleepDetector) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.wakeCh = make(chan struct{}, 1)
	d.stopCh = make(chan struct{})
	d.mu.Unlock()

	cb := syscall.NewCallback(func(_ uintptr, eventType uintptr, _ uintptr) uintptr {
		if eventType == pbtApmSuspend {
			slog.Info("PBT_APMSUSPEND (about to suspend)")
			return 0
		}
		slog.Info("power resume notification received", "event", eventType)
		d.mu.Lock()
		ch := d.wakeCh
		d.mu.Unlock()
		if ch == nil {
			return 0
		}
		select {
		case ch <- struct{}{}:
		default:
		}
		return 0
	})

	params := deviceNotifySubscribeParams{
		Callback: cb,
		Context:  0,
	}

	var handle uintptr
	ret, _, _ := procPowerRegisterSuspendResumeNotification.Call(
		uintptr(deviceNotifyCallback),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		slog.Warn("PowerRegisterSuspendResumeNotification failed, falling back to poll",
			"status", ret)
		go d.poll()
		return
	}
	d.mu.Lock()
	d.notifyHandle = handle
	d.callbackTrampoline = cb // keep alive
	d.mu.Unlock()
	slog.Info("Windows sleep/resume notification registered")
}

func (d *windowsSleepDetector) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	stop := d.stopCh
	handle := d.notifyHandle
	d.notifyHandle = 0
	d.mu.Unlock()
	select {
	case <-stop:
	default:
		close(stop)
	}
	if handle != 0 {
		procPowerUnregisterSuspendResumeNotification.Call(handle)
	}
}

func (d *windowsSleepDetector) WakeChan() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.wakeCh
}

// poll is the legacy wall-clock fallback. Kept for environments where
// PowerRegisterSuspendResumeNotification fails (unusual but documented on
// some Server SKUs that strip user32-adjacent APIs from system accounts).
func (d *windowsSleepDetector) poll() {
	lastCheck := time.Now()
	const pollInterval = 10 * time.Second
	const sleepThreshold = 30 * time.Second

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
				slog.Info("sleep/wake detected via wall-clock gap", "elapsed", elapsed.Round(time.Second))
				d.mu.Lock()
				ch := d.wakeCh
				d.mu.Unlock()
				if ch == nil {
					continue
				}
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}
