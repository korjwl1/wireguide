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

// linkChangeMaxDebounce coalesces NotifyIpInterfaceChange callback storms.
// One Wi-Fi handover can fire 6-10 callbacks within 100ms (link down →
// addr remove → link up → addr add → metric change → ...). Without a
// debounce the reconnect monitor would queue a flurry of identical
// triggers.
const linkChangeMaxDebounce = 500 * time.Millisecond

// windowsNetworkChangeDetector registers an iphlpapi callback for IP
// interface changes and forwards a coalesced signal to ChangeChan.
//
// NotifyIpInterfaceChange fires on:
//   - Adapter add/remove
//   - Link state transitions (cable plug, Wi-Fi associate)
//   - IP address bind/unbind
//   - Metric changes
//
// All four cases mean "the path the user takes to the Internet may have
// changed" → trigger a reconnect.
//
// Signal flow: kernel callback → rawCh (cap 16, non-blocking) → debouncer
// goroutine coalesces a burst → ChangeChan (cap 1). External consumers
// read ChangeChan and see one signal per ~500ms quiet window even if the
// kernel fired hundreds of callbacks during the storm.
type windowsNetworkChangeDetector struct {
	mu      sync.Mutex
	running bool

	notifyHandle windows.Handle
	rawCh        chan struct{}
	changeCh     chan struct{}
	stopCh       chan struct{}
	// Keep the callback alive — Go's GC would otherwise collect it
	// once Start returns, and the iphlpapi callback would crash with
	// an access violation on the next interface change.
	callbackTrampoline uintptr
}

func NewNetworkChangeDetector() NetworkChangeDetector {
	return &windowsNetworkChangeDetector{}
}

var (
	modIphlpapi                       = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange       = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2        = modIphlpapi.NewProc("CancelMibChangeNotify2")
)

const (
	afUnspec = 0
)

func (d *windowsNetworkChangeDetector) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.rawCh = make(chan struct{}, 16)
	d.changeCh = make(chan struct{}, 1)
	d.stopCh = make(chan struct{})
	d.mu.Unlock()

	// Kernel callback. The IO completion thread invokes this; per
	// Microsoft docs the callback "should not perform any blocking
	// operations". We just push to rawCh non-blockingly. The actual
	// debounce work happens in a Go goroutine where blocking is fine.
	cb := syscall.NewCallback(func(_ uintptr, _ uintptr, _ uintptr) uintptr {
		d.mu.Lock()
		ch := d.rawCh
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
	d.mu.Lock()
	d.callbackTrampoline = cb
	d.mu.Unlock()

	var handle windows.Handle
	ret, _, _ := procNotifyIpInterfaceChange.Call(
		uintptr(afUnspec), // AF_UNSPEC — both IPv4 and IPv6
		cb,                // callback
		0,                 // CallerContext
		0,                 // InitialNotification = FALSE
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		slog.Warn("NotifyIpInterfaceChange failed; reconnect-on-network-change disabled",
			"status", ret)
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.notifyHandle = handle
	d.mu.Unlock()
	slog.Info("Windows NotifyIpInterfaceChange detector started")

	go d.debounceLoop()
}

func (d *windowsNetworkChangeDetector) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	handle := d.notifyHandle
	d.notifyHandle = 0
	stop := d.stopCh
	d.mu.Unlock()
	if handle != 0 {
		procCancelMibChangeNotify2.Call(uintptr(handle))
	}
	select {
	case <-stop:
	default:
		close(stop)
	}
}

func (d *windowsNetworkChangeDetector) ChangeChan() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changeCh == nil {
		// Detector wasn't started — return a channel that never fires
		// so listeners block harmlessly. They'll start receiving once
		// Start() runs.
		return neverFiresCh
	}
	return d.changeCh
}

// debounceLoop reads raw callback kicks and emits one settled signal per
// ~500ms quiet window onto changeCh. This is what makes the detector
// useful — without it a Wi-Fi handover would fire the reconnect monitor
// 6-10 times in rapid succession instead of once.
func (d *windowsNetworkChangeDetector) debounceLoop() {
	for {
		// Wait for the first kick of a new burst, or stop.
		select {
		case <-d.stopCh:
			return
		case <-d.rawCh:
		}
		// Drain follow-up kicks for the settle window. Each new kick
		// resets the settle timer; once we go linkChangeMaxDebounce
		// without a kick we emit and start over.
		t := time.NewTimer(linkChangeMaxDebounce)
		settling := true
		for settling {
			select {
			case <-d.stopCh:
				t.Stop()
				return
			case <-d.rawCh:
				if !t.Stop() {
					<-t.C
				}
				t.Reset(linkChangeMaxDebounce)
			case <-t.C:
				settling = false
			}
		}
		select {
		case d.changeCh <- struct{}{}:
		default:
			// A signal is already pending; consumer hasn't drained yet.
			// Collapse into the existing one — equivalent to "edge
			// already raised".
		}
	}
}

// neverFiresCh is closed-but-never-sent-on: listeners select on it
// safely without ever waking up.
var neverFiresCh = make(chan struct{})
