//go:build !darwin

package reconnect

// noopNetworkChangeDetector is the placeholder for non-macOS builds.
// On Linux/Windows, route-monitor logic in internal/network/* and the
// existing wake-on-resume path cover the common cases for today.
type noopNetworkChangeDetector struct{}

// neverFires is closed-but-never-sent-on, so listeners select on it
// safely without ever waking up.
var neverFires = make(chan struct{})

func NewNetworkChangeDetector() NetworkChangeDetector {
	return &noopNetworkChangeDetector{}
}

func (d *noopNetworkChangeDetector) Start()                         {}
func (d *noopNetworkChangeDetector) Stop()                          {}
func (d *noopNetworkChangeDetector) ChangeChan() <-chan struct{}    { return neverFires }
