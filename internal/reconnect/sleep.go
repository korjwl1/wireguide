package reconnect

// SleepDetector detects system sleep/wake events.
type SleepDetector interface {
	Start()
	Stop()
	WakeChan() <-chan struct{}
}
