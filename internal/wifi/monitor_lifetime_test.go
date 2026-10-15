package wifi

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestStopWaitsForExternalCallbackAndRejectsLaterReports(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	m := NewMonitor(func(_, _ string) { calls.Add(1); close(entered); <-release })
	go m.ReportExternalSSID("first")
	<-entered
	stopped := make(chan struct{})
	go func() { m.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned with an external callback in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop failed to finish after its callback")
	}
	m.ReportExternalSSID("later")
	if calls.Load() != 1 || m.LastSSID() != "first" {
		t.Fatal("a stopped monitor accepted a late callback")
	}
}
