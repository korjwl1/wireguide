package tunnel

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoopWatchdogOnlyTripsOnVerifiedRouteLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	var reasons []string
	loopWatchdogPoll(ctx, time.Millisecond, func() (string, error) {
		calls++
		switch calls {
		case 1:
			return "", errors.New("temporary route query failure")
		case 2:
			return "", nil // healthy route, independent of traffic rate
		default:
			return "endpoint 203.0.113.7 routes through utun42", nil
		}
	}, func(reason string) { reasons = append(reasons, reason) })
	if calls != 3 || len(reasons) != 1 || !strings.Contains(reasons[0], "203.0.113.7") {
		t.Fatalf("calls=%d trips=%v", calls, reasons)
	}
}

func TestLoopWatchdogIgnoresResultAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	tripped := false
	go func() {
		defer close(done)
		loopWatchdogPoll(ctx, time.Millisecond, func() (string, error) { close(started); <-release; return "stale route loop", nil }, func(string) { tripped = true })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not stop")
	}
	if tripped {
		t.Fatal("cancelled watchdog tore down a replaced session")
	}
}

func TestEndpointIPsFromUAPITracksLiveIPv4AndIPv6(t *testing.T) {
	state := "endpoint=203.0.113.7:51820\nendpoint=[2001:db8::7]:12345\nendpoint=203.0.113.7:54321\nendpoint=example.com:1234\nendpoint=bad\n"
	got := endpointIPsFromUAPI(state)
	if !slices.Equal(got, []string{"203.0.113.7", "2001:db8::7"}) {
		t.Fatalf("live endpoints = %v", got)
	}
}
