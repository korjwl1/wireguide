package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestSocketBindMonitorRetriesFailedUnchangedIndex(t *testing.T) {
	b, base, ep := newTestGuardedBind(t)
	_ = b.BindSocketToInterface4(7, false)
	m := &socketBindMonitor{binder: b, resolve: func(ipv6 bool) uint32 {
		if ipv6 {
			return 0
		}
		return 7
	}, last: [2]uint32{7, 0}}
	base.fail4.Store(true)
	m.reevaluate()
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 0 {
		t.Fatal("failed rebind did not close the send gate")
	}
	base.fail4.Store(false)
	m.reevaluate()
	_ = b.Send([][]byte{{1}}, ep)
	if base.sent.Load() != 1 {
		t.Fatal("unchanged interface index prevented recovery")
	}
}

func TestSocketBindMonitorPollsWithoutNotificationsAndStops(t *testing.T) {
	b, base, _ := newTestGuardedBind(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checked := make(chan struct{}, 1)
	done := make(chan struct{})
	m := &socketBindMonitor{binder: b, kick: make(chan struct{}, 1), resolve: func(bool) uint32 {
		select {
		case checked <- struct{}{}:
		default:
		}
		return 7
	}}
	go m.run(ctx, time.Millisecond, func() { close(done) })
	select {
	case <-checked:
	case <-time.After(time.Second):
		t.Fatal("no periodic fallback")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop")
	}
	if base.calls.Load() == 0 {
		t.Fatal("monitor never applied socket protection")
	}
}
