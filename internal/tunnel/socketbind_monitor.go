package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	socketBindDebounce     = 150 * time.Millisecond
	socketBindBurstEscape  = 2 * time.Second
	socketBindPollInterval = 5 * time.Second
)

type socketBindMonitor struct {
	binder  conn.BindSocketToInterface
	resolve func(ipv6 bool) uint32
	kick    chan struct{}
	last    [2]uint32 // owned by the monitor goroutine
}

func bindSocketFamily(binder conn.BindSocketToInterface, resolve func(bool) uint32, ipv6 bool) (uint32, error) {
	index := resolve(ipv6)
	var err error
	if ipv6 {
		err = binder.BindSocketToInterface6(index, index == 0)
	} else {
		err = binder.BindSocketToInterface4(index, index == 0)
	}
	if err != nil {
		return 0, fmt.Errorf("bind socket (IPv6=%t, interface=%d): %w", ipv6, index, err)
	}
	return index, nil
}

func (m *socketBindMonitor) reevaluate() {
	for family := range m.last {
		// Reapply even when the index is unchanged: a prior binding may
		// have failed, or WireGuard may have reopened its UDP sockets.
		index, err := bindSocketFamily(m.binder, m.resolve, family == 1)
		if err != nil {
			slog.Warn("socket binding failed; guarded sends remain blocked until retry", "error", err)
			continue
		}
		if m.last[family] != index {
			slog.Info("WireGuard socket underlay changed", "ipv6", family == 1, "interface", index)
			m.last[family] = index
		}
	}
}

// All rebinding happens on this goroutine. Notifications never execute
// setsockopt themselves, so timer callbacks cannot overlap a rebind or stop.
func (m *socketBindMonitor) run(ctx context.Context, pollInterval time.Duration, unregister func()) {
	defer unregister()
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	defer debounce.Stop()
	var firstBurst time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
			if firstBurst.IsZero() {
				firstBurst = time.Now()
			}
			delay := socketBindDebounce
			if time.Since(firstBurst) >= socketBindBurstEscape {
				delay = 0
			}
			debounce.Reset(delay)
		case <-debounce.C:
			firstBurst = time.Time{}
			if ctx.Err() == nil {
				m.reevaluate()
			}
		case <-poll.C:
			if ctx.Err() == nil {
				m.reevaluate()
			}
		}
	}
}
