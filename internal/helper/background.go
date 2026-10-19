package helper

import (
	"fmt"
	"log/slog"
	"math/rand"
	"runtime/debug"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// goSafe restarts a panicked background loop within a bounded budget, logging
// its stack. Normal return stops the loop. Exhaustion emits a critical event so
// the GUI can show which subsystem needs a helper restart.
func (h *Helper) goSafe(name string, fn func()) {
	const maxRestarts = 5
	go func() {
		var lastPanic string
		for attempt := 0; attempt <= maxRestarts; attempt++ {
			panicked := true
			func() {
				defer func() {
					if r := recover(); r != nil {
						lastPanic = fmt.Sprintf("%v", r)
						slog.Error("goroutine panic (will restart)",
							"where", name,
							"panic", lastPanic,
							"stack", string(debug.Stack()),
							"attempt", attempt+1,
							"max", maxRestarts+1)
					}
				}()
				fn()
				panicked = false
			}()
			if !panicked {
				return // fn returned normally — done.
			}
			// Stagger restarts when several loops fail on the same dependency.
			jitter := time.Duration(rand.Intn(1000)) * time.Millisecond //nolint:gosec // G404: jitter, not security
			time.Sleep(500*time.Millisecond + jitter)
		}
		slog.Error("goroutine exceeded max restarts, giving up", "where", name)
		if h != nil && h.server != nil {
			h.server.Broadcast(ipc.EventCriticalError, ipc.CriticalErrorPayload{
				Where:  name,
				Detail: "exceeded restart budget; last panic: " + lastPanic,
			})
		}
	}()
}
