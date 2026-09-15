package healthcheck

import (
	"context"
	"time"
)

type ProbeFunc func(context.Context, string, string) error

// Check tests targets concurrently within one timeout. One valid reply is
// sufficient. Cancellation of the owning loop is never recorded as failure.
func Check(ctx context.Context, iface string, targets []string, probe ProbeFunc) (bool, error) {
	round, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	results := make(chan bool, len(targets))
	for _, target := range targets {
		go func(target string) { results <- probe(round, iface, target) == nil }(target)
	}
	reachable := false
	for range targets {
		if <-results {
			reachable = true
			cancel()
		}
	}
	return reachable, ctx.Err()
}
