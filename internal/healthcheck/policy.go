package healthcheck

import (
	"reflect"
	"time"
)

// State belongs to one tunnel and is accessed only by the health loop.
// Cooldown survives reconnection so a persistently unreachable target cannot
// continuously churn the tunnel. Any successful target resets the failure run.
type State struct {
	config   Config
	session  time.Time
	next     time.Time
	failures int
	cooldown time.Time
}

func (s *State) Due(now, connectedAt time.Time, config Config) bool {
	if !reflect.DeepEqual(s.config, config) || !s.session.Equal(connectedAt) {
		s.config = config
		s.session = connectedAt
		s.failures = 0
		s.next = now.Add(time.Duration(config.IntervalSeconds) * time.Second)
	}
	return config.Enabled && !now.Before(s.next) && !now.Before(s.cooldown)
}

// Observe consumes a complete round. Canceled or invalidated rounds must not
// be passed here. The caller rechecks the tunnel session before reconnecting.
func (s *State) Observe(now time.Time, anyReachable bool) bool {
	s.next = now.Add(time.Duration(s.config.IntervalSeconds) * time.Second)
	if anyReachable {
		s.failures = 0
		return false
	}
	s.failures++
	if s.failures < s.config.FailureThreshold {
		return false
	}
	s.failures = 0
	s.cooldown = now.Add(60 * time.Second)
	return true
}
