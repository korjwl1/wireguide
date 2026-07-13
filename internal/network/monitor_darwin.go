//go:build darwin

package network

import (
	"bufio"
	"log/slog"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

// routeMonitor runs `route -n monitor` in the background and triggers
// re-application of endpoint bypass + DNS + MTU whenever a network change
// event (RTM_*) is received. This mirrors wg-quick's monitor_daemon.
//
// Without this, switching Wi-Fi networks or changing the default gateway
// while a full-tunnel VPN is up would leave the endpoint bypass route
// pointing at the stale gateway, breaking the tunnel.
type routeMonitor struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	stopCh  chan struct{}
	running bool
	reapply func()

	// kick is a 1-buffer signal channel. trigger() non-blocking sends
	// here; the debouncer goroutine drains and coalesces bursts. Zero
	// allocation per event (no time.AfterFunc churn on flaky networks).
	kick chan struct{}

	// pendingStart is the AfterFunc timer for a deferred Start(); set by
	// StartDelayed and cancelled by Stop() so a fast Connect→Disconnect
	// cycle doesn't fire Start() against a monitor whose caller has
	// already torn down. Without this guard, a route -n monitor
	// subprocess + its loop goroutine leak forever.
	pendingStart *time.Timer

	// pending tracks the in-flight reapply callback so Stop() can block
	// until it finishes. Without this, Stop() followed by Connect()
	// could race with a pending reapply that's still touching shared state.
	pending sync.WaitGroup

	// stopped latches once Stop() has run. It blocks any Start that is
	// still in flight (a StartDelayed AfterFunc that fired concurrently
	// with Stop, or loop()'s crash-restart) from resurrecting a monitor
	// whose owner has already torn down.
	stopped bool

	// startedAt / restarts implement the crash-restart cap in loop():
	// a subprocess that survived >1 min resets the counter; one that
	// keeps dying immediately stops being restarted after a few tries.
	startedAt time.Time
	restarts  int
}

// Only lines containing these RTM_ event types trigger a reapply. wg-quick's
// monitor_daemon reacts to the same set. Using a precise regex avoids
// spurious reapplies on informational events like RTM_NEWMADDR.
var rtmEventRegex = regexp.MustCompile(`RTM_(ADD|DELETE|CHANGE|REDIRECT|LOSING|IFINFO|NEWADDR|DELADDR)\b`)

func newRouteMonitor(reapply func()) *routeMonitor {
	return &routeMonitor{reapply: reapply}
}

// routeMonitorMgr multiplexes a single `route -n monitor` subprocess to
// many per-tunnel callbacks. With N connected tunnels each owning its
// own DarwinManager, the previous design spun up N redundant
// subprocesses receiving identical RTM_* events. This manager keeps
// exactly one subprocess for the lifetime of the FIRST → LAST tunnel.
//
// Subscribe / Unsubscribe are keyed by interface name (e.g., "utun7").
// The first Subscribe spawns the underlying routeMonitor (delayed 2s
// to skip our own route-add chatter). The last Unsubscribe stops it.
type routeMonitorMgr struct {
	mu   sync.Mutex
	subs map[string]func()
	// cachedSubs is the fan-out snapshot, invalidated on Subscribe/Unsubscribe.
	// Avoids allocating a fresh []func() on every RTM event — on a flaky
	// network the monitor can fire many times per second.
	cachedSubs []func()
	m          *routeMonitor
}

// rmMgr is the package-level singleton. Process-wide.
var rmMgr = &routeMonitorMgr{subs: make(map[string]func())}

// Subscribe registers a reapply callback under `key`. Spawns the
// underlying monitor on the first subscriber. Safe to call multiple
// times for the same key (later call wins).
func (mgr *routeMonitorMgr) Subscribe(key string, cb func()) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.subs[key] = cb
	mgr.cachedSubs = nil // invalidate
	if mgr.m == nil {
		mgr.m = newRouteMonitor(mgr.fanOut)
		mgr.m.StartDelayed(2 * time.Second)
	}
}

// Unsubscribe removes the callback for `key`. Stops the underlying
// monitor when the last subscriber leaves. Stop() is invoked OUTSIDE
// the lock so its pending.Wait() doesn't deadlock against a fanOut
// that's currently trying to acquire mgr.mu.
func (mgr *routeMonitorMgr) Unsubscribe(key string) {
	mgr.mu.Lock()
	delete(mgr.subs, key)
	mgr.cachedSubs = nil // invalidate
	var toStop *routeMonitor
	if len(mgr.subs) == 0 {
		toStop = mgr.m
		mgr.m = nil
	}
	mgr.mu.Unlock()
	if toStop != nil {
		toStop.Stop()
	}
}

// fanOut is the single reapply callback registered with the underlying
// monitor. It reuses a cached subscriber snapshot (invalidated by
// Subscribe/Unsubscribe) so RTM bursts don't allocate per event.
//
// Each subscriber's callback runs under its own panic guard so a single
// faulty DarwinManager.reapply doesn't strand the others — previously a
// panic in subscriber N silently skipped subscribers N+1..M, leaving
// half the active tunnels without reapply on a network change. The
// underlying `debounceLoop` recovers too, but only at the outermost
// level; per-callback recovery here is the per-tunnel boundary.
func (mgr *routeMonitorMgr) fanOut() {
	mgr.mu.Lock()
	if mgr.cachedSubs == nil {
		mgr.cachedSubs = make([]func(), 0, len(mgr.subs))
		for _, cb := range mgr.subs {
			mgr.cachedSubs = append(mgr.cachedSubs, cb)
		}
	}
	subs := mgr.cachedSubs
	mgr.mu.Unlock()
	for _, cb := range subs {
		func(cb func()) {
			defer func() {
				if r := recover(); r != nil {
					slog.Warn("route monitor subscriber panic recovered", "panic", r)
				}
			}()
			cb()
		}(cb)
	}
}

// StartDelayed schedules Start() to run after `d`. If Stop() is called before
// the timer fires, the scheduled Start is cancelled — this prevents a leaked
// `route -n monitor` subprocess + goroutine when the caller tears down the
// tunnel during the delay window (the original use case for the delay is to
// avoid spurious reapply from our own route-add chatter right after Connect).
func (rm *routeMonitor) StartDelayed(d time.Duration) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.running || rm.pendingStart != nil || rm.stopped {
		return
	}
	rm.pendingStart = time.AfterFunc(d, func() {
		rm.mu.Lock()
		rm.pendingStart = nil
		rm.mu.Unlock()
		rm.Start()
	})
}

// Start begins monitoring. Safe to call multiple times (no-op if already running).
func (rm *routeMonitor) Start() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.running || rm.stopped {
		return
	}

	cmd := exec.Command("route", "-n", "monitor")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slog.Warn("route monitor pipe failed", "error", err)
		return
	}
	if err := cmd.Start(); err != nil {
		slog.Warn("route monitor start failed", "error", err)
		return
	}

	rm.cmd = cmd
	rm.stopCh = make(chan struct{})
	rm.kick = make(chan struct{}, 1)
	rm.running = true
	rm.startedAt = time.Now()

	go rm.loop(stdout)
	go rm.debounceLoop()
	slog.Info("route monitor started")
}

// Stop terminates the monitor goroutine, kills the `route monitor` subprocess,
// and waits for any in-flight reapply callback to finish before returning.
// This guarantees that after Stop() returns no further reapply() calls will
// occur, so the caller can safely tear down shared state.
func (rm *routeMonitor) Stop() {
	rm.mu.Lock()
	// Latch first: any Start still in flight (a StartDelayed AfterFunc
	// that fired concurrently, or loop()'s crash-restart) must not
	// resurrect the monitor after we return.
	rm.stopped = true
	// Cancel any pending delayed Start so a fast Connect→Disconnect doesn't
	// leak a `route -n monitor` subprocess. Safe to call when nil.
	if rm.pendingStart != nil {
		rm.pendingStart.Stop()
		rm.pendingStart = nil
	}
	if !rm.running {
		rm.mu.Unlock()
		return
	}
	close(rm.stopCh)
	if rm.cmd != nil && rm.cmd.Process != nil {
		_ = rm.cmd.Process.Kill()
		_ = rm.cmd.Wait() // reap the zombie
	}
	rm.cmd = nil
	rm.running = false
	rm.mu.Unlock()

	// Wait for any pending reapply callback that was already running to finish.
	// Must happen outside the lock so the callback itself (which also grabs
	// rm.mu via the parent DarwinManager) can progress.
	rm.pending.Wait()
	slog.Info("route monitor stopped")
}

func (rm *routeMonitor) loop(stdout interface {
	Read(p []byte) (int, error)
}) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-rm.stopCh:
			return
		default:
		}
		line := scanner.Text()
		// Only react to the actual topology-changing events. Everything else
		// (RTM_NEWMADDR, RTM_IFANNOUNCE, etc) is noise.
		if !rtmEventRegex.MatchString(line) {
			continue
		}
		rm.trigger()
	}

	// Scan returned false: either Stop() killed the subprocess, or it
	// died on its own (killed externally, crashed). The latter used to
	// go completely unhandled — zombie process, running stuck true,
	// debounceLoop parked forever, and network changes silently stopped
	// triggering reapply (stale endpoint bypass → broken tunnel, or the
	// very routing loop the bypass exists to prevent).
	select {
	case <-rm.stopCh:
		return // normal Stop(); it reaps the subprocess itself
	default:
	}

	rm.mu.Lock()
	if !rm.running || rm.stopped {
		rm.mu.Unlock()
		return
	}
	cmd := rm.cmd
	rm.cmd = nil
	rm.running = false
	// Release debounceLoop. Safe against Stop()'s close: Stop returns
	// early on !running, and both run under rm.mu.
	close(rm.stopCh)
	// Crash-restart cap: a subprocess that survived >1 min earns a fresh
	// counter; one that keeps dying immediately stops being restarted.
	if time.Since(rm.startedAt) > time.Minute {
		rm.restarts = 0
	}
	rm.restarts++
	restarts := rm.restarts
	rm.mu.Unlock()

	if cmd != nil {
		_ = cmd.Wait() // reap the zombie
	}

	const maxRestarts = 5
	if restarts > maxRestarts {
		slog.Error("route monitor subprocess keeps dying; giving up — network changes will not trigger reapply until the next connect",
			"restarts", restarts-1)
		return
	}
	slog.Error("route monitor subprocess exited unexpectedly; restarting", "attempt", restarts)
	rm.StartDelayed(time.Second)
}

// trigger signals the debounce loop. Non-blocking: if a kick is already
// pending, additional events coalesce naturally inside debounceLoop.
// Zero allocation per event.
func (rm *routeMonitor) trigger() {
	rm.mu.Lock()
	kick := rm.kick
	running := rm.running
	rm.mu.Unlock()
	if !running || kick == nil {
		return
	}
	select {
	case kick <- struct{}{}:
	default:
	}
}

// debounceLoop coalesces RTM event bursts into one reapply per ~500ms
// quiet window. Single persistent timer + Reset — no per-event alloc.
//
// The timer is created once before the outer loop; between bursts it
// lives in the "stopped, drained" state so the next Reset is well-defined
// per Go's time.Timer docs.
func (rm *routeMonitor) debounceLoop() {
	const debounce = 500 * time.Millisecond
	// Create the timer in stopped+drained state so the first Reset works
	// cleanly. NewTimer(0) → fires immediately; Stop drains.
	timer := time.NewTimer(debounce)
	if !timer.Stop() {
		<-timer.C
	}
	// Recover from any reapply panic so Stop()'s pending.Wait can't hang.
	runReapply := func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("route monitor reapply panic recovered", "panic", r)
			}
		}()
		if rm.reapply != nil {
			rm.reapply()
		}
	}
	for {
		// Wait for the first kick of a new burst.
		select {
		case <-rm.stopCh:
			return
		case <-rm.kick:
		}
		timer.Reset(debounce)
		settling := true
		for settling {
			select {
			case <-rm.stopCh:
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-rm.kick:
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(debounce)
			case <-timer.C:
				settling = false
			}
		}
		// Burst settled; run reapply under pending so Stop() waits for it
		// before returning. The Add must be ordered against Stop's
		// running=false under rm.mu: with a bare Add here, a Stop that
		// lands between the timer firing and the Add would see a zero
		// WaitGroup, return, and the reapply would still run afterwards —
		// violating Stop's "no reapply after return" guarantee.
		rm.mu.Lock()
		if !rm.running {
			rm.mu.Unlock()
			return
		}
		rm.pending.Add(1)
		rm.mu.Unlock()
		runReapply()
		rm.pending.Done()
	}
}
