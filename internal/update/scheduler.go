package update

import (
	"context"
	"log/slog"
	"math/rand"
	"sync"
	"time"
)

// Scheduler periodically polls the release feed and emits notifications
// when a newer version appears.
//
// Cadence — picked from the wireguard-windows + VS Code consensus
// documented in research-update-patterns. The numbers are deliberate;
// don't lower them without a reason. A VPN GUI sitting in the system
// tray for weeks does not need a 10-minute poll like Electron's default
// — those defaults pessimise battery and burn rate-limit quota.
//
//	first run         : 30-120s after Start (jittered)
//	steady state      : 24h ± 10% (jittered)
//	transient failure : 5-7m  (first failure)
//	sustained failure : 25-30m (consecutive failures)
//
// Dev builds (IsDevBuild) short-circuit the scheduler entirely so
// `task build` cycles don't poke GitHub.
const (
	initialDelayMin = 30 * time.Second
	initialDelayMax = 120 * time.Second
	steadyInterval  = 24 * time.Hour
	steadyJitter    = 24 * time.Hour / 10 // ±2.4h

	firstFailRetryMin = 5 * time.Minute
	firstFailRetryMax = 7 * time.Minute
	failRetryMin      = 25 * time.Minute
	failRetryMax      = 30 * time.Minute

	// focusRecheckThreshold is how long since the last successful check
	// the window-focus opportunistic-recheck path waits before allowing
	// a new fetch. Without this, alt-tabbing back to the window would
	// fire a fresh API call every time.
	focusRecheckThreshold = 4 * time.Hour
)

// NotifyFunc is the callback the scheduler invokes when a new release
// is discovered. The implementation receives the UpdateInfo and decides
// how to deliver it to the user (Wails event emit, system notification,
// etc.). Called from the scheduler goroutine — keep work brief or
// dispatch onto another goroutine.
//
// The notify func is called at most once per discovered version: the
// scheduler remembers LastSeenVersion in the StateStore and skips
// re-notifying until a newer version appears.
type NotifyFunc func(info *UpdateInfo)

// EnabledFunc is consulted on every scheduled tick to decide whether
// the periodic check should fire. Returning false skips the tick
// without resetting backoff state — the user can flip the toggle off
// in Settings without restarting the app, and the scheduler honours
// the change at the next tick boundary. Manual `CheckNow()` calls
// (the "Check now" button) bypass this check by design.
type EnabledFunc func() bool

// Scheduler holds the periodic-poll loop's state. Construct with
// NewScheduler and call Start exactly once.
type Scheduler struct {
	store   *StateStore
	notify  NotifyFunc
	enabled EnabledFunc

	// kick wakes the loop early when the user manually requests a check
	// or the window-focus handler decides enough time has passed. Buffer
	// of 1 so a kick that arrives mid-fetch isn't lost.
	kick chan struct{}

	mu      sync.Mutex
	last    *CheckResult // most recent result, regardless of outcome
	running bool

	// lastNotifiedVersion records the version we already fired notify
	// for in this process lifetime. Distinct from State.LastSeenVersion
	// (which persists across restarts and is set even for "no update
	// available" responses) — this one only changes when notify actually
	// fires, so a fresh process re-notifies the user about an existing
	// pending update.
	lastNotifiedVersion string
}

// NewScheduler wires a scheduler to its persistent state and notification
// sink. notify and enabled may be nil — a nil notify becomes a no-op,
// a nil enabled becomes "always enabled" (tests).
func NewScheduler(store *StateStore, notify NotifyFunc, enabled EnabledFunc) *Scheduler {
	if notify == nil {
		notify = func(*UpdateInfo) {}
	}
	if enabled == nil {
		enabled = func() bool { return true }
	}
	return &Scheduler{
		store:   store,
		notify:  notify,
		enabled: enabled,
		kick:    make(chan struct{}, 1),
	}
}

// Start launches the scheduler goroutine. Subsequent calls are no-ops.
// The goroutine exits when ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	if IsDevBuild() {
		// Dev builds never hit GitHub on a timer. Manual check (the
		// Settings → Check now button) still works because that path
		// calls CheckNow directly, bypassing the scheduler loop.
		slog.Info("update scheduler: dev build, periodic checks disabled",
			"version", CurrentVersion())
		return
	}

	go s.loop(ctx)
}

// Kick asks the scheduler to perform a check at the next loop iteration,
// preempting whatever sleep was pending. Used by the window-focus
// handler in the GUI and the manual "Check now" button.
//
// The store's LastCheckUnix is consulted before sending — kicks within
// focusRecheckThreshold of the previous successful check are silently
// dropped so alt-tabbing doesn't hammer GitHub.
func (s *Scheduler) Kick(force bool) {
	if !force {
		if last := s.store.LastCheckTime(); !last.IsZero() && time.Since(last) < focusRecheckThreshold {
			return
		}
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Latest returns a snapshot of the most recent check result (or nil if
// no check has finished yet). Used by the GUI to populate the
// "Last checked" timestamp in Settings without triggering a new fetch.
func (s *Scheduler) Latest() *CheckResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// CheckNow performs a synchronous check, updates persisted state, and
// returns the result. Used by the manual "Check now" UI path; bypasses
// the kick / sleep machinery so the user gets immediate feedback.
//
// CheckNow respects ETag caching but ignores the dev-build skip — the
// user explicitly asked, so we honour it even on a dev binary. Uses
// context.Background() because the Wails RPC entry point has no
// caller-side cancellation; the http.Client's 10 s timeout still
// applies, so a hung GitHub doesn't wedge the UI.
func (s *Scheduler) CheckNow() (*CheckResult, error) {
	st := s.store.Get()
	res, err := CheckForUpdateConditional(context.Background(), st.ETag, st.LastModified)
	s.recordResult(res, err)
	if err != nil {
		return res, err
	}
	s.maybeNotify(res)
	return res, nil
}

// loop is the periodic-poll goroutine. Exits when ctx is cancelled.
func (s *Scheduler) loop(ctx context.Context) {
	delay := jitterRange(initialDelayMin, initialDelayMax)
	slog.Info("update scheduler: first check scheduled", "delay", delay)

	// One reusable timer instead of a fresh time.After each iteration: a
	// time.After timer isn't collected until it fires, so every Kick or
	// ctx cancel that beat the timer left a live ~26h timer parked in the
	// runtime. Start it stopped+drained so the loop-top Reset is always
	// well-defined (Reset requires a stopped, drained timer).
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		timer.Reset(delay)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.kick:
			if !timer.Stop() {
				<-timer.C
			}
		}

		if !s.enabled() {
			// User flipped the auto-check toggle off. Sleep for the
			// steady interval (don't churn faster than that when the
			// scheduler is disabled) and re-check the toggle.
			delay = jitterAround(steadyInterval, steadyJitter)
			slog.Debug("update scheduler: disabled by user setting; sleeping",
				"delay", delay)
			continue
		}

		st := s.store.Get()
		res, err := CheckForUpdateConditional(ctx, st.ETag, st.LastModified)
		s.recordResult(res, err)

		if err != nil {
			st2 := s.store.Get()
			if st2.ConsecutiveErrors <= 1 {
				delay = jitterRange(firstFailRetryMin, firstFailRetryMax)
			} else {
				delay = jitterRange(failRetryMin, failRetryMax)
			}
			slog.Warn("update scheduler: check failed; will retry",
				"error", err, "retry_in", delay,
				"consecutive_errors", st2.ConsecutiveErrors)
			continue
		}
		s.maybeNotify(res)
		delay = jitterAround(steadyInterval, steadyJitter)
		slog.Debug("update scheduler: next check scheduled", "delay", delay)
	}
}

// recordResult persists the outcome to the StateStore — ETag/Last-Modified
// on every successful response (200 or 304), LastSeenVersion on a 200
// with a newer build, and the error counters on failures.
func (s *Scheduler) recordResult(res *CheckResult, err error) {
	s.mu.Lock()
	s.last = res
	s.mu.Unlock()

	now := time.Now().Unix()

	if err != nil {
		_ = s.store.Update(func(st *State) {
			st.LastErrorUnix = now
			st.ConsecutiveErrors++
			// Cap to avoid integer overflow on long-term offline runs.
			if st.ConsecutiveErrors > 1000 {
				st.ConsecutiveErrors = 1000
			}
		})
		return
	}

	_ = s.store.Update(func(st *State) {
		st.LastCheckUnix = now
		st.LastErrorUnix = 0
		st.ConsecutiveErrors = 0
		if res.ETag != "" {
			st.ETag = res.ETag
		}
		if res.LastModified != "" {
			st.LastModified = res.LastModified
		}
		if res.Info != nil && res.Info.Version != "" {
			st.LastSeenVersion = res.Info.Version
		}
	})
}

// maybeNotify fires the notify callback at most once per (version, app
// session). The dedup logic lives on the backend — not the frontend —
// because the frontend's cached state goes stale the moment the user
// dismisses a banner: the scheduler's next tick would otherwise re-fire
// the same emit, the frontend's stale `dismissed_versions` snapshot
// would let it through, and the banner would reappear seconds after
// being closed.
//
// Three gates, all sourced from the persistent StateStore (truth):
//
//  1. Info.Available must be true.
//  2. The version must not be in DismissedVersions — the user already
//     said "skip this one".
//  3. The version must not equal lastNotifiedVersion — already shown
//     this session. (Persistent skip needs an explicit dismiss; merely
//     having seen the banner once isn't a permanent silence.)
//
// `wireguard-windows` uses the same pattern: see `didNotify` in
// manager/updatestate.go.
func (s *Scheduler) maybeNotify(res *CheckResult) {
	if res == nil || res.Info == nil || !res.Info.Available {
		return
	}
	v := res.Info.Version
	if v == "" {
		return
	}
	if s.store.IsDismissed(v) {
		slog.Debug("update scheduler: skipping notify, version dismissed", "version", v)
		return
	}
	s.mu.Lock()
	already := s.lastNotifiedVersion == v
	if !already {
		s.lastNotifiedVersion = v
	}
	s.mu.Unlock()
	if already {
		slog.Debug("update scheduler: skipping notify, already notified this session", "version", v)
		return
	}
	s.notify(res.Info)
}

// ResetNotifyMemory clears the per-session "already notified" guard so
// the next successful check re-emits even for the same version. Called
// when the user explicitly un-dismisses (clears DismissedVersions via
// some future "show me again" path) — not used right now, but exposing
// the seam keeps the dedup contract explicit instead of buried in a
// private field.
func (s *Scheduler) ResetNotifyMemory() {
	s.mu.Lock()
	s.lastNotifiedVersion = ""
	s.mu.Unlock()
}

// jitterRange picks a uniformly-random duration in [min, max].
func jitterRange(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

// jitterAround returns base ± a uniformly-random amount in [0, spread].
func jitterAround(base, spread time.Duration) time.Duration {
	if spread <= 0 {
		return base
	}
	delta := time.Duration(rand.Int63n(int64(2*spread))) - spread
	return base + delta
}
