// Package helper implements the privileged helper process.
// Runs as root/admin, accepts RPC calls from the GUI, manages tunnel + firewall.
//
// The package is split across three files:
//   - helper.go   (this file) — Helper struct + Run() lifecycle
//   - handlers.go — RPC method handlers
//   - events.go   — status diff + broadcast loop, status conversion
//
// Architectural note: helper imports internal/storage on purpose, scoped to
// two operations:
//
//  1. Tunnel.Rename — atomic "check active + rename .conf" under connectMu;
//     moving the file ops to the GUI would open a TOCTOU window with the
//     wifi-rule auto-connect path.
//  2. wifi-rule auto-connect — Load(name) to fetch the cfg for tunnels the
//     user hasn't opened via the GUI yet. Pushing cfgs from GUI to helper
//     would race the very first SSID transition right after launch.
//
// Storage usage is therefore intentional and minimal; no other privileged
// code path touches the user's home directory.
package helper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/network"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// goSafe runs fn in a goroutine with panic recovery. Without this, a panic
// in ANY helper goroutine crashes the whole process — which is exactly what
// we've been unable to diagnose because the helper dies silently with no log
// trail. Every background goroutine in the helper should be started via this
// wrapper so panics are captured, logged, and surfaced instead of vanishing.
// goSafe runs fn in a goroutine with panic recovery and automatic restart.
// If fn panics, the panic is logged and fn is restarted after a 1-second
// backoff, up to maxRestarts times. This ensures critical background loops
// (like the event broadcast loop) survive transient panics instead of dying
// permanently. If fn returns normally (no panic), it is NOT restarted.
//
// When the restart budget is exhausted, broadcast EventCriticalError so the
// GUI can surface a banner — otherwise the helper appears alive but key
// loops are silently dead and the user has no warning.
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
			// Jittered backoff: 500ms-1500ms. Without jitter, if multiple
			// background loops panic from a common cause (e.g. a shared
			// nil dependency), all of them sleep the exact same 1s and
			// wake up together — repeating the panic in lockstep and
			// freezing the helper for the full restart budget. Jitter
			// staggers wakeups so transient ordering issues can resolve.
			// math/rand is intentional here — predictable randomness is
			// fine for jitter (gosec G404 would flag any math/rand; the
			// security threat model doesn't apply to a sleep timer).
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

// shutdownGrace is the window the helper waits after a GUI disconnect before
// terminating itself. Short enough to prevent orphan processes, long enough to
// tolerate a normal GUI restart.
const shutdownGrace = 10 * time.Second

// startupGrace is the window a freshly-started helper waits for its FIRST
// GUI connection before terminating itself. Covers the orphan case where
// the spawning GUI died while the UAC/authorization prompt was still
// pending — consent then launches a helper no GUI will ever connect to
// (Windows login autostart: UAC shows, GUI times out and exits, helper
// lingers in Task Manager with no tray). Much longer than shutdownGrace
// because a legitimate first connect can be delayed by boot-time disk
// contention or a user who answers the prompt slowly, and the arming
// happens before crash recovery has restored any tunnel.
const startupGrace = 60 * time.Second

// Helper holds the helper process state.
type Helper struct {
	server   *ipc.Server
	manager  *tunnel.Manager
	firewall firewall.FirewallManager
	monitor  *reconnect.Monitor

	// connectMu serializes Connect/Disconnect calls. Without this, two
	// concurrent GUI connections could race on activeCfg, with the loser's
	// rollback overwriting the winner's config.
	connectMu sync.Mutex

	// logLevel is the runtime-mutable slog level. Helper.SetLogLevel (and
	// the Settings UI) writes to this; the broadcast handler reads it for
	// every record. Info by default.
	logLevel *slog.LevelVar

	mu         sync.Mutex
	activeCfgs map[string]*domain.WireGuardConfig // cached for reconnect, keyed by tunnel name

	// Wanted firewall state, guarded by mu. dnsWanted is the user's DNS
	// protection setting (restored from persisted settings at start);
	// ksWanted is the kill switch the user asked for. The firewall itself is
	// always derived from these plus the tunnels that are actually up
	// (reconcileFirewallLocked), never from a snapshot of firewall state.
	dnsWanted bool
	ksWanted  bool
	// reconciledKey is the connected (tunnel, iface) set the last reconcile
	// saw; the event loop compares against it. Guarded by mu.
	reconciledKey string
	// reconcileFails / reconcileRetryAt back off the safety-net retry after a
	// failed reconcile (reconciledKey is then set to reconcileDirtyKey).
	// Guarded by mu.
	reconcileFails   int
	reconcileRetryAt time.Time

	// Reconcile bookkeeping, guarded by connectMu (every reconcile caller
	// holds it): the permit set last applied, whether that apply succeeded,
	// the interfaces folded into the kill switch, and how many reconnect
	// attempts currently have the firewall suspended.
	lastPermits    []firewall.DNSPermit
	dnsApplied     bool
	ksIfaces       map[string]struct{}
	fwSuspendDepth int

	// shutdownTimer is a singleton grace-window timer. When the control
	// connection drops we Reset it; when the GUI reconnects we Stop it. This
	// avoids the previous bug where every disconnect spawned a fresh goroutine
	// and multiple shutdowns could race.
	shutdownTimer *time.Timer

	// latencyByTunnel caches the most recent endpoint round-trip time
	// (in ms) per tunnel name. Updated by latencyLoop every 30s; read by
	// statusDTO on every broadcast tick. Keyed by tunnel name so
	// multi-tunnel setups show per-tunnel latency.
	latencyMu       sync.Mutex
	latencyByTunnel map[string]float64

	// wifiMon polls CurrentSSID every 5s. The helper itself evaluates
	// the user's wifi rules on every change so auto-connect /
	// auto-disconnect work whether or not a GUI is running. The
	// EventWifiSSID broadcast is still sent so a live GUI can react
	// (e.g. show a toast).
	wifiMon *wifi.Monitor

	// wifiMu guards autoConnectedBy. The map records "this tunnel
	// was last activated by a wifi rule on this SSID" so a later
	// SSID change can tell auto-managed tunnels apart from manually
	// connected ones and only touch the former.
	wifiMu          sync.Mutex
	autoConnectedBy map[string]string
	// ssidStampGW is the gateway MAC observed when the GUI last reported
	// the SSID. macOS only: the root helper can't read the SSID itself, so
	// if the GUI exits and the machine then moves networks, the reported
	// SSID goes stale with nothing to refresh it. A different CURRENT
	// gateway MAC than this stamp proves the network changed since the
	// report, so evaluation treats the SSID as unknown rather than acting
	// on the old network's name. Guarded by wifiMu.
	ssidStampGW string
	// ssidFromGUI is set once the GUI has reported an SSID (macOS). The
	// stamp and its staleness guard apply only then: on Linux/Windows the
	// helper reads the SSID itself, so it is always fresh. Guarded by wifiMu.
	ssidFromGUI bool
	// guiAttachedFn, when set, replaces the server's control-connection
	// check in guiAttached (tests only).
	guiAttachedFn func() bool

	// connectedFn, when set, replaces manager.ActiveTunnels() in the legacy
	// reconnect path (tests only).
	connectedFn func() []string

	// reevalMu serialises Automation re-evaluations. The three triggers
	// (SSID change, network change, poll) can fire concurrently; the
	// lock ensures only one evaluation drives connect/disconnect at a
	// time so they don't race on the same tunnel.
	reevalMu sync.Mutex

	// reevalTrigger, when set, replaces reevaluateAutomation for the
	// rules-change watcher and the preview drift check (tests only).
	reevalTrigger func(reason string)
	// rulesWatchInterval overrides rulesWatchDefaultInterval; rulesStat
	// replaces os.Stat of config.json (tests only).
	rulesWatchInterval time.Duration
	rulesStat          func(path string) (mtimeNano, size int64, err error)
	// previewDriftMu guards previewDriftLast (rate limit for the preview's
	// self-heal); previewDriftNow overrides time.Now (tests only).
	previewDriftMu   sync.Mutex
	previewDriftLast time.Time
	previewDriftNow  func() time.Time

	// settle tracks how long the network fingerprint has been stable so
	// negated rules can wait out roam blips; settleTimer re-triggers a
	// held evaluation when the window elapses. Both guarded by settleMu.
	settleMu    sync.Mutex
	settle      *wifi.SettleTracker
	settleTimer *time.Timer

	// manualOverride latches an explicit user connect/disconnect per tunnel
	// (with the network identity it was made on) so automation doesn't undo
	// it until the network settles on a different identity. Guarded by
	// wifiMu.
	manualOverride map[string]manualLatch

	// userTunnelStore reads .conf files from the user's home dir
	// (derived from the uid passed at launch). Needed so wifi rules
	// can connect tunnels that aren't already in activeCfgs — i.e.
	// the user has never opened them via the GUI in this session.
	userTunnelStore *storage.TunnelStore
	userAppSupport  string

	done        chan struct{}
	cleanupOnce sync.Once
	// cleanupDone is closed when cleanup() has finished; the signal handler
	// bounds its wait on it.
	cleanupDone chan struct{}
}

// signalShutdownTimeout bounds how long a SIGTERM/SIGINT-driven shutdown may
// take before the process exits anyway.
const signalShutdownTimeout = 3 * time.Second

// Run starts the helper listening on addr. Blocks until shutdown.
// ownerUID: UID to chown socket to (Unix only, use -1 on Windows).
// ownerSID: spawning user's SID (Windows only, "" on Unix) — scopes the
// pipe ACL and per-connection peer checks to that user (issue #20).
// dataDir: persistent data dir for crash recovery state.
func Run(addr string, ownerUID int, ownerSID, dataDir string) error {
	// wireguard-go allocates sizeable per-Device transient buffer pools. With
	// the runtime default GOGC=100, repeated connect/disconnect on a long-lived
	// helper retained hundreds of MiB of reclaimable heap before GC caught up
	// (30 cycles on linux/arm64: ~118 MiB -> ~283 MiB). GOGC=50 kept the same
	// workload near ~100 MiB with a modest CPU increase (~2.14s -> ~2.34s),
	// while GOGC=20 bought little more memory at a much higher CPU cost.
	// Respect an explicit administrator-provided GOGC override.
	if _, explicitlyConfigured := os.LookupEnv("GOGC"); !explicitlyConfigured {
		previousGCPercent := debug.SetGCPercent(50)
		defer debug.SetGCPercent(previousGCPercent)
	}

	listener, err := ipc.Listen(addr, ownerUID, ownerSID)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	manager := tunnel.NewManager(dataDir)
	fw := firewall.NewPlatformFirewall()
	// Wire the always-on endpoint loop protection. The firewall
	// satisfies tunnel.EndpointProtector trivially on every platform —
	// macOS/Linux return nil from their no-op implementations and the
	// Windows path installs the WFP BLOCK filters described in
	// internal/firewall/endpoint_protection_windows.go.
	manager.SetEndpointProtector(fw)

	h := &Helper{
		server:          ipc.NewServer(listener, ownerUID).WithOwnerSID(ownerSID),
		manager:         manager,
		firewall:        fw,
		activeCfgs:      make(map[string]*domain.WireGuardConfig),
		latencyByTunnel: make(map[string]float64),
		autoConnectedBy: make(map[string]string),
		manualOverride:  make(map[string]manualLatch),
		logLevel:        new(slog.LevelVar), // defaults to Info
		done:            make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}

	// Derive the user's Application Support dir from the uid the
	// LaunchDaemon plist passed in (`--uid=501` typically). Helper
	// runs as root, so os.UserHomeDir() returns /var/root — useless.
	// On platforms we haven't wired up (linux/windows), this returns
	// empty and the wifi-rules helper-side path stays a no-op.
	if appSupport, err := deriveUserAppSupport(ownerUID); err == nil && appSupport != "" {
		h.userAppSupport = appSupport
		h.userTunnelStore = storage.NewTunnelStore(filepath.Join(appSupport, "tunnels"))
	}

	// Install the broadcast slog handler BEFORE the first log call so
	// everything that follows (crash recovery notices, manager init,
	// handler registration) gets piped to subscribed GUIs.
	slog.SetDefault(slog.New(newBroadcastHandler(h.logLevel, func() func(string, interface{}) {
		if h.server == nil {
			return nil
		}
		return h.server.Broadcast
	})))

	// Crash recovery (now logs via broadcast handler). Pass the helper's
	// own firewall instance so cleanup reuses its in-memory state
	// instead of constructing a fresh one inside the tunnel package
	// (which previously decoupled the cleanup from the helper's view).
	if recovered := tunnel.RecoverFromCrash(dataDir, fw); len(recovered) > 0 {
		slog.Warn("recovered from previous crash", "tunnels", recovered)
	}

	// Firewall crash recovery. A helper restart means every tunnel interface
	// the previous process owned is gone, so no WireGuide firewall rule can
	// still be valid: the firewall implementation clears stale state
	// unconditionally (on macOS: flush both pf anchors, release the persisted
	// pf reference, drop legacy markers), whether or not any state file
	// exists. Must run BEFORE any tunnel brings new rules up.
	if recovered := fw.RecoverFromCrash(); recovered {
		slog.Warn("recovered firewall state from previous crash")
	}

	// Reconnect monitor — uses cached config
	h.monitor = reconnect.NewMonitor(manager, h.reconnectFn, h.onReconnectState, reconnect.DefaultConfig())
	h.monitor.SetFirewallCallbacks(h.suspendFirewall, h.resumeFirewall)
	h.monitor.SetLegacyTeardown(h.legacyTeardown)
	h.monitor.Start()

	// Register RPC handlers
	h.registerHandlers()

	// Grace-window shutdown on GUI disconnect. This applies to EVERY launch
	// mode, LaunchDaemon included: a running GUI is the user's statement of
	// intent that WireGuide should be active, so a helper with no GUI (and
	// no active tunnel) has no reason to exist. The LaunchDaemon plist sets
	// RunAtLoad=false precisely so the boot path never produces an
	// invisible root helper; this guard is the runtime half of the same
	// rule, covering the case where the GUI dies without a clean Shutdown.
	//
	// Users who want WireGuide up from boot enable auto_start, which
	// installs the GUI LaunchAgent — the GUI then spawns the helper on the
	// normal path.
	h.server.OnConnect(h.cancelShutdownTimer)
	h.server.OnDisconnect(h.startShutdownTimer)
	// Arm the startup grace window now: a helper that never receives
	// a GUI connection must not run forever (see startupGrace). The
	// first OnConnect cancels it; the fire-time active-tunnel check
	// keeps a crash-recovered tunnel alive even with no GUI.
	h.armShutdownTimer(startupGrace, "startup, no GUI connected yet")

	// Start event emitter (diff loop)
	h.goSafe("eventLoop", h.eventLoop)

	// Start endpoint latency probe loop. Runs at a slow tick (~30s) so
	// it doesn't add measurable load; ICMP pings are blocking and the
	// goroutine is supervised by goSafe like every other long-running
	// helper background task.
	h.goSafe("latencyLoop", h.latencyLoop)
	h.goSafe("pingHealthLoop", h.pingHealthLoop)

	// Start Wi-Fi SSID monitor. On change we broadcast the event for
	// any GUI listener AND evaluate the user's wifi rules right here
	// so auto-connect / auto-disconnect keep working when the GUI is
	// closed.
	h.wifiMon = wifi.NewMonitor(func(oldSSID, newSSID string) {
		h.server.Broadcast(ipc.EventWifiSSID, ipc.WifiSSIDPayload{
			OldSSID: oldSSID,
			NewSSID: newSSID,
		})
		h.handleSSIDChange(oldSSID, newSSID)
	})
	h.wifiMon.Start()

	// Restore persisted helper-side settings so a helper restart (crash,
	// LaunchDaemon KeepAlive, reboot, upgrade) doesn't silently drop what
	// the user enabled. The GUI only pushes these when the user TOGGLES
	// them in Settings (plus log level once at GUI startup), so without
	// this a freshly-restarted headless helper ran with defaults — health
	// check off, pin-interface off, log level Info — regardless of
	// config.json. The kill switch is deliberately NOT
	// applied here: enabling the kill switch at boot with no tunnel up would
	// block all traffic, which is a product decision, not a restore.
	// DNS protection IS restored as WANTED state (dnsWanted): it installs no
	// rule until a connected tunnel justifies one (reconcileFirewallLocked),
	// so it can never blackhole DNS on a helper with nothing connected. The
	// setting itself is persisted by the GUI/CLI in config.json, exactly like
	// health_check and pin_interface.
	if settings, err := h.loadUserSettings(); err == nil {
		h.setDNSWanted(settings.DNSProtection)
		h.monitor.SetHealthCheck(settings.HealthCheck)
		if settings.PinInterface {
			if err := h.manager.SetPinInterface(true); err != nil {
				slog.Warn("restore pin-interface failed", "error", err)
			}
		}
		if settings.LogLevel != "" {
			h.logLevel.Set(parseLevel(settings.LogLevel))
		}
		slog.Info("restored persisted helper settings",
			"health_check", settings.HealthCheck,
			"pin_interface", settings.PinInterface,
			"dns_protection", settings.DNSProtection,
			"log_level", settings.LogLevel)
	}

	// Re-evaluate rules once on startup. The autoConnectedBy map is
	// in-memory only, so a helper crash + LaunchDaemon restart loses
	// the "this tunnel was rule-managed" markers. Without this synthetic
	// re-eval, a tunnel recovered from crash on a SSID with no rule
	// stays up indefinitely until the user manually disconnects.
	// Running it here, after wifiMon starts, also handles the boot
	// case where the helper starts before the Wi-Fi has joined.
	h.goSafe("ssidStartupRule", func() {
		// Brief delay to let the network stack settle and crash
		// recovery finish — racing handleSSIDChange against an
		// in-flight RecoverFromCrash would corrupt activeCfgs.
		select {
		case <-h.done:
			return
		case <-time.After(3 * time.Second):
		}
		// Re-check shutdown after the sleep — `cleanup()` running
		// concurrently calls h.manager.DisconnectAll(), and we'd
		// otherwise race handleSSIDChange's manager.Connect against
		// a torn-down manager.
		select {
		case <-h.done:
			return
		default:
		}
		// Use the helper's known SSID (reported by the GUI on macOS 14+,
		// polled elsewhere) rather than a direct read. With an unknown
		// SSID, skip unless a tunnel has a negated rule: negated rules
		// hold on unknown input (and a blank SSID on Ethernet/tethering is
		// a known value), but a none_match rule would act on the unknown
		// network and could disconnect a freshly crash-recovered tunnel.
		// Subnet-only rules still get their first evaluation from the
		// network-change / poll trigger below.
		ssid := ""
		if h.wifiMon != nil {
			ssid = h.wifiMon.LastSSID()
		}
		if ssid == "" && !h.anyNegatedRules() {
			return
		}
		slog.Info("startup rule re-evaluation", "ssid", ssid)
		h.reevaluateAutomation("startup")
	})

	// Rules-change trigger: nothing else re-evaluates when the user saves
	// new Automation rules, so the settle tracker would never see them.
	h.goSafe("automationRulesWatch", h.rulesWatchLoop)

	// Hybrid subnet-rule trigger. Subnet-based Automation conditions must
	// re-evaluate when the physical network changes even if the SSID
	// doesn't (Ethernet plug/unplug, DHCP subnet change):
	//   - macOS: subscribe to the existing route-change monitor — instant,
	//     event-driven, ~zero added cost (no-op on other platforms).
	//   - Windows/Linux: a 30s poll as the universal safety net, since
	//     they have no process-wide network-change monitor yet.
	// SSID-based rules keep firing instantly via the Wi-Fi monitor above.
	network.SubscribeNetworkChange("automation", func() {
		h.reevaluateAutomation("network-change")
	})
	if runtime.GOOS != "darwin" {
		h.goSafe("automationPoll", func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-h.done:
					return
				case <-ticker.C:
					h.reevaluateAutomation("poll")
				}
			}
		})
	}

	// Top-level panic recovery for the Serve loop itself. If Accept or any
	// per-conn handler panics unrecovered, we at least want a stack trace.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("helper Run panic",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
		}
	}()

	// SIGTERM (launchctl bootout, logout/shutdown, kill) and SIGINT take the
	// same single graceful path as every other shutdown: Shutdown() makes
	// Serve return, then Run's cleanup() runs once (cleanupOnce). Bounded: a
	// wedged teardown must not outlive launchd's patience, and the utun
	// devices die with the process anyway.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigCh)
	go func() {
		// Keep listening until cleanup has FINISHED (not merely started): a
		// SIGTERM that arrives mid-cleanup must still enforce the bounded
		// exit below.
		select {
		case sig := <-sigCh:
			slog.Info("signal received, shutting down", "signal", sig.String())
		case <-h.cleanupDone:
			return
		}
		h.shutdown()
		select {
		case <-h.cleanupDone:
		case <-time.After(signalShutdownTimeout):
			slog.Warn("signal shutdown: cleanup did not finish in time; clearing firewall and DNS and exiting")
			// Best effort, bounded: never leave pf/nft/WFP rules up, or a
			// networksetup DNS override pointing at a dead tunnel resolver
			// (it persists in SystemConfiguration past process death, #34).
			fwDone := make(chan struct{})
			go func() {
				defer close(fwDone)
				if err := h.firewall.Cleanup(); err != nil {
					slog.Warn("signal shutdown: firewall.Cleanup failed", "error", err)
				}
				if h.manager != nil {
					h.manager.RestoreDNSBestEffort()
				}
			}()
			select {
			case <-fwDone:
			case <-time.After(3 * time.Second):
			}
			os.Exit(0)
		}
	}()

	slog.Info("helper listening", "addr", addr, "pid", "daemon")

	// Serve (blocks until shutdown)
	err = h.server.Serve()
	h.cleanup()
	return err
}

// reconnectFn is the callback passed to reconnect.Monitor. When name is
// non-empty, it reconnects only that specific tunnel. When name is empty
// (legacy sleep/wake path), it reconnects all cached tunnels.
// The connectMu is held during Connect to prevent races with concurrent
// GUI connect/disconnect calls.
//
// The ctx is checked at every boundary where we can still short-circuit
// (before grabbing connectMu, between per-tunnel Connects in the legacy
// path). Manager.Connect itself is not ctx-aware today — once we enter it
// the helper is committed to that attempt up to Connect's internal
// timeouts. This still lets monitor.Stop() exit quickly in the common
// case where cancellation lands before Connect starts.
func (h *Helper) reconnectFn(ctx context.Context, name string) error {
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()

	// connectMu is released by defer so a panic in Connect unwinds it BEFORE
	// the monitor's deferred resumeFirewall (which takes connectMu) runs.
	connectLocked := func(cfg *domain.WireGuardConfig) error {
		h.connectMu.Lock()
		defer h.connectMu.Unlock()
		return h.manager.ConnectWithContext(ctx, cfg)
	}

	if name != "" {
		cfg, ok := cfgs[name]
		if !ok {
			return fmt.Errorf("no cached config for tunnel %q", name)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reconnect %q cancelled before Connect: %w", name, err)
		}
		return alreadyConnectedIsOK(connectLocked(cfg))
	}

	// Legacy path: restore the cached tunnels that are down. Tunnels that
	// automation governs are left to it (it is re-evaluated afterwards), as
	// are tunnels the user disconnected on purpose; tunnels that are still
	// connected are simply skipped.
	if len(cfgs) == 0 {
		return reconnect.ErrNothingToReconnect
	}
	deferToAutomation := false
	defer func() {
		if !deferToAutomation {
			return
		}
		// Asynchronously and WITHOUT connectMu: lock order is
		// reevalMu -> connectMu, never the reverse.
		h.goSafe("reconnectReevaluate", func() {
			select {
			case <-h.done:
				return
			default:
			}
			h.reevaluateAutomation("reconnect")
		})
	}()

	if err := waitForDefaultRoute(ctx, gatewayWaitBudget); err != nil {
		return fmt.Errorf("reconnect-all cancelled waiting for a default route: %w", err)
	}

	connected := make(map[string]bool)
	for _, n := range h.connectedTunnels() {
		connected[n] = true
	}
	ruleTunnels := h.automationRuleTunnels()
	names := make([]string, 0, len(cfgs))
	for n := range cfgs {
		names = append(names, n)
	}
	sort.Strings(names)

	var netCtx *wifi.NetworkContext
	var lastErr error
	attempted := 0
	for _, n := range names {
		cfg := cfgs[n]
		latch, latched := h.manualLatchFor(n)
		if connected[n] {
			// A connected tunnel that automation or the user owns was left
			// alone by legacyTeardown; the network may have changed under
			// it, so make sure automation re-evaluates.
			if latched || ruleTunnels[n] {
				deferToAutomation = true
			}
			continue
		}
		if latched && latch.disconnected {
			slog.Info("legacy reconnect: skipping tunnel the user disconnected", "tunnel", n)
			continue
		}
		if ruleTunnels[n] && !latched {
			// Defer only when automation will actually decide this tunnel
			// (connect/disconnect, or held until the network settles). If
			// its rules don't apply here (unmanaged) automation does
			// nothing, so the legacy path must restore it.
			if netCtx == nil {
				c := h.currentNetworkContext()
				netCtx = &c
			}
			state, info := wifi.EvaluateDetailed(h.automationRules(n), *netCtx)
			if state != wifi.StateUnmanaged || info.Held {
				slog.Info("legacy reconnect: leaving tunnel to automation", "tunnel", n)
				deferToAutomation = true
				continue
			}
		}
		if cidr, addr, overlaps := overlapsLocalNetwork(cfg); overlaps {
			slog.Info("legacy reconnect: skipping tunnel whose AllowedIPs overlap the local network",
				"tunnel", n, "cidr", cidr, "local_address", addr.String())
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reconnect-all cancelled mid-loop: %w", err)
		}
		attempted++
		if err := alreadyConnectedIsOK(connectLocked(cfg)); err != nil {
			lastErr = err
		}
	}
	if lastErr == nil && attempted == 0 && !deferToAutomation {
		allConnected := true
		for _, n := range names {
			if !connected[n] {
				allConnected = false
			}
		}
		if !allConnected {
			// Everything still down was skipped on purpose.
			return reconnect.ErrNothingToReconnect
		}
	}
	return lastErr
}

// legacyTeardown is the reconnect monitor's teardown for the legacy
// wake/interface-change path. Instead of dropping an arbitrary tunnel it
// tears down only the connected tunnels that no one else owns, so
// reconnectFn("") can rebuild them on the new network. Tunnels governed by
// automation rules or held by a manual latch are left untouched: automation
// decides them (it is re-evaluated after the legacy attempt), and bouncing
// them would only cause an outage on every network blip.
func (h *Helper) legacyTeardown() error {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	return h.legacyTeardownWith(h.connectedTunnels(), h.manager.DisconnectTunnel)
}

// connectedTunnels lists the currently connected tunnels (test seam:
// connectedFn overrides the manager).
func (h *Helper) connectedTunnels() []string {
	if h.connectedFn != nil {
		return h.connectedFn()
	}
	return h.manager.ActiveTunnels()
}

// legacyTeardownWith implements legacyTeardown over an explicit set of
// connected tunnels. Caller MUST hold h.connectMu.
func (h *Helper) legacyTeardownWith(active []string, disconnect func(string) error) error {
	ruleTunnels := h.automationRuleTunnels()
	for _, n := range active {
		if _, latched := h.manualLatchFor(n); latched || ruleTunnels[n] {
			slog.Info("legacy reconnect: leaving connected tunnel untouched (owned by automation or manual choice)",
				"tunnel", n, "latched", latched)
			continue
		}
		if err := disconnect(n); err != nil {
			var te *tunnel.TunnelError
			if errors.As(err, &te) && te.Kind == tunnel.ErrNotConnected {
				continue
			}
			return fmt.Errorf("legacy reconnect teardown of %q: %w", n, err)
		}
	}
	return nil
}

// guiAttached reports whether a GUI control connection is attached. Safe on
// a helper without a server (tests).
func (h *Helper) guiAttached() bool {
	if h.guiAttachedFn != nil {
		return h.guiAttachedFn()
	}
	return h.server != nil && h.server.HasControlConn()
}

// alreadyConnectedIsOK maps tunnel.ErrAlreadyConnected to success: the
// reconnect's goal (the tunnel is up) already holds, so it must not count
// as a failed attempt that backs off and retries.
func alreadyConnectedIsOK(err error) error {
	var te *tunnel.TunnelError
	if errors.As(err, &te) && te.Kind == tunnel.ErrAlreadyConnected {
		return nil
	}
	return err
}

// anyNegatedRules reports whether any tunnel has a negated automation rule.
func (h *Helper) anyNegatedRules() bool {
	settings, err := h.loadUserSettings()
	if err != nil {
		return false
	}
	settings.EnsureAutomation()
	if settings.Automation == nil {
		return false
	}
	for _, rules := range settings.Automation.PerTunnel {
		if wifi.HasNegated(rules) {
			return true
		}
	}
	return false
}

// automationRules returns tunnel name's automation rules (nil when settings
// can't be read).
func (h *Helper) automationRules(name string) []wifi.Rule {
	settings, err := h.loadUserSettings()
	if err != nil {
		return nil
	}
	settings.EnsureAutomation()
	if settings.Automation == nil {
		return nil
	}
	return settings.Automation.PerTunnel[name]
}

// automationRuleTunnels returns the set of tunnels that have automation
// rules (empty when settings can't be read).
func (h *Helper) automationRuleTunnels() map[string]bool {
	out := map[string]bool{}
	settings, err := h.loadUserSettings()
	if err != nil {
		return out
	}
	settings.EnsureAutomation()
	if settings.Automation == nil {
		return out
	}
	for name, rules := range settings.Automation.PerTunnel {
		if len(rules) > 0 {
			out[name] = true
		}
	}
	return out
}

// copyActiveCfgs returns a shallow copy of the active configs map.
// Caller MUST hold h.mu.
func (h *Helper) copyActiveCfgs() map[string]*domain.WireGuardConfig {
	cp := make(map[string]*domain.WireGuardConfig, len(h.activeCfgs))
	for k, v := range h.activeCfgs {
		cp[k] = v
	}
	return cp
}

// onReconnectState forwards reconnection state changes to any subscribed GUI.
func (h *Helper) onReconnectState(state reconnect.State) {
	h.server.Broadcast(ipc.EventReconnect, ipc.ReconnectStateDTO{
		Reconnecting: state.Reconnecting,
		Attempt:      state.Attempt,
		MaxAttempts:  state.MaxAttempts,
		NextRetry:    state.NextRetry,
	})
}

// startShutdownTimer begins (or re-begins) the grace-window countdown. Called
// when the GUI's control connection drops.
//
// CRITICAL DESIGN: wg-quick never shuts down while a tunnel is active. Our
// helper must follow the same principle. If a tunnel is connected, we do NOT
// start the shutdown timer — the helper stays alive indefinitely, just like
// wg-quick's monitor_daemon. The timer only applies when there is no active
// tunnel (i.e., the user disconnected and then closed the GUI).
func (h *Helper) startShutdownTimer() {
	h.armShutdownTimer(shutdownGrace, "GUI disconnected")
}

// armShutdownTimer is the shared countdown behind startShutdownTimer (GUI
// disconnect) and the startup grace window (never-connected helper). The
// active-tunnel guard applies to both: an active tunnel always keeps the
// helper alive.
func (h *Helper) armShutdownTimer(grace time.Duration, reason string) {
	active := ""
	if h.manager != nil {
		active = h.manager.ActiveTunnel()
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if active != "" {
		slog.Info("tunnel is active — helper stays alive (wg-quick semantics)",
			"reason", reason, "active_tunnel", active)
		// A previously armed window (e.g. the startup grace) is obsolete
		// now that a tunnel is up — stop it rather than leaving it to fire
		// into a transient not-connected instant later.
		if h.shutdownTimer != nil {
			h.shutdownTimer.Stop()
			h.shutdownTimer = nil
		}
		return
	}

	slog.Info("no active tunnel — starting shutdown grace window",
		"reason", reason, "grace", grace)
	if h.shutdownTimer != nil {
		h.shutdownTimer.Stop()
	}
	var t *time.Timer
	t = time.AfterFunc(grace, func() {
		// Timer.Stop() cannot cancel a callback that has already started,
		// so re-check under the lock that we are still the current timer —
		// otherwise a cancel racing with the fire still shuts the helper
		// down right after a GUI attached.
		h.mu.Lock()
		current := h.shutdownTimer
		h.mu.Unlock()
		if current != t {
			return
		}
		// Double-check at fire time: a tunnel may have been activated between
		// timer start and fire (e.g., reconnect monitor brought it back up).
		if h.manager != nil {
			if tn := h.manager.ActiveTunnel(); tn != "" {
				slog.Info("shutdown timer fired but tunnel is now active — aborting shutdown",
					"active_tunnel", tn)
				return
			}
		}
		slog.Info("no reconnect within grace window, shutting down")
		h.shutdown()
	})
	h.shutdownTimer = t
}

// maybeArmShutdownAfterTeardown re-arms the grace window after a tunnel
// teardown that may have dropped the active count to zero. Transient CLI
// clients (`ctl disconnect`, wifi-rule evaluation) never fire the server's
// OnDisconnect, so without this a helper whose GUI already quit — kept alive
// only by its active tunnel — would lose that tunnel and then live forever:
// no GUI, no tunnel, no timer. armShutdownTimer's own active-tunnel guard
// makes this a no-op while any tunnel is still up, and a GUI that IS attached
// keeps its normal lifecycle (its later disconnect arms the window).
func (h *Helper) maybeArmShutdownAfterTeardown(reason string) {
	if h.server.HasControlConn() {
		return
	}
	h.armShutdownTimer(shutdownGrace, reason)
}

// cancelShutdownTimer aborts a pending grace-window shutdown. Called when the
// GUI reconnects before the timer fires.
func (h *Helper) cancelShutdownTimer() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shutdownTimer != nil {
		if h.shutdownTimer.Stop() {
			slog.Info("GUI reconnected within grace window, shutdown cancelled")
		}
		h.shutdownTimer = nil
	}
}

// shutdown initiates a clean exit of the helper process. It does NOT call
// cleanup() directly — instead, it closes the IPC server which causes
// h.server.Serve() (blocked in Run()) to return. Run() then invokes
// h.cleanup() on the deferred path, which DisconnectAll-s tunnels and tears
// down the firewall, and Run() returns to main() which exits the process.
//
// Exit code 0 matters here: the LaunchDaemon plist's KeepAlive is configured
// with SuccessfulExit=false, so launchd respawns only on crash. A successful
// exit driven by this function will NOT restart the daemon — which is what
// the user expects when they click "Quit" in the tray.
func (h *Helper) shutdown() {
	h.server.Shutdown()
}

func (h *Helper) cleanup() {
	h.cleanupOnce.Do(func() {
		defer close(h.cleanupDone)
		slog.Info("helper cleanup starting",
			"connected", h.manager.IsConnected(),
			"call_stack", string(debug.Stack()))
		close(h.done)
		h.mu.Lock()
		t := h.shutdownTimer
		h.shutdownTimer = nil
		h.mu.Unlock()
		if t != nil {
			t.Stop()
		}
		if h.wifiMon != nil {
			h.wifiMon.Stop()
		}
		h.stopSettleTimer()
		network.UnsubscribeNetworkChange("automation")
		h.monitor.Stop()
		// Tear down tunnels BEFORE removing kill-switch / pf rules.
		// Doing it the other way around — flushing pf first — leaves
		// a small but real window where the user's traffic flows
		// over the underlying network unprotected while utun*
		// devices are being closed (DisconnectAll can take seconds
		// per tunnel as wireguard-go drains).
		if h.manager.IsConnected() {
			h.manager.DisconnectAll()
		}
		h.firewall.Cleanup()
		slog.Info("helper shutdown complete")
	})
}
