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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/launchd"
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

// activatedStartupGrace replaces startupGrace when launchd started the helper
// because something connected to its socket. Any process running as the user
// can cause that (a `ctl` probe, a stray connect), and no GUI is promised, so
// a probe must not leave a root process around for a minute. An active tunnel
// still keeps the helper alive (armShutdownTimer's guard).
const activatedStartupGrace = 15 * time.Second

// startupGraceFor picks the first-connection grace window for this launch.
func startupGraceFor(activated bool) time.Duration {
	if activated {
		return activatedStartupGrace
	}
	return startupGrace
}

// activateLaunchd is launchd.Listeners, replaceable in tests.
var activateLaunchd = launchd.Listeners

// fallbackAddr is the address a non-launchd-managed helper listens on.
// ipc.Listen refuses to manage /var/run itself, so a non-launchd start
// pointed at the launchd socket path (a dev run with default arguments) keeps
// to the legacy subdirectory instead.
func fallbackAddr(addr string) string {
	if filepath.Dir(addr) == filepath.Dir(ipc.DarwinSocketPath) {
		slog.Warn("not launchd-managed; using legacy socket directory instead of /var/run",
			"requested", addr, "using", ipc.LegacyDarwinSocketPath)
		return ipc.LegacyDarwinSocketPath
	}
	return addr
}

// acquireListener returns the socket the IPC server should accept on.
//
// On darwin the LaunchDaemon plist declares the socket (Sockets.Listeners),
// so launchd owns it from boot and starts this process on the first connect;
// adopting that socket is what lets the GUI "start" the helper just by
// dialing, without an administrator prompt. ipc.Listen must NOT run in that
// case: it unlinks the path, which would orphan launchd's socket.
//
// Only "not launchd-managed" (dev run, test, old plist) falls back to
// listening ourselves. Any other activation error is fatal: continuing would
// leave launchd's connection pending and respawn the helper in a loop.
func acquireListener(addr string, ownerUID int, ownerSID string) (l net.Listener, listenAddr string, activated bool, err error) {
	if runtime.GOOS == "darwin" {
		ls, aerr := activateLaunchd()
		switch {
		case aerr == nil && len(ls) > 0:
			for _, extra := range ls[1:] {
				extra.Close()
			}
			return ls[0], addr, true, nil
		case aerr == nil, errors.Is(aerr, launchd.ErrNotManaged), errors.Is(aerr, launchd.ErrNoSocketEntry):
			slog.Info("launchd socket activation not in use; listening directly", "reason", aerr)
		default:
			return nil, addr, false, fmt.Errorf("launchd socket activation: %w", aerr)
		}
		addr = fallbackAddr(addr)
	}
	l, err = ipc.Listen(addr, ownerUID, ownerSID)
	if err != nil {
		return nil, addr, false, fmt.Errorf("listen %s: %w", addr, err)
	}
	return l, addr, false, nil
}

// Helper holds the helper process state.
type Helper struct {
	server      *ipc.Server
	activated   bool
	guiSeen     atomic.Bool
	guiSeenCh   chan struct{}
	guiSeenOnce sync.Once
	armedGrace  time.Duration

	manager  *tunnel.Manager
	firewall firewall.FirewallManager
	monitor  *reconnect.Monitor

	// connectMu serializes Connect/Disconnect calls. Without this, two
	// concurrent GUI connections could race on activeCfg, with the loser's
	// rollback overwriting the winner's config.
	connectMu sync.Mutex
	// Failed teardown exceptions, guarded by connectMu and retried by the
	// firewall safety net. They do not survive startup's anchor cleanup.
	permitRemovalRetries map[string]permitRemovalRetry

	// logLevel is the runtime-mutable slog level. Helper.SetLogLevel (and
	// the Settings UI) writes to this; the broadcast handler reads it for
	// every record. Info by default.
	logLevel *slog.LevelVar

	mu         sync.Mutex
	activeCfgs map[string]*domain.WireGuardConfig // cached for reconnect, keyed by tunnel name
	// watchdogBlocked prevents automation from bringing a tunnel back after
	// its loop watchdog forced it down. A manual Connect clears the block.
	watchdogBlocked map[string]struct{}

	// pendingDesired holds tunnels that are still wanted but not up: the
	// desired-state restore tried and failed to connect them (issue #44).
	// They live outside activeCfgs so status, health and firewall paths never
	// mistake them for running tunnels, but persistDesiredState writes them
	// back so the next wake/network trigger can retry. Guarded by mu.
	pendingDesired map[string]struct{}

	// desiredMu orders desired-state file writes against cleanup()'s clear,
	// so a connect finishing during shutdown can't rewrite the file after
	// a clean quit removed it (issue #44).
	desiredMu sync.Mutex

	// Firewall state saved during reconnect suspend/resume cycle.
	// These track what was active before suspend so resume can restore it.
	fwSavedKillSwitch bool

	// dnsProtectionWanted is the user's DNS-protection setting as last sent
	// by the GUI/CLI (or carried over by a crash restore). The rules
	// themselves are derived from it plus every connected tunnel by
	// reapplyDNSProtection (issue #48). Guarded by mu.
	dnsProtectionWanted bool
	// dnsAutoOff records an explicit "off" from the user while a Windows
	// full tunnel had DNS protection on automatically: it stays off until
	// the next full-tunnel connect, as before issue #48. Guarded by mu.
	dnsAutoOff bool
	// dnsMu serializes reapplyDNSProtection so each call renders a fresh
	// snapshot and the last one to run reflects the latest tunnel set.
	dnsMu sync.Mutex
	// Reconciliation journal, guarded by dnsMu. Only successful applies
	// advance dnsApplied; a failed OS operation remains pending for retry.
	dnsApplied    string
	dnsPending    string
	dnsRetryAt    time.Time
	dnsRetryDelay time.Duration
	dnsSuspended  bool

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

	// reevalMu serialises Automation re-evaluations. The three triggers
	// (SSID change, network change, poll) can fire concurrently; the
	// lock ensures only one evaluation drives connect/disconnect at a
	// time so they don't race on the same tunnel.
	reevalMu sync.Mutex

	// userTunnelStore reads .conf files from the user's home dir
	// (derived from the uid passed at launch). Needed so wifi rules
	// can connect tunnels that aren't already in activeCfgs — i.e.
	// the user has never opened them via the GUI in this session.
	userTunnelStore *storage.TunnelStore
	userAppSupport  string

	// dataDir persists helper state (crash-recovery journal, desired-tunnel
	// state). Stored on the Helper so user-intent transitions in handlers
	// can rewrite the desired-state file without threading the path through
	// every call (issue #44).
	dataDir string

	// restoreOnStart allows the startup desired-state restore. False on
	// Windows/Linux unless the GUI respawned this helper after watching
	// the previous one die: there the previous helper also dies at logoff
	// (and at a Fast Startup shutdown, which keeps the boot time), and a
	// fresh session must start with tunnels off (issue #44).
	restoreOnStart bool

	done        chan struct{}
	cleanupOnce sync.Once
}

// Run starts the helper listening on addr. Blocks until shutdown.
// ownerUID: UID to chown socket to (Unix only, use -1 on Windows).
// ownerSID: spawning user's SID (Windows only, "" on Unix) — scopes the
// pipe ACL and per-connection peer checks to that user (issue #20).
// dataDir: persistent data dir for crash recovery state.
func Run(addr string, ownerUID int, ownerSID, dataDir string, restoreDesired bool) (runErr error) {
	finished := make(chan struct{})
	shutdownReady := make(chan func(), 1)
	stopSignals := watchHelperSignals(shutdownReady, finished)
	defer stopSignals()
	defer close(finished)

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

	listener, addr, activated, err := acquireListener(addr, ownerUID, ownerSID)
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
		activated:       activated,
		guiSeenCh:       make(chan struct{}),
		server:          ipc.NewServer(listener, ownerUID).WithOwnerSID(ownerSID),
		manager:         manager,
		firewall:        fw,
		activeCfgs:      make(map[string]*domain.WireGuardConfig),
		watchdogBlocked: loadWatchdogBlocked(dataDir),
		pendingDesired:  make(map[string]struct{}),
		latencyByTunnel: make(map[string]float64),
		autoConnectedBy: make(map[string]string),
		logLevel:        new(slog.LevelVar), // defaults to Info
		done:            make(chan struct{}),
	}
	h.dataDir = dataDir
	// launchd restarts a crashed macOS helper on its own, so there the
	// boot-time check alone decides. Elsewhere only the GUI respawns the
	// helper, and only its mid-session recovery passes --restore-desired.
	h.restoreOnStart = runtime.GOOS == "darwin" || restoreDesired
	// A loop-watchdog trip runs the helper's teardown, not a bare
	// DisconnectTunnel inside the Manager (issue #49).
	manager.SetOnForcedDisconnect(h.handleForcedDisconnect)

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

	// Firewall crash recovery — restores OS-level firewall state (e.g. macOS
	// pf enabled/disabled) that the previous helper persisted to disk before
	// dying. Must run BEFORE any tunnel rebrings rules up, otherwise the new
	// rules would mask whatever stale state the crashed helper left behind.
	// No-op on Linux/Windows (their firewall implementations don't persist
	// state across crashes).
	if recovered := fw.RecoverFromCrash(); recovered {
		slog.Warn("recovered firewall state from previous crash")
	}

	// Reconnect monitor — uses cached config
	h.monitor = reconnect.NewMonitor(manager, h.reconnectFn, h.onReconnectState, reconnect.DefaultConfig())
	h.monitor.SetFirewallCallbacks(h.suspendFirewall, h.resumeFirewall)
	// Wake/network triggers must also fire when nothing is active but a
	// persisted desired state says tunnels are wanted (helper crash-restart
	// whose restore failed; issue #44).
	h.monitor.SetDesiredActiveFn(h.desiredActiveFn)
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
	h.server.OnConnect(func() { h.markGUISeen(); h.cancelShutdownTimer() })
	h.server.OnDisconnect(h.startShutdownTimer)
	// Arm the startup grace window now: a helper that never receives
	// a GUI connection must not run forever (see startupGrace). The
	// first OnConnect cancels it; the fire-time active-tunnel check
	// keeps a crash-recovered tunnel alive even with no GUI.
	h.armStartupGrace()

	// Start event emitter (diff loop)
	h.goSafe("eventLoop", h.eventLoop)

	// Start endpoint latency probe loop. Runs at a slow tick (~30s) so
	// it doesn't add measurable load; ICMP pings are blocking and the
	// goroutine is supervised by goSafe like every other long-running
	// helper background task.
	h.goSafe("latencyLoop", h.latencyLoop)
	h.goSafe("pingHealthLoop", h.pingHealthLoop)
	h.goSafe("dnsReconcileLoop", h.dnsReconcileLoop)

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
	// config.json. Kill switch / DNS protection are deliberately NOT
	// auto-applied here: they are firewall state transitions tied to the
	// connect path (see applyPostConnectFirewall); enabling them at boot
	// with no tunnel up would block all traffic, which is a product
	// decision, not a restore.
	if settings, err := h.loadUserSettings(); err == nil {
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
		if h.activated {
			select {
			case <-h.done:
				return
			case <-h.guiSeenCh:
			}
		}

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
		// polled elsewhere) rather than a direct read. Skip only when the
		// network is entirely unknown — acting on an unknown SSID would
		// let none_match rules disconnect a freshly crash-recovered
		// tunnel before we know what network we're on. Subnet-only rules
		// still get their first evaluation from the network-change / poll
		// trigger below.
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

	// Desired-state restore (issue #44): if the previous helper instance
	// died without a clean shutdown (crash during sleep, kill -9, upgrade
	// ForceShutdown), re-establish the tunnels it had up. Runs after the
	// settings restore and rule wiring above so the helper is fully
	// configured first, and async so a slow restore never delays the IPC
	// listener — the GUI's spawn path has a 30s readiness budget. goSafe
	// restarts the one-shot on panic only; a normal return is completion.
	h.goSafe("desiredStateRestore", h.restoreDesiredTunnels)

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
			// Exit non-zero: the LaunchDaemon restarts only on an
			// unsuccessful exit, and the restarted helper restores the
			// tunnels this one had (issue #44). Returning nil made main
			// exit 0, so a panic looked like a clean Quit.
			runErr = fmt.Errorf("helper panic: %v", r)
		}
	}()

	slog.Info("helper listening", "addr", addr, "pid", "daemon")
	shutdownReady <- h.shutdown

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
	// DNS rules must follow whatever is up afterwards, on every path —
	// including attempts the monitor didn't suspend/resume around (nothing
	// was up, or the suspend itself failed) (issue #48).
	defer func() {
		if dnsErr := h.reapplyDNSProtection(); dnsErr != nil {
			slog.Warn("reconnect: DNS protection rebuild failed", "error", dnsErr)
		}
	}()
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	// Tunnels that are wanted but not up because the helper restarted and
	// its startup restore failed (issue #44). They go through the full
	// connect path, not a bare manager connect: nothing about them is in
	// the firewall yet, and success must move them into activeCfgs.
	pending := h.pendingDesiredCfgs()

	if name != "" {
		cfg, ok := cfgs[name]
		if !ok {
			if pcfg, isPending := pending[name]; isPending {
				return h.connectPendingDesired(ctx, pcfg)
			}
			return fmt.Errorf("no cached config for tunnel %q", name)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reconnect %q cancelled before Connect: %w", name, err)
		}
		h.connectMu.Lock()
		defer h.connectMu.Unlock()
		if !h.stillCached(name) {
			return nil // disconnected while this retry waited (issue #44)
		}
		if latch, ok := h.manualLatchFor(name); ok && latch.disconnected {
			return reconnect.ErrNothingToReconnect
		}
		return alreadyConnectedIsOK(h.manager.ConnectWithContext(ctx, cfg))
	}

	// Legacy path: reconnect all tunnels.
	if len(cfgs) == 0 && len(pending) == 0 {
		return reconnect.ErrNothingToReconnect
	}
	var lastErr error
	attempted := 0
	for _, cfg := range cfgs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reconnect-all cancelled mid-loop: %w", err)
		}
		h.connectMu.Lock()
		// cfgs is a snapshot from before this retry waited on connectMu.
		// A Disconnect that ran meanwhile dropped the tunnel from
		// activeCfgs (and may have cancelled ctx); bringing it back from
		// the stale copy would undo the user's "off" (issue #44).
		latch, latched := h.manualLatchFor(cfg.Name)
		if ctx.Err() != nil || !h.stillCached(cfg.Name) || (latched && latch.disconnected) {
			h.connectMu.Unlock()
			continue
		}
		attempted++
		var err error
		if h.firewall.IsKillSwitchEnabled() {
			// The monitor did not suspend the firewall this attempt (nothing
			// was up — e.g. the previous attempt failed and resume put the
			// base blockade back). A bare connect would run under the
			// blockade, which drops DNS and WireGuard UDP, and nothing
			// would ever permit the new interface. doConnectHeld lifts the
			// blockade for the connect and rebuilds it with this tunnel.
			err = connectUnderKillSwitch(h, cfg)
		} else {
			err = h.manager.ConnectWithContext(ctx, cfg)
		}
		h.connectMu.Unlock()
		// Already up (a GUI connect raced the retry) is the goal state.
		var te *tunnel.TunnelError
		if errors.As(err, &te) && te.Kind == tunnel.ErrAlreadyConnected {
			err = nil
		}
		if err != nil {
			lastErr = err
		}
	}
	for _, cfg := range pending {
		if err := h.connectPendingDesired(ctx, cfg); err != nil {
			lastErr = err
		}
	}
	if attempted == 0 && len(pending) == 0 {
		return reconnect.ErrNothingToReconnect
	}
	return lastErr
}

// stillCached reports whether name is still in activeCfgs.
func (h *Helper) stillCached(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.activeCfgs[name]
	return ok
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

// markGUISeen records the first GUI attachment and releases anything waiting
// on it (the startup rule re-evaluation).
func (h *Helper) markGUISeen() {
	h.guiSeen.Store(true)
	h.guiSeenOnce.Do(func() {
		if h.guiSeenCh != nil {
			close(h.guiSeenCh)
		}
	})
}

// armStartupGrace arms the no-GUI-yet window Run starts with: the short
// activatedStartupGrace for a launchd-started helper, startupGrace otherwise.
func (h *Helper) armStartupGrace() {
	h.armShutdownTimer(startupGraceFor(h.activated), "startup, no GUI connected yet")
}

// armShutdownTimer preserves active and pending desired tunnels while idle.
func (h *Helper) armShutdownTimer(grace time.Duration, reason string) {
	active := ""
	if h.manager != nil {
		active = h.manager.ActiveTunnel()
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// A tunnel waiting on a restore retry is still wanted (issue #44): exit
	// now and nothing retries it until the GUI next starts the helper.
	if active == "" && len(h.pendingDesired) > 0 {
		active = "(pending restore)"
	}
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

	h.armedGrace = grace
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
		pending := len(h.pendingDesired)
		h.mu.Unlock()
		if current != t {
			return
		}
		if pending > 0 {
			slog.Info("shutdown timer fired but a restore is pending — aborting shutdown",
				"pending", pending)
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

// suspendFirewall saves the current firewall state and disables all firewall
// rules. Called by the reconnect monitor before Disconnect so that old pf rules
// referencing the previous utun interface name don't block the new connection.
func (h *Helper) suspendFirewall() error {
	// Under connectMu, like resumeFirewall and handleSetKillSwitch: a user
	// turning the kill switch off between the read below and the saved
	// flag would otherwise be overwritten with "on" and undone by resume
	// (issue #44). Only the monitor goroutine calls this.
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	ksEnabled := h.firewall.IsKillSwitchEnabled()
	dnsEnabled := h.firewall.IsDNSProtectionEnabled()

	h.mu.Lock()
	h.fwSavedKillSwitch = ksEnabled
	h.mu.Unlock()
	// DNS protection needs no saved copy: resume re-derives the rules from
	// the setting and the reconnected tunnels (issue #48).

	if !ksEnabled && !dnsEnabled {
		slog.Debug("suspendFirewall: no firewall rules active, nothing to suspend")
		return nil
	}
	h.dnsMu.Lock()
	h.dnsSuspended = true
	h.dnsApplied = ""
	h.dnsMu.Unlock()

	slog.Info("suspending firewall rules for reconnect",
		"kill_switch", ksEnabled, "dns_protection", dnsEnabled)

	// Disable DNS protection first (it may be a sub-anchor of the kill switch).
	dnsDisabled := false
	if dnsEnabled {
		// Under dnsMu so it can't interleave with a reapply.
		h.dnsMu.Lock()
		err := h.firewall.DisableDNSProtection()
		h.dnsMu.Unlock()
		if err != nil {
			slog.Warn("suspendFirewall: failed to disable DNS protection", "error", err)
			h.dnsMu.Lock()
			h.dnsSuspended = false
			h.dnsMu.Unlock()
			return fmt.Errorf("suspendFirewall: disable DNS protection: %w", err)
		} else {
			dnsDisabled = true
		}
	}
	if ksEnabled {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			h.dnsMu.Lock()
			h.dnsSuspended = false
			h.dnsMu.Unlock()
			// We just turned DNS protection off but the kill switch
			// is still on — that's an inconsistent state. Try to
			// re-enable DNS protection so the system goes back to
			// where it was, and surface the error to the caller so
			// resumeFirewall isn't called against a state that
			// already half-resumed.
			if dnsDisabled {
				if rollbackErr := h.reapplyDNSProtection(); rollbackErr != nil {
					slog.Error("suspendFirewall: DNS protection rollback ALSO failed",
						"error", rollbackErr)
				}
			}
			return fmt.Errorf("suspendFirewall: disable kill switch: %w", err)
		}
	}

	return nil
}

// resumeFirewall re-enables firewall rules that were active before the
// reconnect suspend. It reads the NEW interface name and endpoints from the
// tunnel manager so the pf rules match the newly created utun interface.
func (h *Helper) resumeFirewall() error {
	// The kill-switch half is read and acted on under connectMu, so a user
	// turning the kill switch off mid-reconnect (handleSetKillSwitch clears
	// the flag under connectMu) can't be undone here (issue #44).
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	h.dnsMu.Lock()
	h.dnsSuspended = false
	h.dnsApplied = ""
	h.dnsMu.Unlock()
	h.mu.Lock()
	restoreKS := h.fwSavedKillSwitch
	// Clear saved state so a second resume is a no-op.
	h.fwSavedKillSwitch = false
	h.mu.Unlock()

	slog.Info("resuming firewall rules after reconnect", "kill_switch", restoreKS)

	if restoreKS {
		// Rebuild from every active tunnel, not just the first one: with
		// several tunnels up, a single-interface EnableKillSwitch left the
		// others fenced out after every wake. With none up (reconnect
		// failed) this installs the base blockade, keeping the kill switch
		// on instead of silently dropping it. connectMu is held (above).
		if err := h.enableKillSwitchForActiveTunnels(); err != nil {
			slog.Error("resumeFirewall: failed to re-enable kill switch", "error", err)
			return fmt.Errorf("resumeFirewall: enable kill switch: %w", err)
		}
	}

	// Rebuild DNS protection for every reconnected tunnel. The old code
	// re-enabled it for one interface with servers taken from whichever
	// activeCfgs entry map iteration returned first — a random pairing.
	if err := h.reapplyDNSProtection(); err != nil {
		slog.Error("resumeFirewall: failed to re-enable DNS protection", "error", err)
		return fmt.Errorf("resumeFirewall: enable DNS protection: %w", err)
	}

	return nil
}

func (h *Helper) cleanup() {
	h.cleanupOnce.Do(func() {
		slog.Info("helper cleanup starting",
			"connected", h.manager.IsConnected(),
			"call_stack", string(debug.Stack()))
		close(h.done)
		h.mu.Lock()
		blocked := make([]string, 0, len(h.watchdogBlocked))
		for name := range h.watchdogBlocked {
			blocked = append(blocked, name)
		}
		h.mu.Unlock()
		// Clean shutdown withdraws all wanted tunnels, but preserves
		// watchdog blocks so automation cannot resurrect a suspected loop
		// when the helper starts again. persistDesiredState checks h.done
		// under desiredMu, so no later write can restore wanted tunnels.
		h.desiredMu.Lock()
		if err := saveDesiredIntent(h.dataDir, desiredStateJSON{WatchdogBlocked: blocked}); err != nil {
			slog.Warn("desired-state: preserve watchdog blocks during shutdown failed", "error", err)
		}
		h.desiredMu.Unlock()
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
