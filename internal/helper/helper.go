// Package helper owns privileged tunnel, firewall and automation operations.
// It accepts authenticated local IPC calls and reads the owning user's tunnel
// configs and settings for automation and same-boot crash recovery. Storage
// access is coordinated with tunnel lifecycle transitions through connectMu.
package helper

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/network"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/korjwl1/wireguide/internal/wifi"
)

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

// Helper holds the helper process state.
type Helper struct {
	server      *ipc.Server
	activated   bool
	guiSeen     atomic.Bool
	guiSeenCh   chan struct{}
	guiSeenOnce sync.Once
	armedGrace  time.Duration
	// Startup restore owns a lifetime lease until its first attempts finish.
	// Guarded by mu; connect rollback and pending registration are separate.
	restoreInProgress bool

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

	// Kill-switch intent is independent of OS application success and survives
	// reconnect suspension. Guarded by mu, including desired-state reads.
	killSwitchWanted bool
	ksIntentKnown    bool
	// Saved On applies only during valid crash recovery, never to an idle
	// startup without tunnels. Live intent takes priority. Guarded by mu.
	ksRestoreOn bool
	// Successful suspend calls own one level each. Only the last resume may
	// apply rules. Guarded by connectMu, like the KS reconciliation journal.
	fwSuspendDepth     int
	ksIfaces           map[string]struct{}
	ksApplied          string
	ksPending          string
	ksRetryAt          time.Time
	ksRetryDelay       time.Duration
	fwRepairRetryAt    time.Time
	fwRepairRetryDelay time.Duration

	// dnsProtectionWanted is the user's DNS-protection setting as last sent
	// by the GUI/CLI (or carried over by a crash restore). The rules
	// themselves are derived from it plus every connected tunnel by
	// reapplyDNSProtection (issue #48). Guarded by mu.
	dnsProtectionWanted bool
	// A loaded user setting or live IPC update takes precedence over a
	// potentially older crash journal. Guarded by mu.
	dnsIntentKnown bool
	// A live update also vetoes replay of the journal's automatic-DNS Off.
	dnsIntentExplicit bool
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
	wifiMu            sync.Mutex
	autoConnectedBy   map[string]string
	automationSkipped map[string]string // last reported LAN overlap, guarded by wifiMu
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
	settle      *automation.SettleTracker
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
	userFileUID     *int
	userFileSID     string

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
	var emergencyCleanup atomic.Pointer[func()]
	stopSignals := watchHelperSignals(shutdownReady, finished, func() {
		if f := emergencyCleanup.Load(); f != nil {
			(*f)()
		}
	})
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
	fallback := func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := fw.Cleanup(); err != nil {
				slog.Warn("signal fallback: firewall cleanup failed", "error", err)
			}
		}()
		go func() { defer wg.Done(); manager.RestoreDNSBestEffort() }()
		wg.Wait()
	}
	emergencyCleanup.Store(&fallback)

	h.dataDir = dataDir
	// launchd restarts a crashed macOS helper on its own, so there the
	// boot-time check alone decides. Elsewhere only the GUI respawns the
	// helper, and only its mid-session recovery passes --restore-desired.
	h.restoreOnStart = runtime.GOOS == "darwin" || restoreDesired
	// A loop-watchdog trip runs the helper's teardown, not a bare
	// DisconnectTunnel inside the Manager (issue #49).
	manager.SetOnForcedDisconnect(h.handleForcedDisconnect)
	manager.SetOnRecoveryWarning(func(name string, err error) {
		h.server.Broadcast(ipc.EventRecoveryWarning, ipc.RecoveryWarningPayload{TunnelName: name, Detail: err.Error()})
	})

	// Derive the user's Application Support dir from the uid the
	// LaunchDaemon plist passed in (`--uid=501` typically). Helper
	// runs as root, so os.UserHomeDir() returns /var/root — useless.
	// Each platform derives the profile directory of the invoking user.
	if appSupport, err := deriveUserAppSupport(ownerUID); err == nil && appSupport != "" {
		h.userAppSupport = appSupport
		h.userFileUID = &ownerUID
		h.userFileSID = ownerSID
		h.userTunnelStore = storage.NewUserTunnelStore(filepath.Join(appSupport, "tunnels"), ownerUID, ownerSID)
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
	manager.AdoptPendingRecovery()

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
	h.monitor.SetReconnectPreflight(h.prepareReconnect)
	// Wake/network triggers must also fire when nothing is active but a
	// persisted desired state says tunnels are wanted (helper crash-restart
	// whose restore failed; issue #44).
	h.monitor.SetDesiredActiveFn(h.desiredActiveFn)
	h.restoreUserSettings()
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
	h.mu.Lock()
	h.restoreInProgress = true
	h.mu.Unlock()
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
	// abrupt termination), re-establish the tunnels it had up. Runs after the
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
