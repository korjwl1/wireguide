// Package app provides Wails bindings bridging the Svelte frontend to the
// IPC helper client and local storage.
//
// The package is split across four files so that each has a single reason
// to change:
//   - app.go          (this file)    — TunnelService facade, constructor, shared types
//   - tunnel_ops.go                  — tunnel lifecycle: connect, disconnect, list, status, rename, delete
//   - file_ops.go                    — file/dialog operations: import, export, read, parse, edit
//   - settings_ops.go                — settings + firewall toggles
package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/update"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// TunnelService is the Wails-bound service.
// Storage (tunnel files, settings) stays in the GUI process.
// Tunnel operations go through the helper via an ipc.ClientHolder (so the
// helper can be re-spawned and the connection swapped without rebuilding
// the whole service graph).
type TunnelService struct {
	tunnelStore   *storage.TunnelStore
	settingsStore *storage.SettingsStore
	historyStore  *storage.HistoryStore
	clients       *ipc.ClientHolder
	app           *application.App

	// updateScheduler + updateStore are wired in by the GUI Run() entry
	// after the Wails service registers (we can't inject them at
	// construction time because the scheduler needs the app reference to
	// emit events). Both may stay nil in non-GUI test contexts; the
	// CheckForUpdate / DismissUpdate methods fall back to one-shot
	// behaviour in that case.
	updateScheduler *update.Scheduler
	updateStore     *update.StateStore

	// activeSessions maps tunnel name → open history session ID. Used by
	// ReconcileHistoryFromStatus to identify which row to close when a
	// tunnel disappears from the active set; sync.Map keeps the per-event
	// lookup lock-free against concurrent Connect / Disconnect.
	activeSessions sync.Map

	// lastKnownStats caches the most recent rx/tx + reason hint (see
	// lastKnownTunnelStats) for each currently-active tunnel. The reconcile
	// path looks this up when a tunnel disappears so the closed history
	// session reflects real bytes transferred — without it, helper-driven
	// disconnects (Wi-Fi rule, auto-reconnect cycle, etc.) would record
	// sessions with rx=0/tx=0 because the disappearance status event itself
	// doesn't carry the gone tunnel's counters.
	lastKnownStats sync.Map

	// reconcileMu guards lastReconcileSig — used by ReconcileHistoryFromStatus
	// to fast-skip the active-set diff when nothing changed since the prior
	// status event. The status stream is 1 Hz; without the skip every event
	// would walk the activeSessions sync.Map even in the steady state.
	reconcileMu      sync.Mutex
	lastReconcileSig string
}

// lastKnownTunnelStats is the value type for TunnelService.lastKnownStats.
//
// reason is a hint set by user-initiated Disconnect / DisconnectTunnel
// before the IPC tear-down call. Reconcile reads it on close so the
// resulting history row is labelled "user" instead of the default
// "reconnect" — without this, every user disconnect would look
// indistinguishable from a helper-driven one in the timeline.
type lastKnownTunnelStats struct {
	rx     int64
	tx     int64
	reason string
}

// NewTunnelService creates a service. Set the app reference via SetApp()
// after application.New() for dialog support.
func NewTunnelService(ts *storage.TunnelStore, ss *storage.SettingsStore, hs *storage.HistoryStore, clients *ipc.ClientHolder) *TunnelService {
	return &TunnelService{
		tunnelStore:   ts,
		settingsStore: ss,
		historyStore:  hs,
		clients:       clients,
	}
}

// SetApp injects the Wails app for dialog access.
func (s *TunnelService) SetApp(app *application.App) {
	s.app = app
}

// SetUpdateScheduler injects the periodic update-check scheduler and its
// persistent state store. Called once from gui.Run() after the Wails app
// is constructed. The frontend's "Check now" / dismiss / last-checked
// queries route through these.
func (s *TunnelService) SetUpdateScheduler(sched *update.Scheduler, store *update.StateStore) {
	s.updateScheduler = sched
	s.updateStore = store
}

// errHelperUnavailable is the error returned when the IPC client has been
// torn down (e.g. during app shutdown). Using a sentinel keeps every RPC
// wrapper method uniform.
var errHelperUnavailable = fmt.Errorf("helper connection not available")

// call performs an RPC against the current helper client. Fetches the client
// fresh each call so a helper restart (which swaps the holder's client)
// takes effect immediately. Returns `errHelperUnavailable` if the holder has
// been closed — this prevents nil-pointer panics in the narrow window
// between doShutdown() and Wails app termination.
func (s *TunnelService) call(method string, params interface{}, result interface{}) error {
	c := s.clients.Get()
	if c == nil {
		return errHelperUnavailable
	}
	return c.Call(method, params, result)
}

// callLong performs an RPC with a generous timeout for operations that may
// take many seconds (Connect, Disconnect). The default 10-second timeout
// is too short for Connect, which involves DNS resolution + route setup +
// networksetup DNS configuration across all services (can take 15+ seconds
// on a Mac with many network services). If the client times out before the
// server finishes, the tunnel gets connected server-side but the GUI sees
// a false error, and the health monitor may trigger unnecessary recovery.
func (s *TunnelService) callLong(method string, params interface{}, result interface{}) error {
	c := s.clients.Get()
	if c == nil {
		return errHelperUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return c.CallWithContext(ctx, method, params, result)
}

// TunnelInfo is the summary shown in the tunnel list.
type TunnelInfo struct {
	Name               string `json:"name"`
	IsConnected        bool   `json:"is_connected"`
	Endpoint           string `json:"endpoint"`
	Notes              string `json:"notes,omitempty"`
	LatencyProbeTarget string `json:"latency_probe_target,omitempty"`
	// CreatedAtUnix is the .conf file's mtime; LastUsedUnix is the most
	// recent connection start from history (0 if never connected). Both
	// feed the tunnel-list "date added" / "last used" sort (issue #17).
	CreatedAtUnix int64 `json:"created_at_unix,omitempty"`
	LastUsedUnix  int64 `json:"last_used_unix,omitempty"`
}

// ConnectionStatus is re-exported from the domain package so Wails bindings
// expose the same type that the helper broadcasts — preventing field drift
// between wire format and frontend expectations.
type ConnectionStatus = domain.ConnectionStatus
