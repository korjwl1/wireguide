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
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
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
	clients       *ipc.ClientHolder
	app           *application.App
}

// NewTunnelService creates a service. Set the app reference via SetApp()
// after application.New() for dialog support.
func NewTunnelService(ts *storage.TunnelStore, ss *storage.SettingsStore, clients *ipc.ClientHolder) *TunnelService {
	return &TunnelService{
		tunnelStore:   ts,
		settingsStore: ss,
		clients:       clients,
	}
}

// SetApp injects the Wails app for dialog access.
func (s *TunnelService) SetApp(app *application.App) {
	s.app = app
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
	Name        string `json:"name"`
	IsConnected bool   `json:"is_connected"`
	Endpoint    string `json:"endpoint"`
}

// ConnectionStatus is re-exported from the domain package so Wails bindings
// expose the same type that the helper broadcasts — preventing field drift
// between wire format and frontend expectations.
type ConnectionStatus = domain.ConnectionStatus
