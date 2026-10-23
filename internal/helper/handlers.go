package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/version"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// registerHandlers binds every RPC method to a Helper method. Splitting the
// handlers into named methods (vs inline closures) makes them directly unit
// testable — `handler := &Helper{manager: mockMgr}; handler.handleConnect(...)`.
func (h *Helper) registerHandlers() {
	h.server.Handle(ipc.MethodPing, h.handlePing)
	h.server.Handle(ipc.MethodShutdown, h.handleShutdown)
	h.server.Handle(ipc.MethodForceShutdown, h.handleForceShutdown)
	h.server.Handle(ipc.MethodRequestQuit, h.handleRequestQuit)
	h.server.Handle(ipc.MethodSetLogLevel, h.handleSetLogLevel)
	h.server.Handle(ipc.MethodConnect, h.handleConnect)
	h.server.Handle(ipc.MethodDisconnect, h.handleDisconnect)
	h.server.Handle(ipc.MethodStatus, h.handleStatus)
	h.server.Handle(ipc.MethodIsConnected, h.handleIsConnected)
	h.server.Handle(ipc.MethodActiveName, h.handleActiveName)
	h.server.Handle(ipc.MethodActiveTunnels, h.handleActiveTunnels)
	h.server.Handle(ipc.MethodRename, h.handleRename)
	h.server.Handle(ipc.MethodDelete, h.handleDelete)
	h.server.Handle(ipc.MethodSetKillSwitch, h.handleSetKillSwitch)
	h.server.Handle(ipc.MethodSetDNSProtection, h.handleSetDNSProtection)
	h.server.Handle(ipc.MethodSetHealthCheck, h.handleSetHealthCheck)
	h.server.Handle(ipc.MethodSetPinInterface, h.handleSetPinInterface)
	h.server.Handle(ipc.MethodReportSSID, h.handleReportSSID)
	h.server.Handle(ipc.MethodAutomationPreview, h.handleAutomationPreview)
}

func (h *Helper) handleSetLogLevel(params json.RawMessage) (interface{}, error) {
	var req ipc.SetLogLevelRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	lvl := parseLevel(req.Level)
	h.logLevel.Set(lvl)
	slog.Info("log level changed", "level", req.Level)
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{LogLevel: &req.Level})
	return ipc.Empty{}, nil
}

func (h *Helper) handlePing(params json.RawMessage) (interface{}, error) {
	return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: version.Current, GUIAttached: h.server != nil && h.server.HasControlConn(),
		PID: os.Getpid(), WantedTunnels: h.wantedTunnelNames()}, nil
}

func (h *Helper) handleShutdown(params json.RawMessage) (interface{}, error) {
	go func() {
		time.Sleep(100 * time.Millisecond) // let the response go out first
		h.shutdown()
	}()
	return ipc.Empty{}, nil
}

// handleRequestQuit implements `wireguide ctl stop` — bring the whole app
// down, GUI included.
//
// Two cases, because "stop" has to mean the same thing either way:
//
//   - A GUI is attached: broadcast EventQuit and let the GUI terminate
//     itself. Its normal quit path disconnects tunnels and then stops us.
//     We must NOT shut down directly here — the GUI's health monitor would
//     see the helper vanish and respawn it, which on macOS means an admin
//     password prompt seconds after the user asked everything to stop.
//
//   - No GUI attached (helper running solo): nothing will relay the quit,
//     so shut ourselves down on the same grace-free path as MethodShutdown.
//
// Reports which branch ran so `ctl stop` can tell the user whether it
// stopped an app or just a stray helper.
func (h *Helper) handleRequestQuit(params json.RawMessage) (interface{}, error) {
	if h.server.HasControlConn() {
		slog.Info("quit requested via CLI — asking the GUI to terminate")
		h.server.Broadcast(ipc.EventQuit, ipc.Empty{})
		return ipc.RequestQuitResponse{NotifiedGUI: true}, nil
	}
	slog.Info("quit requested via CLI — no GUI attached, shutting the helper down")
	go func() {
		time.Sleep(100 * time.Millisecond) // let the response go out first
		h.shutdown()
	}()
	return ipc.RequestQuitResponse{NotifiedGUI: false}, nil
}

// handleForceShutdown attempts normal cleanup with a three-second deadline.
// It is the upgrade fallback for an unresponsive graceful shutdown. Timeout
// exits with failure so journals can recover any incomplete OS teardown.
func (h *Helper) handleForceShutdown(params json.RawMessage) (interface{}, error) {
	go func() {
		// First, give the response 50ms to actually reach the client.
		// Then run normal cleanup with a 3s hard cap, then exit.
		time.Sleep(50 * time.Millisecond)
		slog.Warn("helper ForceShutdown requested, cleaning firewall then exiting")
		done := make(chan struct{})
		go func() { defer close(done); h.cleanup() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			slog.Warn("ForceShutdown: cleanup timed out; exiting for crash recovery")
			os.Exit(1)
		}
		os.Exit(0)
	}()
	return ipc.Empty{}, nil
}

// handleRename atomically renames a tunnel's .conf file. Holds the same
// connectMu that handleConnect/handleDisconnect take, so a Connect arriving
// during the rename blocks until we finish — closing the GUI-side TOCTOU
// where the user could rename a tunnel just as it was being auto-connected.
//
// Active-tunnel rename is rejected: the WireGuard interface name is derived
// from the tunnel name on macOS, so renaming would orphan the running utun.
func (h *Helper) handleStatus(params json.RawMessage) (interface{}, error) {
	return h.statusDTO(), nil
}

func (h *Helper) handleIsConnected(params json.RawMessage) (interface{}, error) {
	return ipc.BoolResponse{Value: h.manager.IsConnected()}, nil
}

func (h *Helper) handleActiveName(params json.RawMessage) (interface{}, error) {
	return ipc.StringResponse{Value: h.manager.ActiveTunnel()}, nil
}

func (h *Helper) handleActiveTunnels(params json.RawMessage) (interface{}, error) {
	return ipc.ActiveTunnelsResponse{Names: h.manager.ActiveTunnels()}, nil
}

func (h *Helper) handleSetKillSwitch(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	var req ipc.KillSwitchRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.killSwitchWanted = req.Enabled
	h.ksIntentKnown = true
	h.mu.Unlock()
	// Persist the requested setting even when applying it fails. A retry must
	// follow the last explicit user intent, including Off during reconnect.
	h.persistDesiredState()
	if err := h.reconcileKillSwitch(true, time.Now()); err != nil {
		return nil, err
	}
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{KillSwitch: &req.Enabled})
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetDNSProtection(params json.RawMessage) (interface{}, error) {
	var req ipc.DNSProtectionRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	// The helper derives the allowed servers from every connected tunnel
	// itself; req.DNSServers (one tunnel's list, from older GUI/CLI builds)
	// is ignored (issue #48). With no tunnel up the setting is recorded and
	// the next connect installs the rules.
	h.mu.Lock()
	h.dnsProtectionWanted = req.Enabled
	h.dnsIntentKnown = true
	h.dnsIntentExplicit = true
	h.dnsAutoOff = !req.Enabled
	h.mu.Unlock()
	h.persistDesiredState()
	if err := h.reapplyDNSProtection(); err != nil {
		return nil, err
	}
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{DNSProtection: &req.Enabled})
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetHealthCheck(params json.RawMessage) (interface{}, error) {
	var req ipc.SetHealthCheckRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if h.monitor == nil {
		// Should be impossible — monitor is created unconditionally in Run().
		// If it's nil, helper init was broken; surface that instead of
		// pretending the setting was applied.
		return nil, fmt.Errorf("reconnect monitor not initialised")
	}
	h.monitor.SetHealthCheck(req.Enabled)
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{HealthCheck: &req.Enabled})
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetPinInterface(params json.RawMessage) (interface{}, error) {
	var req ipc.SetPinInterfaceRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if err := h.manager.SetPinInterface(req.Enabled); err != nil {
		return nil, err
	}
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{PinInterface: &req.Enabled})
	return ipc.Empty{}, nil
}

// handleReportSSID receives the current SSID from the GUI process.
// On macOS 14+ the helper (root LaunchDaemon) cannot read SSID via
// CoreWLAN because Location Services permission is bundle-scoped; the
// GUI holds the permission and forwards changes here.
func (h *Helper) handleReportSSID(params json.RawMessage) (interface{}, error) {
	var req ipc.ReportSSIDRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if h.wifiMon == nil {
		// Should be impossible — wifiMon is created unconditionally in Run().
		// Surfacing the error lets the GUI know Wi-Fi rules won't fire,
		// instead of silently swallowing every SSID update.
		return nil, fmt.Errorf("wifi monitor not initialised")
	}
	// Stamp the gateway BEFORE ReportExternalSSID: its onChanged callback
	// re-evaluates automation synchronously, and the staleness check must
	// see the fresh stamp or it would invalidate the SSID we're delivering.
	gw := wifi.GatewayMAC()
	h.wifiMu.Lock()
	h.ssidStampGW = gw
	h.ssidFromGUI = true
	h.wifiMu.Unlock()
	h.wifiMon.ReportExternalSSID(req.SSID)
	return ipc.Empty{}, nil
}
