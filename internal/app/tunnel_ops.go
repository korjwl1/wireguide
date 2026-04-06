package app

import (
	"fmt"
	"log/slog"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// ListTunnelsLocal returns stored tunnels WITHOUT asking the helper which one
// is active — callers that already know the active name (e.g. the system
// tray, which tracks it from the status event stream) should use this to
// avoid an IPC round-trip on every refresh. IsConnected is always false in
// the returned slice; the caller is responsible for applying its own
// active-name match.
func (s *TunnelService) ListTunnelsLocal() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}
	var result []TunnelInfo
	for _, name := range names {
		cfg, err := s.tunnelStore.Load(name)
		if err != nil {
			slog.Warn("skipping broken tunnel config", "name", name, "error", err)
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		result = append(result, TunnelInfo{
			Name:       name,
			Endpoint:   endpoint,
			HasScripts: cfg.HasScripts(),
		})
	}
	return result, nil
}

// ListTunnels returns every stored tunnel with its summary info.
//
// The active-tunnel marker used to come from an IPC round-trip on every call.
// That made the tray's rebuild-menu path slow when it was being invoked on
// the status event stream. The frontend now learns the active tunnel from
// the status event itself, and the tray caches it internally — so this
// function stays fully local (disk-only, no IPC) and returns IsConnected
// purely as a best-effort flag based on a single active-name probe that is
// safe to skip entirely on slow paths.
func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}

	// One cheap probe for the active tunnel — used by the frontend's initial
	// load before it has received its first status event. The tray no longer
	// relies on this (it tracks active tunnel via the status stream).
	var active ipc.StringResponse
	_ = s.call(ipc.MethodActiveName, nil, &active)

	var result []TunnelInfo
	for _, name := range names {
		cfg, err := s.tunnelStore.Load(name)
		if err != nil {
			slog.Warn("skipping broken tunnel config", "name", name, "error", err)
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		result = append(result, TunnelInfo{
			Name:        name,
			IsConnected: name == active.Value,
			Endpoint:    endpoint,
			HasScripts:  cfg.HasScripts(),
		})
	}
	return result, nil
}

// Connect loads a tunnel config from local storage and asks the helper to
// bring it up. The helper re-validates server-side.
//
// When the config contains scripts and scriptsAllowed is true, the helper
// verifies the scripts against its persistent allowlist. If the scripts are
// not yet approved, the helper rejects with ErrCodeScriptsNotApproved and
// this method automatically sends an ApproveScripts RPC (the user already
// consented via the GUI's script warning dialog) then retries the connect.
func (s *TunnelService) Connect(name string, scriptsAllowed bool) error {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return fmt.Errorf("loading tunnel %s: %w", name, err)
	}

	// Mark the RPC as in-flight so the health monitor doesn't falsely
	// detect helper death while the server is busy processing Connect
	// (which blocks the per-connection request loop, preventing pings).
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()

	err = s.call(ipc.MethodConnect, ipc.ConnectRequest{
		Config:         cfg,
		ScriptsAllowed: scriptsAllowed,
	}, nil)

	// If the helper rejected because scripts aren't in the allowlist yet,
	// send the approval (the user already consented at the GUI level) and
	// retry. This only happens once per unique script set.
	if isScriptsNotApproved(err) && scriptsAllowed {
		slog.Info("scripts not yet in helper allowlist, approving",
			"tunnel", name)
		if approveErr := s.call(ipc.MethodApproveScripts, ipc.ApproveScriptsRequest{
			Config: cfg,
		}, nil); approveErr != nil {
			return fmt.Errorf("approving scripts: %w", approveErr)
		}
		// Retry the connect — scripts are now in the allowlist.
		return s.call(ipc.MethodConnect, ipc.ConnectRequest{
			Config:         cfg,
			ScriptsAllowed: scriptsAllowed,
		}, nil)
	}

	return err
}

// isScriptsNotApproved checks whether an error is the specific
// ErrCodeScriptsNotApproved rejection from the helper.
func isScriptsNotApproved(err error) bool {
	if err == nil {
		return false
	}
	if ipcErr, ok := err.(*ipc.Error); ok {
		return ipcErr.Code == ipc.ErrCodeScriptsNotApproved
	}
	return false
}

// Disconnect tears down whatever tunnel the helper currently has active.
func (s *TunnelService) Disconnect() error {
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	return s.call(ipc.MethodDisconnect, nil, nil)
}

// GetStatus queries the helper for the current connection status. IPC errors
// are surfaced to the caller — the frontend needs to distinguish "helper says
// disconnected" from "helper unreachable".
func (s *TunnelService) GetStatus() (*ConnectionStatus, error) {
	var status ConnectionStatus
	if err := s.call(ipc.MethodStatus, nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetTunnelDetail returns the full WireGuardConfig for a tunnel. Used by the
// detail pane to show allowed IPs, DNS, public keys, etc.
func (s *TunnelService) GetTunnelDetail(name string) (*domain.WireGuardConfig, error) {
	return s.tunnelStore.Load(name)
}

// DeleteTunnel removes a tunnel from local storage. Rejects deletion of the
// currently connected tunnel (would orphan the interface).
func (s *TunnelService) DeleteTunnel(name string) error {
	var active ipc.StringResponse
	if err := s.call(ipc.MethodActiveName, nil, &active); err != nil {
		return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", err)
	}
	if active.Value == name {
		return fmt.Errorf("cannot delete connected tunnel %q — disconnect first", name)
	}
	return s.tunnelStore.Delete(name)
}

// RenameTunnel changes a tunnel's name. Rejects rename of the connected
// tunnel since the interface name is derived from it.
func (s *TunnelService) RenameTunnel(oldName, newName string) error {
	if err := storage.ValidateTunnelName(newName); err != nil {
		return err
	}
	var active ipc.StringResponse
	if err := s.call(ipc.MethodActiveName, nil, &active); err != nil {
		return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", err)
	}
	if active.Value == oldName {
		return fmt.Errorf("cannot rename connected tunnel %q — disconnect first", oldName)
	}
	return s.tunnelStore.Rename(oldName, newName)
}

// TunnelExists reports whether a tunnel with the given name is stored.
func (s *TunnelService) TunnelExists(name string) bool {
	return s.tunnelStore.Exists(name)
}
