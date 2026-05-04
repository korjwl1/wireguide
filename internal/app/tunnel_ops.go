package app

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
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
			Name:     name,
			Endpoint: endpoint,
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
		})
	}
	return result, nil
}

// CheckConflicts loads a tunnel's config and scans local network interfaces
// for routing overlaps (e.g. Tailscale, another WireGuard instance). Runs
// entirely in the GUI process — no IPC needed. The frontend calls this before
// Connect so it can show a warning dialog if conflicts exist.
func (s *TunnelService) CheckConflicts(name string) ([]tunnel.ConflictInfo, error) {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return nil, fmt.Errorf("loading tunnel %s: %w", name, err)
	}
	var allowedIPs []string
	for _, peer := range cfg.Peers {
		allowedIPs = append(allowedIPs, peer.AllowedIPs...)
	}
	conflicts, err := tunnel.CheckConflicts(allowedIPs)
	if err != nil {
		slog.Warn("conflict check failed", "tunnel", name, "error", err)
		// Non-fatal — don't block connect if the scan itself fails.
		return nil, nil
	}
	return conflicts, nil
}

// Connect loads a tunnel config from local storage and asks the helper to
// bring it up. The helper re-validates server-side.
func (s *TunnelService) Connect(name string) error {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return fmt.Errorf("loading tunnel %s: %w", name, err)
	}

	// Mark the RPC as in-flight so the health monitor doesn't falsely
	// detect helper death while the server is busy processing Connect
	// (which blocks the per-connection request loop, preventing pings).
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()

	return s.callLong(ipc.MethodConnect, ipc.ConnectRequest{
		Config: cfg,
	}, nil)
}

// Disconnect tears down whatever tunnel the helper currently has active.
// If the call fails with a "client closed" error (the health monitor may have
// swapped the client during a recovery), retry once with the fresh client.
func (s *TunnelService) Disconnect() error {
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	err := s.callLong(ipc.MethodDisconnect, nil, nil)
	if err != nil && isClientClosed(err) {
		slog.Info("disconnect got client-closed, retrying with fresh client")
		err = s.callLong(ipc.MethodDisconnect, nil, nil)
	}
	return err
}

// DisconnectTunnel disconnects a specific tunnel by name. Mirrors
// Disconnect()'s "client closed" retry: a helper recovery during a
// per-tunnel disconnect (e.g. user clicks the tray's per-tunnel
// item right when the health monitor swaps clients) should be
// transparent, not surfaced as a confusing error.
func (s *TunnelService) DisconnectTunnel(name string) error {
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	err := s.callLong(ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: name}, nil)
	if err != nil && isClientClosed(err) {
		slog.Info("disconnect-tunnel got client-closed, retrying with fresh client",
			"tunnel", name)
		err = s.callLong(ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: name}, nil)
	}
	return err
}

// isClientClosed returns true for errors caused by the IPC client being closed
// mid-call (e.g., health monitor swapped clients during recovery).
func isClientClosed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "client closed")
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

// isActiveTunnel returns true if `name` is currently up. Uses the
// multi-tunnel ActiveTunnels list, NOT ActiveName, because the
// latter only returns the lexicographically-first connected tunnel
// — which made delete/rename/update incorrectly succeed against a
// non-primary connected tunnel and orphan the live interface.
func (s *TunnelService) isActiveTunnel(name string) (bool, error) {
	var resp ipc.ActiveTunnelsResponse
	if err := s.call(ipc.MethodActiveTunnels, nil, &resp); err != nil {
		return false, err
	}
	for _, n := range resp.Names {
		if n == name {
			return true, nil
		}
	}
	return false, nil
}

// DeleteTunnel removes a tunnel from local storage. Rejects deletion of the
// currently connected tunnel (would orphan the interface).
func (s *TunnelService) DeleteTunnel(name string) error {
	active, err := s.isActiveTunnel(name)
	if err != nil {
		return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", err)
	}
	if active {
		return fmt.Errorf("cannot delete connected tunnel %q — disconnect first", name)
	}
	return s.tunnelStore.Delete(name)
}

// RenameTunnel changes a tunnel's name. Rejects rename of the connected
// tunnel since the interface name is derived from it.
//
// Routes through the helper's Tunnel.Rename so the active-tunnel check and
// the file rename both happen under the helper's connectMu — closing the
// race where a Connect arriving between the GUI's check and the rename
// could leave the new name in activeCfgs while the file path moved.
//
// Falls back to a direct local rename if the helper rejects the method
// (older helper that hasn't been upgraded yet).
func (s *TunnelService) RenameTunnel(oldName, newName string) error {
	if err := storage.ValidateTunnelName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	err := s.call(ipc.MethodRename, ipc.RenameRequest{OldName: oldName, NewName: newName}, nil)
	if err == nil {
		return nil
	}
	if isMethodNotFound(err) {
		active, activeErr := s.isActiveTunnel(oldName)
		if activeErr != nil {
			return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", activeErr)
		}
		if active {
			return fmt.Errorf("cannot rename connected tunnel %q — disconnect first", oldName)
		}
		return s.tunnelStore.Rename(oldName, newName)
	}
	return err
}

// isMethodNotFound classifies an IPC error as "old helper doesn't know
// this method" so callers can fall back to a local-only path.
func isMethodNotFound(err error) bool {
	if err == nil {
		return false
	}
	var coded *ipc.Error
	if errors.As(err, &coded) {
		return coded.Code == ipc.ErrCodeMethodNotFound
	}
	return false
}

// TunnelExists reports whether a tunnel with the given name is stored.
func (s *TunnelService) TunnelExists(name string) bool {
	return s.tunnelStore.Exists(name)
}
