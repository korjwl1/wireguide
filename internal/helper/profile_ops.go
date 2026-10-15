package helper

import (
	"encoding/json"
	"fmt"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func (h *Helper) handleRename(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	h.registerPendingRestore()

	var req ipc.RenameRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.OldName == "" || req.NewName == "" {
		return nil, fmt.Errorf("rename: old and new names are required")
	}
	if req.OldName == req.NewName {
		return ipc.Empty{}, nil
	}

	// Reject if the tunnel is currently active. h.connectMu is held so
	// no Connect/Disconnect can race past this check.
	for _, name := range h.manager.ActiveTunnels() {
		if name == req.OldName {
			return nil, fmt.Errorf("cannot rename connected tunnel %q — disconnect first", req.OldName)
		}
	}

	if h.userTunnelStore == nil {
		return nil, fmt.Errorf("rename: helper has no user tunnel store (running as root without --uid?)")
	}
	if err := h.userTunnelStore.Rename(req.OldName, req.NewName); err != nil {
		return nil, err
	}

	// Sync activeCfgs under h.mu.
	h.mu.Lock()
	if cfg, ok := h.activeCfgs[req.OldName]; ok {
		delete(h.activeCfgs, req.OldName)
		if cfg != nil {
			cfg.Name = req.NewName
		}
		h.activeCfgs[req.NewName] = cfg
	}
	if _, ok := h.pendingDesired[req.OldName]; ok {
		delete(h.pendingDesired, req.OldName)
		h.pendingDesired[req.NewName] = struct{}{}
	}
	if _, ok := h.watchdogBlocked[req.OldName]; ok {
		delete(h.watchdogBlocked, req.OldName)
		h.watchdogBlocked[req.NewName] = struct{}{}
	}
	h.mu.Unlock()

	// Sync autoConnectedBy under h.wifiMu, released before the next lock
	// (connectMu is held throughout; the order everywhere is connectMu →
	// wifiMu).
	h.wifiMu.Lock()
	if owner, ok := h.autoConnectedBy[req.OldName]; ok {
		delete(h.autoConnectedBy, req.OldName)
		h.autoConnectedBy[req.NewName] = owner
	}
	if latch, ok := h.manualOverride[req.OldName]; ok {
		delete(h.manualOverride, req.OldName)
		h.manualOverride[req.NewName] = latch
	}
	h.wifiMu.Unlock()

	// Move the cached latency under the new key so the old name doesn't
	// linger as an orphaned map entry (the sibling maps above are already
	// re-keyed; this one was missed).
	h.latencyMu.Lock()
	if lat, ok := h.latencyByTunnel[req.OldName]; ok {
		delete(h.latencyByTunnel, req.OldName)
		h.latencyByTunnel[req.NewName] = lat
	}
	h.latencyMu.Unlock()

	// Keep the desired-state key in sync (issue #44). Active tunnels can't
	// be renamed, but a pending (restore-failed) one can.
	h.persistDesiredState()
	return ipc.Empty{}, nil
}

// handleDelete keeps the live-state check, desired-state withdrawal and file
// removal in one transition. A GUI-side check cannot exclude an automation
// connect that starts immediately before the subsequent local delete.
func (h *Helper) handleDelete(params json.RawMessage) (interface{}, error) {
	var req ipc.DeleteRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if err := storage.ValidateTunnelName(req.TunnelName); err != nil {
		return nil, err
	}
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	if h.userTunnelStore == nil {
		return nil, fmt.Errorf("delete: helper has no user tunnel store")
	}
	h.registerPendingRestore()
	active := false
	for _, name := range h.manager.ActiveTunnels() {
		if name == req.TunnelName {
			active = true
			break
		}
	}
	if active && !req.Disconnect {
		return nil, fmt.Errorf("cannot delete connected tunnel %q — disconnect first", req.TunnelName)
	}
	h.mu.Lock()
	_, cached := h.activeCfgs[req.TunnelName]
	_, pending := h.pendingDesired[req.TunnelName]
	h.mu.Unlock()
	if active || cached || pending {
		if _, err := h.disconnectHeld(req.TunnelName); err != nil {
			return nil, err
		}
	}
	if err := h.userTunnelStore.Delete(req.TunnelName); err != nil {
		return nil, err
	}
	// Prevent the still-loaded automation rules from racing the caller's
	// settings cleanup. An absent config also makes later rule loads fail.
	h.recordManualOverride(req.TunnelName, true)
	h.mu.Lock()
	delete(h.watchdogBlocked, req.TunnelName)
	h.mu.Unlock()
	h.persistDesiredState()
	h.latencyMu.Lock()
	delete(h.latencyByTunnel, req.TunnelName)
	h.latencyMu.Unlock()
	return ipc.Empty{}, nil
}
