package ipc

import "sync"

// ClientHolder wraps a *Client so that multiple goroutines can share a single
// IPC connection and swap it atomically after a helper restart. Both the
// Wails-bound service and the GUI event bridge read through a ClientHolder so
// that a single `Set(newClient)` call points everybody at the new connection.
//
// The old client is closed automatically on Set, after the new one is in
// place — any in-flight Call on the old client returns a "client closed"
// error and the frontend can retry or surface it.
type ClientHolder struct {
	mu     sync.RWMutex
	client *Client
}

// NewClientHolder wraps an initial client.
func NewClientHolder(c *Client) *ClientHolder {
	return &ClientHolder{client: c}
}

// Get returns the current client. Callers must not retain the pointer across
// operations that might involve a swap — always fetch fresh before each Call.
func (h *ClientHolder) Get() *Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.client
}

// Set installs a new client and closes the previous one (if any).
func (h *ClientHolder) Set(c *Client) {
	h.mu.Lock()
	prev := h.client
	h.client = c
	h.mu.Unlock()
	if prev != nil && prev != c {
		prev.Close()
	}
}

// Close closes the current client. Safe to call multiple times.
func (h *ClientHolder) Close() {
	h.mu.Lock()
	prev := h.client
	h.client = nil
	h.mu.Unlock()
	if prev != nil {
		prev.Close()
	}
}
