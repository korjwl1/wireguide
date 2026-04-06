// Package helper — script allowlist for privilege escalation prevention.
//
// The helper process runs as root and executes Pre/PostUp/Down shell scripts
// from WireGuard configs. Without verification, any process running as the
// same user as the GUI can connect to the IPC socket and send arbitrary
// commands to be executed as root.
//
// This module maintains a persistent allowlist of SHA-256 hashes of approved
// script sets. When a ConnectRequest arrives with scripts AND ScriptsAllowed=true,
// the helper computes a fingerprint of all scripts and checks the allowlist.
// If the scripts are not approved, the connect request is rejected with a
// specific error that tells the GUI to prompt the user and send an
// ApproveScripts RPC.
//
// The allowlist file is stored in DataDir (root-owned), so only the helper
// can modify it — the GUI user cannot tamper with it.
package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/korjwl1/wireguide/internal/domain"
)

const allowlistFile = "script_allowlist.json"

// ScriptAllowlist manages the persistent set of approved script fingerprints.
// Thread-safe: all methods acquire the mutex.
type ScriptAllowlist struct {
	mu       sync.Mutex
	path     string            // full path to the JSON file
	approved map[string]string // fingerprint → human-readable description
}

// NewScriptAllowlist creates or loads an allowlist from the given data directory.
func NewScriptAllowlist(dataDir string) *ScriptAllowlist {
	al := &ScriptAllowlist{
		path:     filepath.Join(dataDir, allowlistFile),
		approved: make(map[string]string),
	}
	al.load()
	return al
}

// ScriptFingerprint computes a deterministic SHA-256 fingerprint of all scripts
// in a WireGuard config. The fingerprint covers the tunnel name and every
// script hook+command pair, sorted for stability.
//
// The tunnel name is included so that approving scripts for tunnel "work" does
// NOT auto-approve the same script text embedded in a tunnel named "evil".
// This prevents an attacker from copying approved scripts into a different
// config context.
func ScriptFingerprint(cfg *domain.WireGuardConfig) string {
	scripts := cfg.Scripts()
	if len(scripts) == 0 {
		return ""
	}

	h := sha256.New()
	// Include the tunnel name as a binding context.
	h.Write([]byte("tunnel:" + cfg.Name + "\n"))

	// Sort scripts by hook name for deterministic ordering.
	sort.Slice(scripts, func(i, j int) bool {
		return scripts[i].Hook < scripts[j].Hook
	})
	for _, s := range scripts {
		h.Write([]byte(s.Hook + ":" + s.Command + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// IsApproved checks whether the scripts in cfg have been previously approved.
// Returns true if the config has no scripts (nothing to approve).
func (al *ScriptAllowlist) IsApproved(cfg *domain.WireGuardConfig) bool {
	fp := ScriptFingerprint(cfg)
	if fp == "" {
		return true // no scripts — nothing to approve
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	_, ok := al.approved[fp]
	return ok
}

// Approve adds the scripts from cfg to the allowlist and persists to disk.
func (al *ScriptAllowlist) Approve(cfg *domain.WireGuardConfig) error {
	fp := ScriptFingerprint(cfg)
	if fp == "" {
		return nil
	}

	desc := fmt.Sprintf("tunnel %q", cfg.Name)
	scripts := cfg.Scripts()
	for _, s := range scripts {
		desc += fmt.Sprintf(", %s=%q", s.Hook, truncate(s.Command, 60))
	}

	al.mu.Lock()
	al.approved[fp] = desc
	al.mu.Unlock()

	return al.save()
}

// Revoke removes the scripts from cfg from the allowlist.
func (al *ScriptAllowlist) Revoke(cfg *domain.WireGuardConfig) error {
	fp := ScriptFingerprint(cfg)
	if fp == "" {
		return nil
	}
	al.mu.Lock()
	delete(al.approved, fp)
	al.mu.Unlock()
	return al.save()
}

// load reads the allowlist from disk. Non-fatal: missing or corrupt file
// starts with an empty allowlist.
func (al *ScriptAllowlist) load() {
	data, err := os.ReadFile(al.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("failed to read script allowlist", "path", al.path, "error", err)
		}
		return
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	if err := json.Unmarshal(data, &al.approved); err != nil {
		slog.Warn("corrupt script allowlist, starting fresh", "path", al.path, "error", err)
		al.approved = make(map[string]string)
	}
}

// save writes the allowlist atomically (write-to-temp + rename).
func (al *ScriptAllowlist) save() error {
	al.mu.Lock()
	data, err := json.MarshalIndent(al.approved, "", "  ")
	al.mu.Unlock()
	if err != nil {
		return err
	}

	tmp := al.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, al.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
