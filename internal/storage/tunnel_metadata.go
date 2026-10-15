package storage

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/healthcheck"
)

// TunnelMeta holds per-tunnel metadata stored alongside the .conf file in a
// .meta.json sidecar. Kept separate from the .conf because WireGuard's config
// format is shared with other clients (wg-quick, official apps) and embedding
// app-specific fields as comments would be lost on round-trip through them.
type TunnelMeta struct {
	PingHealth         *healthcheck.Config `json:"ping_health,omitempty"`
	Notes              string              `json:"notes,omitempty"`
	LatencyProbeTarget string              `json:"latency_probe_target,omitempty"`
	// CreatedUnix is when the tunnel was first added, stamped once on
	// creation and preserved across edits/rename. The .conf mtime is NOT a
	// reliable "date added": editing a tunnel rewrites the file and would
	// make it look freshly added, corrupting the list's date-added sort
	// (issue #17). 0 means "unknown" (tunnel predates this field) — callers
	// fall back to the mtime.
	CreatedUnix int64 `json:"created_unix,omitempty"`
}

func (s *TunnelStore) metaPath(name string) string {
	return filepath.Join(s.dir, name+".meta.json")
}

// LoadMeta reads the .meta.json sidecar. A missing file or a parse error
// returns empty meta with nil error — the sidecar is purely additive and
// must never break tunnel listing. RLock matches Load() so a concurrent
// SaveMeta / Rename / Delete can't race against the read.
func (s *TunnelStore) LoadMeta(name string) (*TunnelMeta, error) {
	if err := ValidateTunnelName(name); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadMetaLocked(name)
}

// loadMetaLocked reads the .meta.json sidecar without acquiring the lock.
// Caller MUST hold s.mu (R or W).
func (s *TunnelStore) loadMetaLocked(name string) (*TunnelMeta, error) {
	data, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return &TunnelMeta{}, nil
		}
		return nil, err
	}
	var m TunnelMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return &TunnelMeta{}, nil
	}
	return &m, nil
}

// LoadWithMeta reads the config and metadata under the same cross-process
// lock as Rename, so it cannot observe half of a rename. The meta
// load is best-effort — meta-only failures fall back to an empty meta and
// never propagate as an error from this call.
func (s *TunnelStore) LoadWithMeta(name string) (*config.WireGuardConfig, *TunnelMeta, error) {
	if err := ValidateTunnelName(name); err != nil {
		return nil, nil, err
	}
	unlock, err := s.lockWrite()
	if err != nil {
		return nil, nil, err
	}
	defer unlock()

	cfg, err := s.loadConfigLocked(name)
	if err != nil {
		return nil, nil, err
	}

	meta, _ := s.loadMetaLocked(name)
	if meta == nil {
		meta = &TunnelMeta{}
	}
	return cfg, meta, nil
}

// SaveMeta writes the .meta.json sidecar atomically. Empty meta still writes
// the file (the caller may want to record an explicit "no notes" state).
func (s *TunnelStore) SaveMeta(name string, meta *TunnelMeta) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}
	unlock, err := s.lockWrite()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(s.path(name)); err != nil {
		return err
	}
	return s.saveMetaLocked(name, meta)
}

// UpdateMeta applies fn to the current meta and persists the result under a
// single write lock, so two concurrent single-field updates (e.g. notes and
// latency target flushed back-to-back by the frontend) can't interleave a
// load-then-save and silently drop each other's field.
func (s *TunnelStore) UpdateMeta(name string, fn func(*TunnelMeta)) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}
	unlock, err := s.lockWrite()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(s.path(name)); err != nil {
		return err
	}
	meta, err := s.loadMetaLocked(name)
	if err != nil {
		return err
	}
	fn(meta)
	return s.saveMetaLocked(name, meta)
}

// saveMetaLocked writes the .meta.json sidecar atomically. Caller MUST hold
// s.mu (write).
func (s *TunnelStore) saveMetaLocked(name string, meta *TunnelMeta) error {
	if meta == nil {
		meta = &TunnelMeta{}
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	return atomicfile.WriteFile(s.metaPath(name), data, 0600)
}
