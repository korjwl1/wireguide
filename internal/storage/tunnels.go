package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/config"
)

// TunnelStore manages .conf files on disk.
type TunnelStore struct {
	mu       sync.RWMutex
	dir      string
	root     *os.Root // borrowed only while the local lock is held
	ownerUID *int
	ownerSID string
}

// NewTunnelStore creates a TunnelStore for the given directory.
func NewTunnelStore(tunnelsDir string) *TunnelStore {
	return &TunnelStore{dir: tunnelsDir}
}

// Save writes a tunnel config to disk with 0600 permissions.
func (s *TunnelStore) Save(cfg *config.WireGuardConfig) error {
	if err := ValidateTunnelName(cfg.Name); err != nil {
		return err
	}

	unlock, err := s.lockWrite()
	if err != nil {
		return err
	}
	defer unlock()
	return s.saveLocked(cfg)
}

// saveLocked publishes a config with a validated name. Caller holds s.mu for writing.
func (s *TunnelStore) saveLocked(cfg *config.WireGuardConfig) error {
	// Refuse to overwrite a differently-cased existing tunnel: on a
	// case-insensitive filesystem that write would replace the other
	// tunnel's file (and its private key). An exact-case match is a
	// legitimate update and is allowed through.
	if variant, ok := s.caseVariantLocked(cfg.Name); ok {
		return fmt.Errorf("tunnel %q conflicts with existing %q on case-insensitive filesystems; choose a distinct name", cfg.Name, variant)
	}

	// A tunnel that doesn't exist yet is being created now — remember when,
	// so the date-added sort survives later edits (issue #17).
	isNew := !s.exists(cfg.Name)
	if isNew {
		if err := s.root.Remove(cfg.Name + ".meta.json"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	content := config.Serialize(cfg)
	if err := atomicfile.WriteInRoot(s.root, cfg.Name+".conf", []byte(content), 0600); err != nil {
		return err
	}

	// Stamp the creation time for a brand-new tunnel (best-effort — the
	// .conf is already durably written; a meta hiccup must not fail the
	// save). Only when new, so edits preserve the original date-added.
	if isNew {
		_ = s.saveMetaLocked(cfg.Name, &TunnelMeta{CreatedUnix: time.Now().Unix()})
	}
	return nil
}

// Load reads a tunnel config from disk by name.
func (s *TunnelStore) Load(name string) (*config.WireGuardConfig, error) {
	if err := ValidateTunnelName(name); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.loadConfigLocked(name)
}

// loadConfigLocked bounds config reads before parsing. Caller holds s.mu.
func (s *TunnelStore) loadConfigLocked(name string) (*config.WireGuardConfig, error) {
	root, release, err := s.borrowRoot()
	if err != nil {
		return nil, err
	}
	defer release()
	f, err := s.openProfileFile(root, name+".conf")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := config.ParseReader(f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", name, err)
	}
	cfg.Name = name
	return cfg, nil
}

// Delete removes a tunnel config from disk.
//
// The config and metadata are removed under the store write lock. Metadata
// cleanup remains best effort; callers receive the config removal error.
func (s *TunnelStore) Delete(name string) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}

	unlock, err := s.lockWrite()
	if err != nil {
		return err
	}
	defer unlock()

	err = s.root.Remove(name + ".conf")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = s.root.Remove(name + ".meta.json")
	return err
}

// Rename moves a config and its metadata from oldName to newName. The old
// path must stay inside the tunnel directory; legacy names containing dots
// may be renamed even though new names must pass ValidateTunnelName.
// The two files are moved separately, with best-effort rollback on failure.
func (s *TunnelStore) Rename(oldName, newName string) error {
	if err := ValidateTunnelName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}

	unlock, err := s.lockWrite()
	if err != nil {
		return err
	}
	defer unlock()

	if filepath.Base(oldName) != oldName || oldName == "." || oldName == ".." {
		return fmt.Errorf("invalid old tunnel name %q", oldName)
	}
	if !s.exists(oldName) {
		return fmt.Errorf("tunnel %q does not exist", oldName)
	}
	// A pure case change (Work → work) is allowed: on a case-insensitive
	// filesystem s.exists(newName) is true only because it resolves to
	// oldName's own file, so skip the collision check for that case.
	pureCaseChange := strings.EqualFold(oldName, newName)
	if !pureCaseChange {
		if s.exists(newName) {
			return fmt.Errorf("tunnel %q already exists", newName)
		}
		if variant, ok := s.caseVariantLocked(newName); ok {
			return fmt.Errorf("tunnel %q conflicts with existing %q on case-insensitive filesystems; choose a distinct name", newName, variant)
		}
	}
	oldPath, newPath := oldName+".conf", newName+".conf"
	oldMeta, newMeta := oldName+".meta.json", newName+".meta.json"
	_, err = s.root.Stat(oldMeta)
	hasMeta := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// An orphan belongs to an earlier profile, never to the renamed one.
	if !pureCaseChange {
		if err := s.root.Remove(newMeta); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := s.root.Rename(oldPath, newPath); err != nil {
		return err
	}
	if hasMeta {
		if err := s.root.Rename(oldMeta, newMeta); err != nil {
			if rollbackErr := s.root.Rename(newPath, oldPath); rollbackErr != nil {
				return fmt.Errorf("rename metadata: %w; config rollback: %v", err, rollbackErr)
			}
			return fmt.Errorf("rename metadata: %w (config rolled back)", err)
		}
	}
	return nil
}

// List returns all tunnel names (without .conf extension).
func (s *TunnelStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	root, release, err := s.borrowRoot()
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer release()
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".conf") {
			names = append(names, strings.TrimSuffix(name, ".conf"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// Exists checks if a tunnel with the given name exists.
func (s *TunnelStore) Exists(name string) bool {
	if err := ValidateTunnelName(name); err != nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.exists(name)
}

// exists is the internal lock-free version for use within already-locked methods.
func (s *TunnelStore) exists(name string) bool {
	root, release, err := s.borrowRoot()
	if err != nil {
		return false
	}
	defer release()
	_, err = root.Stat(name + ".conf")
	return err == nil
}

// ModTimeUnix returns the .conf file's modification time as a Unix
// timestamp. Only a FALLBACK for the date-added sort, for tunnels created
// before TunnelMeta.CreatedUnix stamping existed (issue #17) — an edit
// rewrites the .conf and moves this, so it must not be the primary
// source. Returns 0 when the file can't be stat'd.
func (s *TunnelStore) ModTimeUnix(name string) int64 {
	if err := ValidateTunnelName(name); err != nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	root, release, err := s.borrowRoot()
	if err != nil {
		return 0
	}
	defer release()
	fi, err := root.Stat(name + ".conf")
	if err != nil {
		return 0
	}
	return fi.ModTime().Unix()
}

// caseVariantLocked returns the stored tunnel name that differs from `name`
// only by case, if one exists on disk. Caller MUST hold s.mu.
//
// On case-insensitive filesystems (APFS on macOS — the primary target —
// and NTFS on Windows) "Work.conf" and "work.conf" are the same file, so
// saving "work" over an existing "Work" would silently destroy the first
// tunnel's private key. Detecting the variant lets callers refuse instead.
func (s *TunnelStore) caseVariantLocked(name string) (string, bool) {
	root, release, err := s.borrowRoot()
	if err != nil {
		return "", false
	}
	defer release()
	dir, err := root.Open(".")
	if err != nil {
		return "", false
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fn := e.Name()
		if !strings.HasSuffix(fn, ".conf") {
			continue
		}
		stored := strings.TrimSuffix(fn, ".conf")
		if stored != name && strings.EqualFold(stored, name) {
			return stored, true
		}
	}
	return "", false
}

// ImportFromContent creates a new config. Concurrent GUI/CLI imports serialize
// their existence check and publication; importing cannot replace existing keys.
func (s *TunnelStore) ImportFromContent(name, content string) (*config.WireGuardConfig, error) {
	if err := ValidateTunnelName(name); err != nil {
		return nil, err
	}
	cfg, err := config.Parse(content)
	if err != nil {
		return nil, err
	}
	cfg.Name = name

	result := config.Validate(cfg)
	if !result.IsValid() {
		return nil, fmt.Errorf("validation failed: %s", strings.Join(result.ErrorMessages(), "; "))
	}

	unlock, err := s.lockWrite()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if s.exists(name) {
		return nil, fmt.Errorf("tunnel %q already exists", name)
	}
	if err := s.saveLocked(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (s *TunnelStore) path(name string) string {
	return filepath.Join(s.dir, name+".conf")
}
