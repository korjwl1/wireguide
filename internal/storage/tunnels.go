package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/config"
)

// TunnelStore manages .conf files on disk.
type TunnelStore struct {
	mu  sync.RWMutex
	dir string
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

	content := config.Serialize(cfg)
	path := s.path(cfg.Name)

	if err := atomicfile.WriteFile(path, []byte(content), 0600); err != nil {
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
	f, err := os.Open(s.path(name))
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

	path := s.path(name)
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(s.metaPath(name))
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

	// Validate that oldName resolves to a path within the tunnels directory
	// to prevent path traversal (e.g., oldName = "../../etc/shadow").
	oldPath := s.path(oldName)
	absOld, err := filepath.Abs(oldPath)
	if err != nil {
		return fmt.Errorf("invalid old name: %w", err)
	}
	absDir, err := filepath.Abs(s.dir)
	if err != nil {
		return fmt.Errorf("invalid directory: %w", err)
	}
	// Resolve symlinks so that a symlinked tunnels directory (or symlinked
	// path components in oldName) cannot bypass the HasPrefix check.
	if resolved, err := filepath.EvalSymlinks(absDir); err == nil {
		absDir = resolved
	}
	if resolved, err := filepath.EvalSymlinks(absOld); err == nil {
		absOld = resolved
	}
	if !strings.HasPrefix(absOld, absDir+string(filepath.Separator)) {
		return fmt.Errorf("tunnel name %q escapes tunnels directory", oldName)
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
	// Check both destinations before moving the config and its metadata.
	// The advisory checks cannot guarantee a later rename (especially with
	// Windows sharing locks). If metadata rename fails, roll back the config
	// and report any rollback failure so the split state is visible.
	newPath := s.path(newName)
	oldMeta := s.metaPath(oldName)
	newMeta := s.metaPath(newName)
	hasMeta := false
	if _, err := os.Stat(oldMeta); err == nil {
		hasMeta = true
	}

	// Skip the writability pre-check for a pure case change: on a
	// case-insensitive filesystem the destination "already exists"
	// (it's the same file), which the probe would reject. os.Rename
	// handles the case-only rename directly and surfaces any real error.
	if !pureCaseChange {
		if err := preCheckWritable(oldPath, newPath); err != nil {
			return fmt.Errorf("rename pre-check failed for .conf: %w", err)
		}
		if hasMeta {
			if err := preCheckWritable(oldMeta, newMeta); err != nil {
				return fmt.Errorf("rename pre-check failed for .meta: %w", err)
			}
		}
	}

	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	if hasMeta {
		if err := os.Rename(oldMeta, newMeta); err != nil {
			// A pre-check cannot rule out sharing violations or later races.
			// Roll back .conf and surface both errors if that also fails.
			if rollbackErr := os.Rename(newPath, oldPath); rollbackErr != nil {
				return fmt.Errorf("rename meta failed after pre-check (%w) AND .conf rollback also failed (%v) — manual fix required", err, rollbackErr)
			}
			return fmt.Errorf("rename meta: %w (rolled back .conf rename)", err)
		}
	}
	return nil
}

// preCheckWritable checks source accessibility and destination absence. Its
// hard-link probe is advisory: it does not prove rename permission or Windows
// delete-sharing support. Actual rename failures still require rollback.
func preCheckWritable(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("source not accessible: %w", err)
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("destination already exists: %s", dst)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("destination check failed: %w", err)
	}
	// Hardlink probe — same directory so EXDEV is impossible (TunnelStore
	// keeps .conf and .meta in s.dir).
	probe := src + ".rename-probe"
	if err := os.Link(src, probe); err != nil {
		// Hardlink failed — either filesystem doesn't support it (FAT)
		// or permission. Fall through; the actual rename will surface
		// the real error if it can't proceed.
		return nil
	}
	os.Remove(probe)
	return nil
}

// List returns all tunnel names (without .conf extension).
func (s *TunnelStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
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
	_, err := os.Stat(s.path(name))
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
	fi, err := os.Stat(s.path(name))
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
	entries, err := os.ReadDir(s.dir)
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
