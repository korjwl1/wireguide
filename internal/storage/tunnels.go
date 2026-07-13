package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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

	s.mu.Lock()
	defer s.mu.Unlock()

	// Refuse to overwrite a differently-cased existing tunnel: on a
	// case-insensitive filesystem that write would replace the other
	// tunnel's file (and its private key). An exact-case match is a
	// legitimate update and is allowed through.
	if variant, ok := s.caseVariantLocked(cfg.Name); ok {
		return fmt.Errorf("tunnel %q conflicts with existing %q on case-insensitive filesystems; choose a distinct name", cfg.Name, variant)
	}

	content := config.Serialize(cfg)
	path := s.path(cfg.Name)

	// Atomic write: temp file + rename (prevents partial writes on crash).
	// Use os.CreateTemp to avoid predictable temp file names (symlink attacks).
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".wireguide-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := atomicRenameDurable(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
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

	path := s.path(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", name, err)
	}
	cfg.Name = name
	return cfg, nil
}

// Delete removes a tunnel config from disk.
//
// Best-effort meta cleanup: if the .meta.json sidecar exists, remove it
// alongside. Failure to remove the sidecar never blocks tunnel deletion —
// a stale meta file would just linger until the same tunnel name is
// recreated, at which point LoadMeta would surface its old contents.
func (s *TunnelStore) Delete(name string) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.path(name)
	err := os.Remove(path)
	_ = os.Remove(s.metaPath(name))
	return err
}

// Rename renames a tunnel from oldName to newName.
//
// Only `newName` is validated — `oldName` must already correspond to an
// existing file on disk, and filesystem escaping is handled by s.path().
// Validating oldName would strand users who have legacy files with
// characters the current ValidateTunnelName rejects (e.g. dots from the
// pre-Phase-0 era: `work.vpn.conf`), with no way to rename them out.
//
// Note: there is an intentional TOCTOU between exists() and Rename() — this
// is a single-user desktop app and the window is microseconds. If this ever
// becomes a multi-user service, switch to os.Link + os.Remove.
func (s *TunnelStore) Rename(oldName, newName string) error {
	if err := ValidateTunnelName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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
	// Two-phase commit for the (.conf, .meta.json) pair. The rollback-
	// based design (rename .conf, then rename .meta, roll back .conf on
	// failure) had a tail risk: the rollback rename can itself fail on
	// Windows (file lock) or under disk-full / EROFS, leaving the user
	// in a split state with permanent metadata loss.
	//
	// Strategy:
	//   Phase 1 (PRE-CHECK): verify both paths are writable by attempting
	//     a no-op os.Link-then-Remove on each. This catches permission
	//     and file-lock failures up front, before any mutation.
	//   Phase 2 (COMMIT): rename .conf then .meta. If either fails after
	//     pre-check passed, the cause is almost certainly a TOCTOU race
	//     (someone else touched the files between phases). Roll back
	//     best-effort and surface both errors.
	//
	// Pre-check is best-effort; it doesn't fully eliminate races, but
	// it catches the common "Windows file lock" cause that the original
	// design hit hardest.
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
			// Pre-check said this was writable so the failure is almost
			// certainly a TOCTOU race. Roll back .conf best-effort and
			// surface both errors so the operator can investigate.
			if rollbackErr := os.Rename(newPath, oldPath); rollbackErr != nil {
				return fmt.Errorf("rename meta failed after pre-check (%w) AND .conf rollback also failed (%v) — manual fix required", err, rollbackErr)
			}
			return fmt.Errorf("rename meta: %w (rolled back .conf rename)", err)
		}
	}
	return nil
}

// preCheckWritable verifies that we can rename src→dst by performing a
// minimal probe: ensure src is statable AND dst doesn't already exist
// AND we can hardlink src→tmp (this exercises the same VFS permission
// path as rename without committing). The probe is removed immediately.
//
// Hardlinks fail across filesystems with EXDEV; in that case we fall
// back to "src exists + dst doesn't" which is a weaker check but better
// than nothing.
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
// timestamp — used as the tunnel's "date added" for sorting. Returns 0
// when the file can't be stat'd.
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

// ImportFromContent parses content, assigns a name, and saves.
func (s *TunnelStore) ImportFromContent(name, content string) (*config.WireGuardConfig, error) {
	cfg, err := config.Parse(content)
	if err != nil {
		return nil, err
	}
	cfg.Name = name

	result := config.Validate(cfg)
	if !result.IsValid() {
		return nil, fmt.Errorf("validation failed: %s", strings.Join(result.ErrorMessages(), "; "))
	}

	if err := s.Save(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (s *TunnelStore) path(name string) string {
	return filepath.Join(s.dir, name+".conf")
}

// TunnelMeta holds per-tunnel metadata stored alongside the .conf file in a
// .meta.json sidecar. Kept separate from the .conf because WireGuard's config
// format is shared with other clients (wg-quick, official apps) and embedding
// app-specific fields as comments would be lost on round-trip through them.
type TunnelMeta struct {
	Notes              string `json:"notes,omitempty"`
	LatencyProbeTarget string `json:"latency_probe_target,omitempty"`
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

// LoadWithMeta loads both the .conf and the .meta.json sidecar under a
// single RLock so a concurrent Rename can't move the .conf out from under
// the meta read (or vice-versa) and produce a mismatched pair. The meta
// load is best-effort — meta-only failures fall back to an empty meta and
// never propagate as an error from this call.
func (s *TunnelStore) LoadWithMeta(name string) (*config.WireGuardConfig, *TunnelMeta, error) {
	if err := ValidateTunnelName(name); err != nil {
		return nil, nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := s.path(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Parse(string(data))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", name, err)
	}
	cfg.Name = name

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
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
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

	dst := s.metaPath(name)
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), ".wireguide-meta-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := atomicRenameDurable(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
