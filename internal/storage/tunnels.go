package storage

import (
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
	if err := atomicRename(tmpPath, path); err != nil {
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
func (s *TunnelStore) Delete(name string) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.path(name)
	return os.Remove(path)
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
	if s.exists(newName) {
		return fmt.Errorf("tunnel %q already exists", newName)
	}
	return os.Rename(oldPath, s.path(newName))
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
