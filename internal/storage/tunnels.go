package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/korjwl1/wireguide/internal/config"
)

// TunnelStore manages .conf files on disk.
type TunnelStore struct {
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

	content := config.Serialize(cfg)
	path := s.path(cfg.Name)

	// Atomic write: temp file + rename (prevents partial writes on crash).
	// On rename failure, clean up the orphan tmpfile.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// Load reads a tunnel config from disk by name.
func (s *TunnelStore) Load(name string) (*config.WireGuardConfig, error) {
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
// Note: there is an intentional TOCTOU between Exists() and Rename() — this
// is a single-user desktop app and the window is microseconds. If this ever
// becomes a multi-user service, switch to os.Link + os.Remove.
func (s *TunnelStore) Rename(oldName, newName string) error {
	if err := ValidateTunnelName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	if !s.Exists(oldName) {
		return fmt.Errorf("tunnel %q does not exist", oldName)
	}
	if s.Exists(newName) {
		return fmt.Errorf("tunnel %q already exists", newName)
	}
	return os.Rename(s.path(oldName), s.path(newName))
}

// List returns all tunnel names (without .conf extension).
func (s *TunnelStore) List() ([]string, error) {
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
