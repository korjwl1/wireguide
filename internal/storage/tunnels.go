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
	if cfg.Name == "" {
		return fmt.Errorf("tunnel name is empty")
	}
	// Validate name to prevent path traversal
	for _, r := range cfg.Name {
		valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if !valid {
			return fmt.Errorf("invalid character in tunnel name: %q", cfg.Name)
		}
	}
	if cfg.Name == "." || cfg.Name == ".." {
		return fmt.Errorf("invalid tunnel name: %q", cfg.Name)
	}

	content := config.Serialize(cfg)
	path := s.path(cfg.Name)

	// Atomic write: temp file + rename (prevents partial writes on crash)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
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
func (s *TunnelStore) Rename(oldName, newName string) error {
	if oldName == newName {
		return nil
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
