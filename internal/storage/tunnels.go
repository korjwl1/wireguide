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
	content := config.Serialize(cfg)
	path := s.path(cfg.Name)
	return os.WriteFile(path, []byte(content), 0600)
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
