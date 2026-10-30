package app

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/config"
)

// ImportConfig parses, validates, and saves a tunnel config under the given
// name. Returns a TunnelInfo for optimistic UI display.
func (s *TunnelService) ImportConfig(name, content string) (*TunnelInfo, error) {
	cfg, err := s.tunnelStore.ImportFromContent(name, content)
	if err != nil {
		return nil, err
	}
	endpoint := ""
	if len(cfg.Peers) > 0 {
		endpoint = cfg.Peers[0].Endpoint
	}
	return &TunnelInfo{
		Name:     cfg.Name,
		Endpoint: endpoint,
	}, nil
}

// BaseName extracts the filename without extension from a path.
func (s *TunnelService) BaseName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

// ValidateConfig parses and validates a raw config string. Returns a list of
// human-readable error messages, or nil if the config is valid.
func (s *TunnelService) ValidateConfig(content string) ([]string, error) {
	cfg, err := config.Parse(content)
	if err != nil {
		return []string{err.Error()}, nil
	}
	result := config.Validate(cfg)
	if result.IsValid() {
		return nil, nil
	}
	return result.ErrorMessages(), nil
}

// LintConfigFor returns advisory (non-blocking) editor diagnostics for a raw
// config string: DNS errors mirroring ValidateConfig, plus warnings and hints.
// editing is the saved tunnel name being edited ("" for a new tunnel); it is
// reserved for cross-tunnel checks. It never affects whether a config is
// valid. Content that does not parse yields no diagnostics (ValidateConfig
// reports the parse error).
func (s *TunnelService) LintConfigFor(editing, content string) ([]config.Diagnostic, error) {
	_ = editing
	cfg, err := config.Parse(content)
	if err != nil {
		return []config.Diagnostic{}, nil
	}
	ds := safeLint(cfg, nil)
	if ds == nil {
		ds = []config.Diagnostic{}
	}
	return ds, nil
}

// lintConfig is the linter safeLint guards; a variable so tests can make it panic.
var lintConfig = config.Lint

// safeLint runs config.Lint but never lets a panic escape: linting is advisory
// and must not be able to kill the GUI.
func safeLint(cfg *config.WireGuardConfig, others map[string]*config.WireGuardConfig) (ds []config.Diagnostic) {
	defer func() {
		if r := recover(); r != nil {
			ds = nil
		}
	}()
	return lintConfig(cfg, others)
}

// GetConfigText returns the serialized form of a stored tunnel's config.
func (s *TunnelService) GetConfigText(name string) (string, error) {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return "", err
	}
	return config.Serialize(cfg), nil
}

// UpdateConfig parses, validates, and overwrites an existing tunnel's config.
// Rejects edits of the connected tunnel.
func (s *TunnelService) UpdateConfig(name, content string) error {
	// Pending reconnects count as active intent too; editing their config
	// would leave the helper's cached version out of sync with disk.
	active, err := s.isActiveTunnel(name)
	if err != nil {
		return fmt.Errorf("cannot verify tunnel state: %w", err)
	}
	if active {
		return fmt.Errorf("cannot edit connected tunnel %q — disconnect first", name)
	}
	cfg, err := config.Parse(content)
	if err != nil {
		return err
	}
	result := config.Validate(cfg)
	if !result.IsValid() {
		return fmt.Errorf("validation failed: %s", strings.Join(result.ErrorMessages(), "; "))
	}
	cfg.Name = name
	return s.tunnelStore.Save(cfg)
}

// ExportConfig returns the serialized text for display in the export dialog.
func (s *TunnelService) ExportConfig(name string) (string, error) {
	return s.GetConfigText(name)
}

// ExportTunnel shows a native save dialog and writes the .conf file.
// Returns the saved path, or empty string if the user cancelled.
func (s *TunnelService) ExportTunnel(name string) (string, error) {
	content, err := s.GetConfigText(name)
	if err != nil {
		return "", err
	}
	if s.app == nil {
		return "", fmt.Errorf("app not initialized")
	}

	path, err := s.app.Dialog.SaveFile().
		SetFilename(name+".conf").
		AddFilter("WireGuard Config", "*.conf").
		PromptForSingleSelection()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // user cancelled
	}

	// Exported files contain private keys — write with 0600.
	if err := atomicfile.WriteFile(path, []byte(content), 0600); err != nil {
		return "", err
	}
	return path, nil
}
