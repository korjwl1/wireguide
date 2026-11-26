package app

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/config"
)

// ImportConfig parses, validates, and saves a tunnel config under the given
// name. Returns a TunnelInfo for optimistic UI display.
func (s *TunnelService) ImportConfig(name, content string) (*TunnelInfo, error) {
	return s.importConfig(name, content, nil)
}

// importConfig is ImportConfig with an optional snapshot of the saved tunnels
// for the duplicate-Address check. A non-nil saved is owned by the caller and
// is updated with the imported tunnel, so a batch import loads the store once
// and later entries are checked against earlier ones. A nil saved is loaded
// on demand.
func (s *TunnelService) importConfig(name, content string, saved map[string]*config.WireGuardConfig) (*TunnelInfo, error) {
	cfg, err := s.tunnelStore.ImportFromContent(name, content)
	if err != nil {
		return nil, err
	}
	endpoint := ""
	if len(cfg.Peers) > 0 {
		endpoint = cfg.Peers[0].Endpoint
	}
	info := &TunnelInfo{
		Name:     cfg.Name,
		Endpoint: endpoint,
	}
	// Non-blocking: surface a duplicate-Address warning against the other
	// saved tunnels. The import has already succeeded, so a failure here must
	// not fail it.
	others := saved
	if others == nil {
		others = s.otherTunnelConfigs(cfg.Name)
	}
	delete(others, cfg.Name) // an overwritten tunnel is not its own duplicate
	info.Warnings = safeDuplicateAddress(cfg, others)
	if saved != nil {
		saved[cfg.Name] = cfg
	}
	return info, nil
}

// safeDuplicateAddress runs config.DuplicateAddressDiagnostics but never lets a
// panic escape.
func safeDuplicateAddress(cfg *config.WireGuardConfig, others map[string]*config.WireGuardConfig) (ds []config.Diagnostic) {
	defer func() {
		if r := recover(); r != nil {
			ds = nil
		}
	}()
	return config.DuplicateAddressDiagnostics(cfg, others)
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

// LintConfig returns advisory (non-blocking) editor diagnostics for a raw
// config string: DNS errors mirroring ValidateConfig, plus warnings and hints.
// editing is the saved tunnel name being edited ("" for a new tunnel); it is
// excluded from the cross-tunnel duplicate-Address check so an edit never
// "conflicts" with its own saved copy. It never affects whether a config is
// valid. Content that does not parse yields no diagnostics (ValidateConfig
// reports the parse error).
func (s *TunnelService) LintConfig(editing, content string) ([]config.Diagnostic, error) {
	cfg, err := config.Parse(content)
	if err != nil {
		return []config.Diagnostic{}, nil
	}
	ds := safeLint(cfg, s.otherTunnelConfigs(editing))
	if ds == nil {
		ds = []config.Diagnostic{}
	}
	return ds, nil
}

// otherTunnelConfigs loads every saved tunnel except `exclude`. Unreadable
// tunnels are skipped.
func (s *TunnelService) otherTunnelConfigs(exclude string) map[string]*config.WireGuardConfig {
	if s.tunnelStore == nil {
		return nil
	}
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil
	}
	others := make(map[string]*config.WireGuardConfig, len(names))
	for _, n := range names {
		if n == exclude {
			continue
		}
		if c, err := s.tunnelStore.Load(n); err == nil {
			others[n] = c
		}
	}
	return others
}

// lintConfig is the linter safeLint guards; a variable so tests can make it panic.
var lintConfig = config.Lint

// safeLint runs config.Lint but never lets a panic escape: linting is advisory
// and must not be able to kill the GUI or fail an already-saved import.
func safeLint(cfg *config.WireGuardConfig, others map[string]*config.WireGuardConfig) (ds []config.Diagnostic) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("configuration lint failed")
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
