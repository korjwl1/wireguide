package app

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// ZipImportResult holds the outcome of importing one .conf entry from a zip.
type ZipImportResult struct {
	Name  string `json:"name"`
	Error string `json:"error,omitempty"`
}

// zipUniqueName returns a tunnel name that doesn't conflict with existing ones.
func (s *TunnelService) zipUniqueName(base string) string {
	if !s.tunnelStore.Exists(base) {
		return base
	}
	for i := 1; i < 1000; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !s.tunnelStore.Exists(candidate) {
			return candidate
		}
	}
	return fmt.Sprintf("%s-%d", base, time.Now().UnixMilli())
}

// ImportZip extracts all .conf files from a zip archive and imports each one.
// Returns per-file results; an error is only returned for zip-level failures.
func (s *TunnelService) ImportZip(path string) ([]ZipImportResult, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()
	return s.importZipReader(r.Reader)
}

// ImportZipData imports a zip supplied as raw bytes (used by the file picker,
// which provides a File object rather than a filesystem path).
func (s *TunnelService) ImportZipData(data []byte) ([]ZipImportResult, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("reading zip: %w", err)
	}
	return s.importZipReader(*r)
}

// importZipReader is the shared implementation for ImportZip and ImportZipData.
func (s *TunnelService) importZipReader(r zip.Reader) ([]ZipImportResult, error) {
	var results []ZipImportResult
	for _, f := range r.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".conf") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		baseName := strings.TrimSuffix(filepath.Base(f.Name), ".conf")
		name := s.zipUniqueName(baseName)
		if _, err := s.ImportConfig(name, string(data)); err != nil {
			results = append(results, ZipImportResult{Name: baseName, Error: err.Error()})
		} else {
			results = append(results, ZipImportResult{Name: name})
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no .conf files found in zip")
	}
	return results, nil
}

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

// maxReadFileSize is the largest file ReadFile will accept (10 MB).
// WireGuard configs are typically a few KB; anything larger is almost
// certainly not a valid .conf file.
const maxReadFileSize = 10 << 20

// ReadFile reads a file from disk (used by native file drop). Returns the
// content as a string so the frontend can handle name conflicts before import.
func (s *TunnelService) ReadFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	if info.Size() > maxReadFileSize {
		return "", fmt.Errorf("file %s is too large (%d bytes, max %d)", path, info.Size(), maxReadFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return string(data), nil
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
	var active ipc.StringResponse
	if err := s.call(ipc.MethodActiveName, nil, &active); err != nil {
		return fmt.Errorf("cannot verify tunnel state: %w", err)
	}
	if active.Value == name {
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
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", err
	}
	return path, nil
}
