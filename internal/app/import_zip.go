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
		suffix := fmt.Sprintf("-%d", i)
		candidate := base[:min(len(base), 64-len(suffix))] + suffix
		if !s.tunnelStore.Exists(candidate) {
			return candidate
		}
	}
	suffix := fmt.Sprintf("-%d", time.Now().UnixMilli())
	return base[:min(len(base), 64-len(suffix))] + suffix
}

// ImportZip extracts all .conf files from a zip archive and imports each one.
// Returns per-file results; an error is only returned for zip-level failures.
func (s *TunnelService) ImportZip(path string) ([]ZipImportResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxZipDataSize {
		return nil, fmt.Errorf("zip must be a regular file of at most %d bytes", maxZipDataSize)
	}
	r, err := zip.NewReader(f, info.Size())
	if err != nil {
		return nil, fmt.Errorf("reading zip: %w", err)
	}
	return s.importZipReader(r)
}

// maxZipDataSize caps the in-memory zip payload accepted from the GUI
// file picker. WireGuard configs are tiny; a multi-MB zip dump is
// either a mistake or a memory-exhaustion attempt.
const maxZipDataSize = 32 << 20

// maxZipEntrySize bounds each decompressed entry (zip-bomb guard).
const maxZipEntrySize = 1 << 20

// Bound work and total expansion, not just the size of each entry. Check
// budgets before importing anything so an oversized archive has no side effects.
const maxZipEntries = 256
const maxZipExpandedSize = 32 << 20

// ImportZipData imports a zip supplied as raw bytes (used by the file picker,
// which provides a File object rather than a filesystem path).
func (s *TunnelService) ImportZipData(data []byte) ([]ZipImportResult, error) {
	if len(data) > maxZipDataSize {
		return nil, fmt.Errorf("zip too large: %d bytes (max %d)", len(data), maxZipDataSize)
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("reading zip: %w", err)
	}
	return s.importZipReader(r)
}

// importZipReader is the shared implementation for ImportZip and ImportZipData.
func (s *TunnelService) importZipReader(r *zip.Reader) ([]ZipImportResult, error) {
	if len(r.File) > maxZipEntries {
		return nil, fmt.Errorf("zip contains too many entries (max %d)", maxZipEntries)
	}
	var declared uint64
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".conf") {
			continue
		}
		if f.UncompressedSize64 > maxZipExpandedSize-declared {
			return nil, fmt.Errorf("zip total expanded config size exceeds %d bytes", maxZipExpandedSize)
		}
		declared += f.UncompressedSize64
	}
	var results []ZipImportResult
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".conf") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		// Per-entry size cap — zip bomb protection.
		data, err := io.ReadAll(io.LimitReader(rc, maxZipEntrySize+1))
		rc.Close()
		if err != nil {
			results = append(results, ZipImportResult{Name: filepath.Base(f.Name), Error: err.Error()})
			continue
		}
		if int64(len(data)) > maxZipEntrySize {
			results = append(results, ZipImportResult{
				Name:  filepath.Base(f.Name),
				Error: fmt.Sprintf("entry exceeds %d bytes", maxZipEntrySize),
			})
			continue
		}
		baseName := strings.TrimSuffix(filepath.Base(f.Name), filepath.Ext(f.Name))
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
