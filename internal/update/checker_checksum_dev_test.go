//go:build !production

package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Checksum-only authentication belongs to development builds. Production
// coverage uses signed fixtures and separately rejects a missing signing key.
func TestDownloadUpdate_ChecksumMatch(t *testing.T) {
	// Build a fake asset body that is >= minAssetSize.
	bodySize := minAssetSize + 1024
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = byte(i % 256)
	}

	h := sha256.Sum256(body)
	expectedHash := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.Write(body)
	}))
	defer srv.Close()

	info := &UpdateInfo{
		DownloadURL:  srv.URL + "/asset.dmg",
		AssetName:    "asset.dmg",
		AssetSize:    int64(bodySize),
		ExpectedHash: expectedHash,
	}

	path, err := DownloadUpdate(info)
	if err != nil {
		t.Fatalf("DownloadUpdate failed: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}
	if !info.HashVerified {
		t.Error("expected HashVerified to be true")
	}

	// Clean up the temp file.
	if err := removeIfExists(path); err != nil {
		t.Logf("cleanup warning: %v", err)
	}
}

func TestDownloadUpdate_ChecksumMismatch(t *testing.T) {
	bodySize := minAssetSize + 1024
	body := make([]byte, bodySize)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.Write(body)
	}))
	defer srv.Close()

	info := &UpdateInfo{
		DownloadURL:  srv.URL + "/asset.dmg",
		AssetName:    "asset.dmg",
		AssetSize:    int64(bodySize),
		ExpectedHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	_, err := DownloadUpdate(info)
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected 'checksum mismatch' in error, got: %v", err)
	}
}

func TestDownloadUpdate_NoChecksum(t *testing.T) {
	bodySize := minAssetSize + 1024
	body := make([]byte, bodySize)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.Write(body)
	}))
	defer srv.Close()

	info := &UpdateInfo{
		DownloadURL:  srv.URL + "/asset.dmg",
		AssetName:    "asset.dmg",
		AssetSize:    int64(bodySize),
		ExpectedHash: "", // no checksum available
	}

	_, err := DownloadUpdate(info)
	if err == nil {
		t.Fatal("expected error when no checksum is available")
	}
	if !strings.Contains(err.Error(), "no checksum available") {
		t.Errorf("expected 'no checksum available' in error, got: %v", err)
	}
}
