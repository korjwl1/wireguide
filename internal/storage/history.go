package storage

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SessionRecord stores a completed VPN session.
type SessionRecord struct {
	TunnelName string    `json:"tunnel_name"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	TotalRx    int64     `json:"total_rx"`
	TotalTx    int64     `json:"total_tx"`
}

// HistoryStore manages connection history.
type HistoryStore struct {
	mu      sync.Mutex
	path    string
	maxSize int
}

// NewHistoryStore creates a history store.
func NewHistoryStore(configDir string, maxRecords int) *HistoryStore {
	if maxRecords < 1 {
		maxRecords = 1
	}
	return &HistoryStore{
		path:    filepath.Join(configDir, "history.json"),
		maxSize: maxRecords,
	}
}

// Add appends a session record.
func (h *HistoryStore) Add(record SessionRecord) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	records, err := h.load()
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("history file permission denied: %w", err)
		}
		if !os.IsNotExist(err) {
			slog.Warn("history file corrupted, starting fresh", "error", err)
			records = nil
		}
	}
	records = append(records, record)
	if len(records) > h.maxSize {
		records = records[len(records)-h.maxSize:]
	}
	return h.save(records)
}

// Load reads all session records.
func (h *HistoryStore) Load() ([]SessionRecord, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.load()
}

// load is the internal unlocked version of Load.
func (h *HistoryStore) load() ([]SessionRecord, error) {
	data, err := os.ReadFile(h.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []SessionRecord
	if err := json.Unmarshal(data, &records); err != nil {
		// Mirror settings.go's hardening: rename the corrupt file
		// to <path>.corrupt before discarding so the user can
		// recover (or we can debug) the original. Without this,
		// the next Add call's append-then-write silently truncated
		// the corrupted history to a single new record.
		corruptPath := h.path + ".corrupt"
		if renameErr := os.Rename(h.path, corruptPath); renameErr != nil {
			slog.Warn("history file corrupt; could not back up",
				"path", h.path, "error", err, "rename_error", renameErr)
		} else {
			slog.Warn("history file corrupt; backed up before resetting",
				"path", h.path, "backup", corruptPath, "error", err)
		}
		return nil, err
	}
	return records, nil
}

// Clear removes all history. Returns nil if the file doesn't exist.
func (h *HistoryStore) Clear() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := os.Remove(h.path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

func (h *HistoryStore) save(records []SessionRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write + private permissions (history may include tunnel names
	// and timestamps that are user-sensitive on multi-user systems).
	// Use os.CreateTemp to avoid predictable temp file names.
	tmpFile, err := os.CreateTemp(filepath.Dir(h.path), ".wireguide-*.tmp")
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
	if err := atomicRename(tmpPath, h.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
