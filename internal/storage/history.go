package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	path    string
	maxSize int
}

// NewHistoryStore creates a history store.
func NewHistoryStore(configDir string, maxRecords int) *HistoryStore {
	return &HistoryStore{
		path:    filepath.Join(configDir, "history.json"),
		maxSize: maxRecords,
	}
}

// Add appends a session record.
func (h *HistoryStore) Add(record SessionRecord) error {
	records, _ := h.Load()
	records = append(records, record)
	if len(records) > h.maxSize {
		records = records[len(records)-h.maxSize:]
	}
	return h.save(records)
}

// Load reads all session records.
func (h *HistoryStore) Load() ([]SessionRecord, error) {
	data, err := os.ReadFile(h.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []SessionRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

// Clear removes all history.
func (h *HistoryStore) Clear() error {
	return os.Remove(h.path)
}

func (h *HistoryStore) save(records []SessionRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(h.path, data, 0644)
}
