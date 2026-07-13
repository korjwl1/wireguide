package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// HistoryMaxRecords caps the rolling session log. Hard-coded rather than
// configurable: the file lives in the user's config directory and the cap
// keeps it small enough that GetAll() can deserialise on every UI open
// without paginating.
const HistoryMaxRecords = 200

// Session is one VPN session record. EndTime is a pointer so a still-active
// session (no end yet) can be distinguished from a completed session that
// happens to have ended at time.Time{} — the previous flat-struct design
// couldn't tell those apart and showed phantom "0s" rows in the UI when the
// helper was killed mid-connect before the disconnect path could write
// final stats.
type Session struct {
	ID               string     `json:"id"`
	TunnelName       string     `json:"tunnel_name"`
	StartTime        time.Time  `json:"start_time"`
	EndTime          *time.Time `json:"end_time,omitempty"`
	DurationSec      int64      `json:"duration_sec"`
	RxBytes          int64      `json:"rx_bytes"`
	TxBytes          int64      `json:"tx_bytes"`
	DisconnectReason string     `json:"disconnect_reason,omitempty"`
}

// historyFlushDelay debounces disk writes when multiple RecordConnect /
// RecordDisconnect calls land in rapid succession (e.g. multi-tunnel
// connect, batch reconciliation). Worst-case data loss on crash is
// bounded by this window; in exchange we save N-1 disk write+marshal
// cycles per burst.
const historyFlushDelay = 100 * time.Millisecond

// HistoryStore persists Sessions to history.json with a rolling cap.
//
// Concurrency: a single mutex guards both the in-memory list and the file —
// Connect / Disconnect / Reconcile can race in multi-tunnel scenarios so
// every public method takes the lock. All disk writes go through atomicRename
// so a crash during save can never leave a half-written file.
//
// Disk-write coalescing: every public mutator marks the in-memory cache dirty
// and schedules a deferred flush. Reads always go through loadLocked which
// prefers the in-memory cache when present, so the dirty window is never
// observable to callers.
type HistoryStore struct {
	mu         sync.Mutex
	path       string
	cache      []Session // nil until first load
	cacheValid bool
	dirty      bool
	flushTimer *time.Timer
}

// NewHistoryStore creates a store backed by configDir/history.json.
func NewHistoryStore(configDir string) *HistoryStore {
	return &HistoryStore{path: filepath.Join(configDir, "history.json")}
}

// scheduleFlushLocked arms a debounced flush. Caller MUST hold h.mu.
//
// Concurrency: every body run is serialised through h.mu. A scheduleFlushLocked
// arriving while a previous body is mid-save blocks on the lock; once it
// gets in it Resets the timer for another tick. Worst case: a high-write
// burst produces N+1 disk writes instead of N — still bounded, and each
// write is atomic (saveLocked uses tmp + rename), so the file never sees
// a partially-written snapshot.
func (h *HistoryStore) scheduleFlushLocked() {
	h.dirty = true
	if h.flushTimer != nil {
		// Reset on an AfterFunc timer is safe regardless of fired state
		// (per time.AfterFunc docs): if it has already fired, Reset
		// schedules another run; if not, it shifts the deadline forward.
		h.flushTimer.Reset(historyFlushDelay)
		return
	}
	h.flushTimer = time.AfterFunc(historyFlushDelay, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if !h.dirty || !h.cacheValid {
			return
		}
		if err := h.saveLocked(h.cache); err != nil {
			slog.Warn("history: deferred flush failed", "error", err)
			return
		}
		h.dirty = false
	})
}

// Flush forces a synchronous write of pending changes. Call from shutdown
// paths so the deferred-flush window doesn't lose recent records.
func (h *HistoryStore) Flush() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty || !h.cacheValid {
		return
	}
	if h.flushTimer != nil {
		h.flushTimer.Stop()
	}
	if err := h.saveLocked(h.cache); err != nil {
		slog.Warn("history: explicit Flush failed", "error", err)
		return
	}
	h.dirty = false
}

// RecordConnect opens a new session for tunnelName, appends it, and returns
// the generated ID. Disk failures are logged at warn — recording is
// best-effort and never blocks connect.
func (h *HistoryStore) RecordConnect(tunnelName string) string {
	id := newSessionID()
	now := time.Now()
	session := Session{
		ID:         id,
		TunnelName: tunnelName,
		StartTime:  now,
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	sessions := h.loadLocked()
	sessions = append(sessions, session)
	sessions = trimSessions(sessions)
	h.commitLocked(sessions)
	return id
}

// RecordDisconnect closes an open session by ID. If the ID is unknown
// (history file was cleared, session not found, etc.) the call is a no-op.
//
// Phantom drop: a 0-duration / 0-byte completion is removed entirely rather
// than recorded. Those come from interrupted bootstraps and helper restarts
// — keeping them just clutters the timeline with empty rows.
func (h *HistoryStore) RecordDisconnect(id string, rx, tx int64, reason string) {
	if id == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	sessions := h.loadLocked()
	now := time.Now()
	changed := false
	for i := range sessions {
		if sessions[i].ID != id || sessions[i].EndTime != nil {
			continue
		}
		dur := int64(now.Sub(sessions[i].StartTime).Seconds())
		if dur < 0 {
			dur = 0
		}
		if dur == 0 && rx == 0 && tx == 0 {
			sessions = append(sessions[:i], sessions[i+1:]...)
			changed = true
			break
		}
		end := now
		sessions[i].EndTime = &end
		sessions[i].DurationSec = dur
		sessions[i].RxBytes = rx
		sessions[i].TxBytes = tx
		sessions[i].DisconnectReason = reason
		changed = true
		break
	}
	if !changed {
		return
	}
	h.commitLocked(sessions)
}

// CloseOpenSessions closes every session that still has nil EndTime — used
// at app start (to clean up sessions left open by a previous crash) and at
// shutdown. 0-duration open sessions are dropped rather than recorded.
func (h *HistoryStore) CloseOpenSessions(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	sessions := h.loadLocked()
	now := time.Now()
	changed := false
	kept := sessions[:0]
	for i := range sessions {
		if sessions[i].EndTime == nil {
			dur := int64(now.Sub(sessions[i].StartTime).Seconds())
			if dur < 0 {
				dur = 0
			}
			if dur == 0 {
				changed = true
				continue
			}
			end := now
			sessions[i].EndTime = &end
			sessions[i].DurationSec = dur
			sessions[i].DisconnectReason = reason
			changed = true
		}
		kept = append(kept, sessions[i])
	}
	sessions = kept
	if !changed {
		return
	}
	h.commitLocked(sessions)
}

// GetAll returns sessions newest-first. Stale 0-duration / 0-byte completed
// rows from older crashes are filtered out so the user never sees a phantom.
func (h *HistoryStore) GetAll() []Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	sessions := h.loadLocked()
	out := make([]Session, 0, len(sessions))
	for i := len(sessions) - 1; i >= 0; i-- {
		s := sessions[i]
		if s.EndTime != nil && s.DurationSec == 0 && s.RxBytes == 0 && s.TxBytes == 0 {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Clear removes the history file entirely. Returns nil if it doesn't exist.
func (h *HistoryStore) Clear() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Drop deferred flush so it can't recreate the file after we delete it.
	if h.flushTimer != nil {
		h.flushTimer.Stop()
	}
	h.cache = nil
	h.cacheValid = true
	h.dirty = false

	err := os.Remove(h.path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// loadLocked returns the current session list. Prefers the in-memory cache;
// reads from disk on the first call. Missing file → empty slice. Parse error
// → rename to <path>.corrupt and start fresh, mirroring settings.go's
// hardening so a corrupt history is preserved for debugging instead of
// silently truncated by the next Add.
func (h *HistoryStore) loadLocked() []Session {
	if h.cacheValid {
		// Return a copy so mutating callers can't tear the cache.
		out := make([]Session, len(h.cache))
		copy(out, h.cache)
		return out
	}
	data, err := os.ReadFile(h.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("history: read failed", "error", err)
		}
		h.cache = nil
		h.cacheValid = true
		return nil
	}
	var sessions []Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		corruptPath := h.path + ".corrupt"
		if renameErr := os.Rename(h.path, corruptPath); renameErr != nil {
			slog.Warn("history: corrupt file; could not back up",
				"path", h.path, "error", err, "rename_error", renameErr)
		} else {
			slog.Warn("history: corrupt file; backed up before resetting",
				"path", h.path, "backup", corruptPath, "error", err)
		}
		h.cache = nil
		h.cacheValid = true
		return nil
	}
	h.cache = sessions
	h.cacheValid = true
	// Return a copy so the mutating callers can't tear the cache.
	out := make([]Session, len(sessions))
	copy(out, sessions)
	return out
}

// commitLocked stores the new session list in cache and schedules a flush.
// Caller MUST hold h.mu.
func (h *HistoryStore) commitLocked(sessions []Session) {
	h.cache = sessions
	h.cacheValid = true
	h.scheduleFlushLocked()
}

// saveLocked atomically writes sessions with 0600 perms.
func (h *HistoryStore) saveLocked(sessions []Session) error {
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(h.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, ".wireguide-history-*.tmp")
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
	if err := atomicRenameDurable(tmpPath, h.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// trimSessions keeps only the last HistoryMaxRecords entries (oldest-first
// → drop from the front).
func trimSessions(sessions []Session) []Session {
	if len(sessions) <= HistoryMaxRecords {
		return sessions
	}
	return sessions[len(sessions)-HistoryMaxRecords:]
}

// newSessionID returns a 16-hex-char random ID. crypto/rand failure falls
// back to a timestamp so the ID is never empty (an empty ID disables the
// disconnect-side lookup).
func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
