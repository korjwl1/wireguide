package update

import (
	"encoding/json"
	"fmt"
	"github.com/korjwl1/wireguide/internal/atomicfile"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the persisted update-checker state.
//
// Lives alongside config.json in ConfigDir so it survives app restarts
// without leaking into the system-wide DataDir owned by the root helper.
// Only the GUI process reads/writes this file; the helper never touches
// updates (update notifications are pure UI concerns — keep the root
// process's network/HTTP surface minimal).
type State struct {
	// LastCheckUnix is the wall-clock time of the last *successful* check.
	// Failed checks leave this field alone so the scheduler can tell
	// "checked recently and got an answer" from "tried recently but the
	// network was down".
	LastCheckUnix int64 `json:"last_check_unix"`

	// LastSeenVersion is the version string returned by the most recent
	// successful check, with or without an update available. Used by the
	// scheduler to skip re-emitting the same "update found" event on every
	// subsequent check (the wireguard-windows `didNotify` pattern).
	LastSeenVersion string `json:"last_seen_version"`

	// ETag is the value of the response ETag header from the last
	// successful check. Sent as If-None-Match on the next request to let
	// GitHub answer 304 Not Modified — avoids burning the 60-req/hour/IP
	// anonymous rate limit on offices behind shared NAT.
	ETag string `json:"etag,omitempty"`

	// LastModified mirrors ETag for servers that prefer Last-Modified
	// semantics. GitHub sends both; we cache both and send both back.
	LastModified string `json:"last_modified,omitempty"`

	// DismissedVersions records versions the user explicitly dismissed in
	// the in-app banner. The scheduler still records them in LastSeenVersion,
	// but the UI suppresses the banner if a dismissal matches.
	//
	// Implemented as a slice (not a set) so the on-disk representation is
	// stable JSON; the dismissed-set check is linear, fine for typical
	// dismissed counts (≤ tens).
	DismissedVersions []string `json:"dismissed_versions,omitempty"`

	// LastErrorUnix is the wall-clock time of the most recent failed
	// check. Used to drive the wireguard-windows-style backoff: first
	// failure → 5 min retry, sustained failure → 25-30 min. Reset to 0
	// on success.
	LastErrorUnix int64 `json:"last_error_unix,omitempty"`

	// ConsecutiveErrors counts checks that failed in a row since the
	// last success. Capped at a small number — we only use it to decide
	// between the short and long backoff windows.
	ConsecutiveErrors int `json:"consecutive_errors,omitempty"`
}

// StateStore is a goroutine-safe wrapper around the on-disk update.json
// file. The scheduler holds one of these; the IPC layer reads from it to
// answer "when did you last check?" queries from the UI.
type StateStore struct {
	path string

	mu    sync.Mutex
	state State
}

// NewStateStore opens (or initialises) the store under dir/update.json.
// A read error returns a zero-valued state and logs at debug — first-run
// installs have no file yet, which is not an error condition.
func NewStateStore(dir string) (*StateStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("update state: empty dir")
	}
	s := &StateStore{path: filepath.Join(dir, "update.json")}
	if err := s.load(); err != nil {
		slog.Debug("update state: starting fresh", "path", s.path, "reason", err)
	}
	return s, nil
}

// Get returns a snapshot copy of the current state. Mutating the returned
// value does not affect the store; use Update for that.
func (s *StateStore) Get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy the slice so the caller cannot mutate our internal one.
	out := s.state
	if len(s.state.DismissedVersions) > 0 {
		out.DismissedVersions = append([]string(nil), s.state.DismissedVersions...)
	}
	return out
}

// Update applies the given function to the state under the lock and
// persists the result. The caller's function should mutate the pointed-to
// State; the store handles serialisation and disk I/O.
func (s *StateStore) Update(fn func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.state)
	return s.save()
}

// Dismiss appends version to the dismissed list (idempotent) and persists.
func (s *StateStore) Dismiss(version string) error {
	if version == "" {
		return nil
	}
	return s.Update(func(st *State) {
		for _, v := range st.DismissedVersions {
			if v == version {
				return
			}
		}
		st.DismissedVersions = append(st.DismissedVersions, version)
	})
}

// IsDismissed reports whether the user already dismissed this version.
func (s *StateStore) IsDismissed(version string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.state.DismissedVersions {
		if v == version {
			return true
		}
	}
	return false
}

func (s *StateStore) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		// Corrupt file: don't crash; just start over. A corrupted
		// update.json is harmless — we'll re-check on the next tick.
		return fmt.Errorf("parse update.json: %w", err)
	}
	s.state = st
	return nil
}

// save writes atomically via tmpfile+rename so a crashed write doesn't
// leave a truncated update.json on disk.
func (s *StateStore) save() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(s.path, raw, 0600)
}

// LastCheckTime returns the timestamp of the last successful check as a
// time.Time, or zero time if no check has ever succeeded.
func (s *StateStore) LastCheckTime() time.Time {
	st := s.Get()
	if st.LastCheckUnix == 0 {
		return time.Time{}
	}
	return time.Unix(st.LastCheckUnix, 0)
}
