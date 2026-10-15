//go:build darwin

package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"golang.org/x/sys/unix"
)

type pfLeaseState struct {
	Token      string `json:"token,omitempty"`
	Boot       string `json:"boot,omitempty"`
	WasEnabled bool   `json:"was_enabled"`
}

var pfLease = struct {
	sync.Mutex
	state pfLeaseState
}{}
var pfBootID = func() (string, error) { return unix.Sysctl("kern.bootsessionuuid") }
var pfTokenPattern = regexp.MustCompile(`(?m)Token\s*:\s*([0-9]+)`)

// pfctl -E/-X reference counting lets other VPN/firewall owners keep PF
// enabled. A prior enabled/disabled snapshot cannot establish ownership.
func enablePf() error {
	pfLease.Lock()
	defer pfLease.Unlock()
	boot, err := pfBootID()
	if err != nil {
		return err
	}
	if pfLease.state.Token != "" && pfLease.state.Boot == boot {
		// `pfctl -d` (another VPN, the user) stops PF and invalidates every
		// reference, ours included (xnu DIOCSTOP: invalidate_all_tokens).
		// A cached token therefore proves nothing about enforcement.
		running, err := pfRunning()
		if err != nil {
			return fmt.Errorf("verify PF is running: %w", err)
		}
		if running {
			return nil
		}
		slog.Warn("PF is stopped although a reference is held; taking a new one", "token", pfLease.state.Token)
		pfLease.state.Token, pfLease.state.Boot = "", ""
		if err := writePfLease(pfLease.state); err != nil {
			slog.Warn("failed to drop stale PF token from journal", "error", err)
		}
	}
	out, err := runPfctl("-E")
	if err != nil {
		return fmt.Errorf("pfctl -E: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	match := pfTokenPattern.FindSubmatch(out)
	if len(match) != 2 {
		return fmt.Errorf("pfctl -E did not return a reference token")
	}
	if _, err := strconv.ParseUint(string(match[1]), 10, 64); err != nil {
		return fmt.Errorf("invalid PF token: %w", err)
	}
	pfLease.state.Token = string(match[1])
	pfLease.state.Boot = boot
	if err := writePfLease(pfLease.state); err != nil {
		_, releaseErr := runPfctl("-X", pfLease.state.Token)
		if releaseErr == nil {
			pfLease.state.Token = ""
		}
		return errors.Join(err, releaseErr)
	}
	return nil
}

func disablePf() error {
	pfLease.Lock()
	defer pfLease.Unlock()
	state := pfLease.state
	if state.Token == "" {
		data, err := os.ReadFile(savedPfStateFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		// Old releases persisted just 0/1. They supplied no ownership
		// token, so never globally disable PF based on that snapshot.
		if text := strings.TrimSpace(string(data)); text == "0" || text == "1" {
			return nil
		}
		if err := json.Unmarshal(data, &state); err != nil {
			return err
		}
	}
	if state.Token == "" {
		return nil
	}
	pfLease.state = state // a failed release remains recoverable in memory too
	boot, err := pfBootID()
	if err != nil {
		return err
	}
	if state.Boot == boot {
		if out, err := runPfctl("-X", state.Token); err != nil {
			if !pfTokenGone(out) {
				return fmt.Errorf("pfctl -X: %w (%s)", err, strings.TrimSpace(string(out)))
			}
			// Nothing left to release: PF was stopped (all references
			// invalidated) or the kernel no longer knows this token.
			slog.Warn("PF reference already invalid; dropping it", "token", state.Token,
				"error", err, "output", strings.TrimSpace(string(out)))
		}
	}
	pfLease.state = pfLeaseState{}
	return nil
}

// pfRunning reports whether PF is enabled. A failed query is an error, not
// "stopped": callers must not discard a live reference on a pfctl hiccup.
func pfRunning() (bool, error) {
	out, err := runPfctl("-si")
	if err != nil {
		return false, fmt.Errorf("pfctl -si: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return strings.Contains(string(out), "Status: Enabled"), nil
}

// pfTokenGone reports whether a failed `pfctl -X` means the token can no
// longer be live. xnu DIOCSTOPREF fails with ENOENT when PF is not running
// and EINVAL for an unknown token; pfctl reports these as "pf not enabled"
// and "pf: token invalid". The text is matched as a hint only, and PF being
// verifiably stopped is independent proof. Any other failure (timeout,
// unreadable status) keeps the token for a later retry.
func pfTokenGone(out []byte) bool {
	text := string(out)
	if strings.Contains(text, "pf not enabled") || strings.Contains(text, "token invalid") {
		return true
	}
	running, err := pfRunning()
	return err == nil && !running
}

func writePfLease(state pfLeaseState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(savedPfStateFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return atomicfile.WriteFile(savedPfStateFile, data, 0600)
}
