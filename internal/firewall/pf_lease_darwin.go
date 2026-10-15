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
	OwnerPID   int    `json:"owner_pid,omitempty"`
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
		live, err := pfReferenceHeld(pfLease.state)
		if err != nil {
			return fmt.Errorf("verify PF reference: %w", err)
		}
		if live {
			return nil
		}
		slog.Warn("PF reference was invalidated; taking a new one", "token", pfLease.state.Token)
		pfLease.state.Token, pfLease.state.Boot = "", ""
		pfLease.state.OwnerPID = 0
		if err := writePfLease(pfLease.state); err != nil {
			slog.Warn("failed to drop stale PF token from journal", "error", err)
		}
	}
	out, ownerPID, err := acquirePfReference()
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
	pfLease.state.OwnerPID = ownerPID
	if err := writePfLease(pfLease.state); err != nil {
		releaseErr := releasePfReference(pfLease.state)
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
		if err := releasePfReference(state); err != nil {
			return err
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
	if strings.Contains(string(out), "Status: Enabled") {
		return true, nil
	}
	if strings.Contains(string(out), "Status: Disabled") {
		return false, nil
	}
	return false, fmt.Errorf("unrecognized PF status")
}

// A running PF may belong only to another tool after an external stop/start.
// Check our exact token, rather than confusing that tool's lease with ours.
func livePfLease() (bool, error) {
	pfLease.Lock()
	defer pfLease.Unlock()
	if pfLease.state.Token == "" {
		return false, nil
	}
	boot, err := pfBootID()
	if err != nil || pfLease.state.Boot != boot {
		return false, err
	}
	return pfReferenceHeld(pfLease.state)
}

// xnu hashes the allocated reference object's address to generate its token.
// After -d frees it, another -E can immediately receive the same number.
// Match the issuing pfctl PID as well, including before crash cleanup's -X.
func pfReferenceHeld(state pfLeaseState) (bool, error) {
	if state.OwnerPID <= 0 {
		// A legacy journal cannot distinguish our token from a reused one.
		// Do not adopt or release an ownership claim it cannot establish.
		return false, nil
	}
	out, err := runPfctl("-s", "References")
	if err != nil {
		return false, fmt.Errorf("pfctl -s References: %w", err)
	}
	return parsePfReferences(string(out), state.Token, state.OwnerPID)
}

func releasePfReference(state pfLeaseState) error {
	held, err := pfReferenceHeld(state)
	if err != nil || !held {
		return err
	}
	if out, err := runPfctl("-X", state.Token); err != nil && !pfTokenGone(out) {
		return fmt.Errorf("pfctl -X: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func parsePfReferences(out, token string, ownerPID int) (bool, error) {
	if strings.Contains(out, "No pf starter references held") {
		return false, nil
	}
	// pfctl prints PID, process name, TOKEN, and "N days HH:MM:SS".
	// Process names may contain whitespace; take the token from the end.
	header, found, rows := false, false, 0
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "PID" && strings.Contains(line, "TOKEN") && strings.Contains(line, "TIMESTAMP") {
			header = true
			continue
		}
		if !header {
			continue
		}
		if len(fields) < 6 || fields[len(fields)-2] != "days" {
			return false, fmt.Errorf("unrecognized PF reference row")
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 {
			return false, fmt.Errorf("invalid PF reference PID: %q", fields[0])
		}
		rowToken := fields[len(fields)-4]
		if _, err := strconv.ParseUint(rowToken, 10, 64); err != nil {
			return false, fmt.Errorf("invalid PF reference token: %w", err)
		}
		rows++
		found = found || (rowToken == token && pid == ownerPID)
	}
	if !header || rows == 0 {
		return false, fmt.Errorf("unrecognized PF reference listing")
	}
	return found, nil
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
