//go:build darwin

package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

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
		return nil
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
			return fmt.Errorf("pfctl -X: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	pfLease.state = pfLeaseState{}
	return nil
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
	f, err := os.CreateTemp(dir, ".pf-lease-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), savedPfStateFile)
}
