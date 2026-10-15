package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/wifi"
)

const automationBackupSuffix = ".automation-v2-backup"

type AutomationBackupStatus struct {
	Available      bool   `json:"available"`
	Different      bool   `json:"different"`
	RecoveryCopies int    `json:"recovery_copies"`
	Error          string `json:"error,omitempty"`
}

func extendedAutomation(a *wifi.Automation) bool {
	if a != nil {
		for _, rules := range a.PerTunnel {
			if wifi.HasNegated(rules) {
				return true
			}
		}
	}
	return false
}

func automationBytes(a *wifi.Automation) []byte {
	data, _ := json.MarshalIndent(a, "", "  ")
	return data
}

func readAutomationBackup(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const limit = 2 << 20
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && len(data) > limit {
		err = fmt.Errorf("automation backup exceeds 2 MiB")
	}
	return data, err
}

func (s *SettingsStore) currentAutomation() (*wifi.Automation, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var previous Settings
	if err := json.Unmarshal(data, &previous); err != nil {
		return nil, err
	}
	return previous.Automation, nil
}

// Unrelated settings writes never depend on backup writability. Changing
// extended rules does: first preserve an orphaned pre-downgrade snapshot,
// then publish the new backup before the active settings.
func (s *SettingsStore) prepareAutomationBackup(settings *Settings) (bool, error) {
	previous, previousErr := s.currentAutomation()
	if previousErr == nil && bytes.Equal(automationBytes(previous), automationBytes(settings.Automation)) {
		return false, nil
	}
	extended := extendedAutomation(settings.Automation)
	retire := !extended && extendedAutomation(previous)
	if !extended && !retire {
		return false, nil
	}
	path := s.path + automationBackupSuffix
	oldBackup, err := readAutomationBackup(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err == nil {
		var old wifi.Automation
		matchesPrevious := json.Unmarshal(oldBackup, &old) == nil && bytes.Equal(automationBytes(&old), automationBytes(previous))
		if !matchesPrevious {
			archive := fmt.Sprintf("%s.recovery-%x", path, sha256.Sum256(oldBackup))
			if err := atomicfile.WriteFile(archive, oldBackup, 0600); err != nil {
				return false, fmt.Errorf("preserve earlier automation backup: %w", err)
			}
		}
	}
	if extended {
		if err := writeAutomationBackup(path, automationBytes(settings.Automation)); err != nil {
			return false, err
		}
	}
	return retire, nil
}

func writeAutomationBackup(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data, 0600)
}

// AutomationBackupStatus exposes recovery copies without activating them.
// It is queried on demand, so rule polling does not emit repeated warnings.
func (s *SettingsStore) AutomationBackupStatus() AutomationBackupStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	var status AutomationBackupStatus
	archives, err := filepath.Glob(s.path + automationBackupSuffix + ".recovery-*")
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.RecoveryCopies = len(archives)
	previous, previousErr := s.currentAutomation()
	data, err := readAutomationBackup(s.path + automationBackupSuffix)
	if errors.Is(err, os.ErrNotExist) && !extendedAutomation(previous) {
		return status
	}
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Available = true
	var backup wifi.Automation
	if err := json.Unmarshal(data, &backup); err != nil {
		status.Error = err.Error()
		return status
	}
	status.Different = previousErr != nil || !bytes.Equal(automationBytes(&backup), automationBytes(previous))
	return status
}
