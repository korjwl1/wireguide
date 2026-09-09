//go:build darwin

package gui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/elevate"
)

func TestDisabledPromptSettingsDoesNotAuthorizeOrConsumeRetry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("PROMPT_TEST_DIR", dir)
	// Stub only the UI executables: no native windows or Settings changes.
	script := `#!/bin/sh
printf '%s\n' "$2" >> "$PROMPT_TEST_DIR/prompts"
if [ ! -f "$PROMPT_TEST_DIR/opened" ]; then
 printf 'Open Settings\n'
else
 printf 'Retry\n'
fi
`
	openScript := `#!/bin/sh
printf '%s\n' "$1" > "$PROMPT_TEST_DIR/opened"
`
	for name, body := range map[string]string{"osascript": script, "open": openScript} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if !askHelperRetry(fmt.Errorf("setup failed: %w", elevate.ErrBackgroundDisabled)) {
		t.Fatal("explicit Retry was lost after Open Settings")
	}
	prompts, err := os.ReadFile(filepath.Join(dir, "prompts"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(prompts), `buttons {"Quit", "Open Settings", "Retry"}`) != 2 {
		t.Fatalf("unexpected dialogs: %s", prompts)
	}
	if strings.Contains(string(prompts), "administrator privileges") {
		t.Fatal("disabled-service dialog requested authorization")
	}
	opened, err := os.ReadFile(filepath.Join(dir, "opened"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(opened)) != "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" {
		t.Fatalf("wrong settings destination: %s", opened)
	}
}
