package elevate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func ValidateHelperSource(ctx context.Context) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}
	source, err := daemonSource(exe)
	if err != nil {
		return err
	}
	return validateDaemonSource(ctx, source)
}

func daemonSource(exe string) (string, error) {
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("locate helper source: %w", err)
	}
	macOS := filepath.Dir(resolved)
	contents := filepath.Dir(macOS)
	if filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.EqualFold(filepath.Ext(filepath.Dir(contents)), ".app") {
		return resolved, nil
	}
	helper := filepath.Join(contents, "Library", "LaunchServices", daemonLabel)
	st, err := os.Lstat(helper)
	if err != nil {
		return "", fmt.Errorf("app bundle has no standalone helper; reinstall WireGuide: %w", err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("bundled helper is not a regular executable: %s", helper)
	}
	return helper, nil
}

func validateDaemonSource(ctx context.Context, source string) error {
	bundle := daemonSourceBundle(source)
	if bundle == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", bundle).CombinedOutput(); err != nil {
		return fmt.Errorf("app bundle signature is invalid: %w (%s)", err, tailOf(out, 500))
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--all-architectures", source).CombinedOutput(); err != nil {
		return fmt.Errorf("standalone helper signature is invalid: %w (%s)", err, tailOf(out, 500))
	}
	return nil
}

func daemonSourceBundle(source string) string {
	launchServices := filepath.Dir(source)
	library := filepath.Dir(launchServices)
	contents := filepath.Dir(library)
	bundle := filepath.Dir(contents)
	if filepath.Base(source) == daemonLabel && filepath.Base(launchServices) == "LaunchServices" && filepath.Base(library) == "Library" && filepath.Base(contents) == "Contents" && strings.EqualFold(filepath.Ext(bundle), ".app") {
		return bundle
	}
	return ""
}
