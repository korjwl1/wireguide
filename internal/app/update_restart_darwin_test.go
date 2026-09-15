package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestUpdateRestartWaitsForOldProcessAndPreservesPath(t *testing.T) {
	dir := t.TempDir()
	// A path that would execute a command if interpolated into shell source.
	marker := filepath.Join(dir, "updated app $(touch injected)")
	old := exec.Command("/bin/sleep", "30")
	if err := old.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = old.Process.Kill(); _ = old.Wait() })
	launcher := exec.Command("/bin/sh", "-c", updateRestartScript, "wireguide-restart",
		strconv.Itoa(old.Process.Pid), marker, "/usr/bin/touch")
	launcher.Dir = dir
	if err := launcher.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launcher.Process.Kill() })
	time.Sleep(250 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("launched before old process exited: %v", err)
	}
	_ = old.Process.Kill()
	_ = old.Wait()
	done := make(chan error, 1)
	go func() { done <- launcher.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("launcher did not resume after old process exited")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
		t.Fatalf("path was interpreted as shell code: %v", err)
	}
}

func TestUpdateRestartWithoutApplication(t *testing.T) {
	if err := (&TunnelService{}).restartAfterUpdate(); err == nil {
		t.Fatal("missing application must not report successful restart")
	}
}
