package guiinstance

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func macInstanceDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "wg-instance-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func noLegacyApplication() (bool, error) { return false, nil }

func TestMacOSReservationActivatesAndRestarts(t *testing.T) {
	dir := macInstanceDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := acquireDarwinAt(ctx, dir, noLegacyApplication)
	if err != nil || first == nil {
		t.Fatalf("primary: %v", err)
	}
	defer first.Close()
	second, err := acquireDarwinAt(ctx, dir, noLegacyApplication)
	if err != nil || second != nil {
		t.Fatalf("duplicate GUI: %v", err)
	}
	select {
	case <-first.Requests():
	case <-ctx.Done():
		t.Fatal("activation not delivered")
	}
	first.Close()
	next, err := acquireDarwinAt(ctx, dir, noLegacyApplication)
	if err != nil || next == nil {
		t.Fatalf("restart after Close: %v", err)
	}
	next.Close()
}

func TestMacOSConcurrentLaunchesReserveOneGUI(t *testing.T) {
	dir := macInstanceDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	primaries := make(chan *Instance, 8)
	errors := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i, err := acquireDarwinAt(ctx, dir, noLegacyApplication)
			if err != nil {
				errors <- err
			} else if i != nil {
				primaries <- i
			}
		}()
	}
	wg.Wait()
	close(primaries)
	close(errors)
	count := 0
	for primary := range primaries {
		count++
		primary.Close()
	}
	for err := range errors {
		t.Error(err)
	}
	if count != 1 {
		t.Fatalf("got %d GUI reservations, want 1", count)
	}
}

func TestMacOSKilledProcessReleasesLockAndStaleSocket(t *testing.T) {
	dir := macInstanceDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMacOSInstanceChild$")
	cmd.Env = append(os.Environ(), "WIREGUIDE_INSTANCE_TEST_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	scanner := bufio.NewScanner(out)
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "ready" {
			ready = true
			break
		}
	}
	if !ready {
		cmd.Wait()
		t.Fatal("child did not acquire the reservation")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child did not die from SIGKILL")
	}
	if _, err := os.Lstat(filepath.Join(dir, "gui.sock")); err != nil {
		t.Fatal("fixture did not leave a stale socket")
	}
	next, err := acquireDarwinAt(ctx, dir, noLegacyApplication)
	if err != nil || next == nil {
		t.Fatalf("stale reservation prevented restart: %v", err)
	}
	next.Close()
}

func TestMacOSInstanceChild(t *testing.T) {
	dir := os.Getenv("WIREGUIDE_INSTANCE_TEST_DIR")
	if !strings.HasPrefix(dir, "/private/tmp/wg-instance-") {
		t.Skip("subprocess fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	i, err := acquireDarwinAt(ctx, dir, noLegacyApplication)
	if err != nil || i == nil {
		t.Fatalf("child primary: %v", err)
	}
	os.Stdout.WriteString("ready\n")
	select {}
}

func TestMacOSLegacyActivationReleasesReservation(t *testing.T) {
	dir := macInstanceDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	i, err := acquireDarwinAt(ctx, dir, func() (bool, error) { return true, nil })
	if err != nil || i != nil {
		t.Fatalf("legacy activation created a GUI: %v", err)
	}
	i, err = acquireDarwinAt(ctx, dir, noLegacyApplication)
	if err != nil || i == nil {
		t.Fatalf("legacy activation left its lock behind: %v", err)
	}
	i.Close()
}

func TestMacOSLockDoesNotFollowSymlinks(t *testing.T) {
	dir := macInstanceDir(t)
	target := filepath.Join(dir, "unrelated")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "gui.lock")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if i, err := acquireDarwinAt(ctx, dir, noLegacyApplication); err == nil || i != nil {
		t.Fatal("followed a symlink for the reservation lock")
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "unchanged" {
		t.Fatal("modified an unrelated file")
	}
}

func TestMacOSMigrationActivatesOldReservation(t *testing.T) {
	dir := macInstanceDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	old, err := acquireDarwinAt(ctx, dir, noLegacyApplication)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	active, err := activateOldReservation(ctx, dir)
	if err != nil || !active {
		t.Fatalf("migration skipped running old binary: active=%v err=%v", active, err)
	}
	select {
	case <-old.Requests():
	case <-ctx.Done():
		t.Fatal("old GUI was not activated")
	}
	old.Close()
	active, err = activateOldReservation(ctx, dir)
	if err != nil || active {
		t.Fatalf("stale old lock prevented new primary: %v %v", active, err)
	}
}
