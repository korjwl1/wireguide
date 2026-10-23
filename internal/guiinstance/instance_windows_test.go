//go:build windows

package guiinstance

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func testIdentity(t *testing.T) (string, uint32, string) {
	t.Helper()
	sid, session, err := identity()
	if err != nil {
		t.Fatal(err)
	}
	return sid, session, fmt.Sprintf(`\\.\pipe\wireguide.gui.test.%d.%s`, os.Getpid(), t.Name())
}

func TestNativeExclusivePipeAndReactivation(t *testing.T) {
	sid, session, path := testIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	primary, err := acquireAt(ctx, path, sid, session)
	if err != nil || primary == nil {
		t.Fatalf("primary: %v", err)
	}
	defer primary.Close()
	second, err := acquireAt(ctx, path, sid, session)
	if err != nil || second != nil {
		if second != nil {
			second.Close()
		}
		t.Fatalf("secondary created GUI: %v", err)
	}
	select {
	case <-primary.Requests():
	case <-ctx.Done():
		t.Fatal("native activation not delivered")
	}
	primary.Close()
	next, err := acquireAt(ctx, path, sid, session)
	if err != nil || next == nil {
		t.Fatalf("restart after close: %v", err)
	}
	next.Close()
}

func TestNativeSeparateProcessesShareOneGUI(t *testing.T) {
	sid, session, path := testIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	primary, err := acquireAt(ctx, path, sid, session)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeInstanceChild$")
	cmd.Env = append(os.Environ(), "WIREGUIDE_INSTANCE_TEST_PIPE="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("second process: %v\n%s", err, out)
	}
	select {
	case <-primary.Requests():
	case <-ctx.Done():
		t.Fatal("child activation not delivered")
	}
}

func TestNativeProcessExitReleasesReservation(t *testing.T) {
	sid, session, path := testIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeInstanceChild$")
	cmd.Env = append(os.Environ(), "WIREGUIDE_INSTANCE_TEST_PIPE="+path, "WIREGUIDE_INSTANCE_TEST_PRIMARY=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("first process: %v\n%s", err, out)
	}
	primary, err := acquireAt(ctx, path, sid, session)
	if err != nil || primary == nil {
		t.Fatalf("process death left a stale reservation: %v", err)
	}
	primary.Close()
}

func TestNativeInstanceChild(t *testing.T) {
	path := os.Getenv("WIREGUIDE_INSTANCE_TEST_PIPE")
	if path == "" {
		t.Skip("subprocess fixture only")
	}
	if !strings.HasPrefix(path, `\\.\pipe\wireguide.gui.test.`) {
		t.Fatal("not a test pipe")
	}
	sid, session, err := identity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	instance, err := acquireAt(ctx, path, sid, session)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("WIREGUIDE_INSTANCE_TEST_PRIMARY") == "1" {
		if instance == nil {
			t.Fatal("expected primary")
		}
		// Exit without Close to verify Windows releases the pipe after a crash.
		os.Exit(0)
	}
	if instance != nil {
		instance.Close()
		t.Fatal("duplicate GUI reservation")
	}
}

func TestNativeConcurrentLaunchesDoNotCreateAnotherGUI(t *testing.T) {
	sid, session, path := testIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	primary, err := acquireAt(ctx, path, sid, session)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	results := make(chan error, 8)
	for n := 0; n < 8; n++ {
		go func() {
			other, err := acquireAt(ctx, path, sid, session)
			if other != nil {
				other.Close()
				err = fmt.Errorf("created another GUI")
			}
			results <- err
		}()
	}
	for n := 0; n < 8; n++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-primary.Requests():
	default:
		t.Fatal("activation lost")
	}
}

func TestNativeLaunchDuringQuitWaitsForReservationRelease(t *testing.T) {
	sid, session, path := testIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	primary, err := acquireAt(ctx, path, sid, session)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	primary.BeginShutdown()
	closed := make(chan struct{})
	go func() { time.Sleep(100 * time.Millisecond); primary.Close(); close(closed) }()
	replacement, err := acquireAt(ctx, path, sid, session)
	if err != nil || replacement == nil {
		t.Fatalf("did not wait for closing GUI: %v", err)
	}
	defer replacement.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("replacement started before former GUI released its reservation")
	}
}
