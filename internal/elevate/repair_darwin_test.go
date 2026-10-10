//go:build darwin

package elevate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/update"
)

func TestBoundedDaemonRepair(t *testing.T) {
	failed := errors.New("startup failed")
	for _, tt := range []struct {
		name               string
		fast               bool
		startErr, readyErr []error
		wantCalls          []bool
		wantErr            error
	}{
		{"healthy passive start", true, nil, nil, []bool{true}, nil},
		{"job not loaded repairs once", true, []error{failed, nil}, nil, []bool{true, false}, nil},
		{"loaded job without RPC repairs once", true, nil, []error{failed, nil}, []bool{true, false}, nil},
		{"failed full repair stops", true, nil, []error{failed, failed}, []bool{true, false}, failed},
		{"fresh install failure stops", false, []error{failed}, nil, []bool{false}, failed},
		{"canceled authorization stops", true, []error{ErrAuthorizationCanceled}, nil, []bool{true}, ErrAuthorizationCanceled},
		{"disabled job stops", true, []error{ErrBackgroundDisabled}, nil, []bool{true}, ErrBackgroundDisabled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []bool
			probes := 0
			err := startDaemonWithRepair(context.Background(), tt.fast, func(fast bool) error {
				calls = append(calls, fast)
				if len(calls) <= len(tt.startErr) {
					return tt.startErr[len(calls)-1]
				}
				return nil
			}, func(context.Context) error {
				probes++
				if probes <= len(tt.readyErr) {
					return tt.readyErr[probes-1]
				}
				return nil
			})
			if !reflect.DeepEqual(calls, tt.wantCalls) || !errors.Is(err, tt.wantErr) {
				t.Fatalf("calls=%v err=%v; want %v, %v", calls, err, tt.wantCalls, tt.wantErr)
			}
		})
	}
}

// The no-prompt fast path: with an up-to-date install the only things that
// run are the enabled check and the unprivileged loaded check. The admin
// authorization (osascript) must not be reached.
func TestFastPathDoesNotAuthorize(t *testing.T) {
	var authorized []string
	ops := daemonOps{
		checkEnabled: func(context.Context) error { return nil },
		loaded:       func(context.Context) error { return nil },
		authorize:    func(script string) error { authorized = append(authorized, script); return nil },
	}
	ctx := context.Background()
	if err := startDaemonStep(ctx, ops, "/tmp/exe", "/tmp/p.plist", true); err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 0 {
		t.Fatalf("fast path requested administrator authorization: %v", authorized)
	}
	// Full repair authorizes exactly once with the install script.
	if err := startDaemonStep(ctx, ops, "/tmp/exe", "/tmp/p.plist", false); err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 1 || !strings.Contains(authorized[0], "launchctl bootstrap system") {
		t.Fatalf("full repair scripts = %v", authorized)
	}
}

func TestFastPathEscalatesOnlyOnFailure(t *testing.T) {
	notLoaded := errors.New("not loaded")
	for _, tt := range []struct {
		name          string
		loadedErr     error
		readyErr      error
		wantAuthorize int
	}{
		{"loaded and ready", nil, nil, 0},
		{"readiness arrives late but within the wait", nil, nil, 0},
		{"job not loaded", notLoaded, nil, 1},
		{"wait timed out", nil, errors.New("helper did not become responsive"), 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authorized := 0
			ops := daemonOps{
				checkEnabled: func(context.Context) error { return nil },
				loaded:       func(context.Context) error { return tt.loadedErr },
				authorize:    func(string) error { authorized++; return nil },
			}
			readyCalls := 0
			err := startDaemonWithRepair(context.Background(), true, func(fast bool) error {
				return startDaemonStep(context.Background(), ops, "/tmp/exe", "/tmp/p.plist", fast)
			}, func(context.Context) error {
				readyCalls++
				if readyCalls == 1 && tt.readyErr != nil {
					return tt.readyErr
				}
				return nil
			})
			if err != nil || authorized != tt.wantAuthorize {
				t.Fatalf("err=%v authorized=%d, want %d", err, authorized, tt.wantAuthorize)
			}
		})
	}
}

func TestDaemonLoadedFromPrint(t *testing.T) {
	const ok = "com.wireguide.helper = {\n\tstate = not running\n\truns = 0\n\n\tsockets = {\n\t\t\"Listeners\" = {\n\t\t\ttype = stream\n\n\t\t\tsockets = {\n\t\t\t\t45 (no bytes to read)\n\t\t\t}\n\n\t\t\tactive = 0\n\t\t}\n\t}\n\n\tspawn type = daemon (3)\n}\n"
	const bad = "com.wireguide.helper = {\n\tsockets = {\n\t\t\"Listeners\" = {\n\t\t\ttype = stream\n\t\t\terror = 2\n\t\t}\n\t}\n}\n"
	const errOutsideSockets = "com.wireguide.helper = {\n\tlast exit code = 1\n\terror = 5\n\tsockets = {\n\t}\n}\n"
	for _, tt := range []struct {
		name    string
		out     string
		cmdErr  error
		wantErr bool
	}{
		{"healthy socket", ok, nil, false},
		{"socket bind error", bad, nil, true},
		{"error outside the sockets block is ignored", errOutsideSockets, nil, false},
		{"no sockets block defers to the wait", "com.wireguide.helper = {\n\tstate = not running\n}\n", nil, false},
		{"not loaded", "Could not find service", errors.New("exit status 113"), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := daemonLoadedFromPrint([]byte(tt.out), tt.cmdErr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %t", err, tt.wantErr)
			}
		})
	}
}

// With launchd's socket present the probe's connect starts the helper, so a
// readiness arriving after the old 1 s budget must still count as healthy.
func TestHelperResponsiveToleratesSlowActivation(t *testing.T) {
	addr := repairSocket(t)
	listener, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(listener)
	srv.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		time.Sleep(1500 * time.Millisecond) // > the 1 s no-socket budget
		return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: update.CurrentVersion()}, nil
	})
	go srv.Serve()
	t.Cleanup(srv.Shutdown)
	if err := helperResponsive(context.Background(), addr); err != nil {
		t.Fatalf("slow activation treated as unhealthy: %v", err)
	}
}

func TestRepairStopsWhenAppCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := startDaemonWithRepair(ctx, true, func(bool) error { calls++; return nil }, func(context.Context) error { cancel(); return ctx.Err() })
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestDisabledDaemonDetection(t *testing.T) {
	for _, tt := range []struct {
		output   string
		disabled bool
	}{
		{"disabled services = {\n\t\"com.wireguide.helper\" => true\n}\n", true},
		{"\t\"com.wireguide.helper\" => true,\n", true},
		{"\t\"com.wireguide.helper\" => false\n", false},
		{"\t\"com.wireguide.helper.old\" => true\n", false},
		{"\t\"com.other.helper\" => true\n", false},
		{"\t\"com.wireguide.helper\" => disabled\n", true},
		{"\t\"com.wireguide.helper\" => enabled\n", false},
		{"Bootstrap failed: 5: Input/output error", false},
	} {
		if got := disabledDaemonLine.MatchString(tt.output); got != tt.disabled {
			t.Errorf("%q: disabled=%t", tt.output, got)
		}
	}
}

func repairSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wg-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func TestHelperHealthRequiresCompatibleRPC(t *testing.T) {
	for _, version := range []string{update.CurrentVersion(), "0.0.0-old"} {
		t.Run(version, func(t *testing.T) {
			addr := repairSocket(t)
			listener, err := ipc.Listen(addr, -1, "")
			if err != nil {
				t.Fatal(err)
			}
			srv := ipc.NewServer(listener)
			srv.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
				return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: version}, nil
			})
			go srv.Serve()
			t.Cleanup(srv.Shutdown)
			err = helperResponsive(context.Background(), addr)
			if (err == nil) != (version == update.CurrentVersion()) {
				t.Fatalf("health error=%v for version %s", err, version)
			}
			if srv.HasControlConn() {
				t.Fatal("health probe acquired a GUI lease")
			}
		})
	}
}

func TestReachableSocketWithoutRPCIsNotHealthy(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(map[bool]string{false: "closed", true: "stalled"}[stall], func(t *testing.T) {
			addr := repairSocket(t)
			l, err := net.Listen("unix", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, e := l.Accept()
				if e == nil {
					accepted <- c
					if !stall {
						c.Close()
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			started := time.Now()
			err = helperResponsive(ctx, addr)
			if err == nil {
				t.Fatal("socket without RPC accepted as healthy")
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("context ignored: %v", elapsed)
			}
			select {
			case c := <-accepted:
				c.Close()
			case <-time.After(time.Second):
				t.Fatal("no connection accepted")
			}
		})
	}
}

// Exercise the host's actual output vocabulary: Tahoe uses disabled/enabled,
// while other launchctl versions print true/false.
func TestNativeDisabledStateParsing(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_LAUNCHD") != "1" {
		t.Skip("requires logged-in macOS session")
	}
	label := fmt.Sprintf("com.wireguide.issue41.disabled-%d", os.Getpid())
	target := fmt.Sprintf("gui/%d/%s", os.Getuid(), label)
	if out, err := exec.Command("launchctl", "disable", target).CombinedOutput(); err != nil {
		t.Fatalf("disable fixture: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("launchctl", "enable", target).CombinedOutput(); err != nil {
			t.Errorf("enable fixture: %v: %s", err, out)
		}
	})
	out, err := exec.Command("launchctl", "print-disabled", fmt.Sprintf("gui/%d", os.Getuid())).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !disabledDaemonLine.MatchString(strings.ReplaceAll(string(out), label, daemonLabel)) {
		t.Fatalf("native disabled fixture was not recognized: %s", out)
	}
}
