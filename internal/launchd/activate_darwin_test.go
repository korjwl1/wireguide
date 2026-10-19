//go:build darwin && cgo

package launchd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A plain test process was not started by launchd.
func TestListenersOutsideLaunchd(t *testing.T) {
	if os.Getenv(fixtureEnv) != "" {
		t.Skip("running as launchd fixture")
	}
	if _, err := Listeners(); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("Listeners() error = %v, want ErrNotManaged", err)
	}
}

const fixtureEnv = "WIREGUIDE_LAUNCHD_FIXTURE_SOCK"

// TestLaunchdFixture is the launchd-spawned job body for
// TestNativeSocketActivation: it adopts the socket, serves exactly one
// connection and exits 0. It is a no-op in a normal test run.
func TestLaunchdFixture(t *testing.T) {
	marker := os.Getenv(fixtureEnv)
	if marker == "" {
		t.Skip("only meaningful inside the launchd fixture job")
	}
	ls, err := Listeners()
	if err != nil {
		os.WriteFile(marker+".err", []byte(err.Error()), 0600)
		t.Fatal(err)
	}
	c, err := ls[0].Accept()
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(marker, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	fmt.Fprintf(f, "run %d\n", os.Getpid())
	f.Close()
	c.Write([]byte("ok"))
	c.Close()
	ls[0].Close()
	os.Exit(0)
}

// TestNativeSocketActivation runs a throwaway per-user (gui/<uid>) launchd
// job in a temp dir. It never touches the system domain.
func TestNativeSocketActivation(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_LAUNCHD") != "1" {
		t.Skip("set WIREGUIDE_TEST_LAUNCHD=1 in a logged-in macOS session")
	}
	// sun_path is limited to 104 bytes on darwin.
	dir, err := os.MkdirTemp("/tmp", "wg-ld-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	marker := filepath.Join(dir, "runs")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("com.wireguide.d5.test-%d", os.Getpid())
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>%s</string>
    <key>ProgramArguments</key>
    <array><string>%s</string><string>-test.run=^TestLaunchdFixture$</string></array>
    <key>EnvironmentVariables</key>
    <dict><key>%s</key><string>%s</string></dict>
    <key>RunAtLoad</key><false/>
    <key>ThrottleInterval</key><integer>1</integer>
    <key>Sockets</key>
    <dict><key>Listeners</key>
    <dict>
        <key>SockPathName</key><string>%s</string>
        <key>SockType</key><string>stream</string>
        <key>SockPathMode</key><integer>384</integer>
    </dict></dict>
    <key>StandardErrorPath</key><string>%s</string>
    <key>StandardOutPath</key><string>%s</string>
</dict>
</plist>
`, label, exe, fixtureEnv, marker, sock, filepath.Join(dir, "log"), filepath.Join(dir, "log"))
	path := filepath.Join(dir, "job.plist")
	if err := os.WriteFile(path, []byte(plist), 0600); err != nil {
		t.Fatal(err)
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	if out, err := exec.Command("launchctl", "bootstrap", domain, path).CombinedOutput(); err != nil {
		t.Fatalf("bootstrap: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("launchctl", "bootout", domain+"/"+label).Run() })

	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("job ran before any connect (stat: %v)", err)
	}
	for i := 1; i <= 2; i++ {
		c, err := net.DialTimeout("unix", sock, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 2)
		if _, err := c.Read(buf); err != nil || string(buf) != "ok" {
			errText, _ := os.ReadFile(marker + ".err")
			t.Fatalf("connect %d: read %q, %v (fixture error: %s)", i, buf, err, errText)
		}
		c.Close()
		time.Sleep(1500 * time.Millisecond) // > ThrottleInterval
	}
	out, _ := os.ReadFile(marker)
	if n := strings.Count(string(out), "run "); n != 2 {
		t.Fatalf("launchd launched the job %d times, want 2 (one per connect): %q", n, out)
	}
	// The socket file must survive the job exiting.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket file vanished after job exit: %v", err)
	}
}
