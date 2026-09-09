//go:build darwin

package elevate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testArgs returns a representative Args for plist generation.
func testArgs() Args {
	return Args{
		SocketPath: "/var/run/wireguide/wireguide.sock",
		SocketUID:  501,
		DataDir:    "/Library/Application Support/wireguide",
	}
}

// TestGeneratedPlistLints guards the XML comments embedded in the plist
// template. plutil is what installAndLoadDaemon runs before attempting the
// install, so a malformed template would surface as a failed admin-prompt
// install rather than a build error.
func TestGeneratedPlistLints(t *testing.T) {
	plist := generatePlistContent("/Library/PrivilegedHelperTools/com.wireguide.helper", testArgs())

	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, []byte(plist), 0644); err != nil {
		t.Fatalf("write plist: %v", err)
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint rejected the generated plist: %v\n%s", err, out)
	}
}

// TestPlistDoesNotRunAtLoad pins the helper's boot behaviour. RunAtLoad=false
// is the whole reason a closed WireGuide leaves no root process behind: with
// it true, launchd starts the helper at every boot with no GUI, no window and
// no tray icon, and the helper's Wi-Fi automation rules could bring a tunnel
// up while the user believes the app is closed.
//
// The runtime half of the same rule lives in helper.Run, which arms the
// startup grace window unconditionally. Both must hold.
func TestPlistDoesNotRunAtLoad(t *testing.T) {
	plist := generatePlistContent("/Library/PrivilegedHelperTools/com.wireguide.helper", testArgs())

	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, []byte(plist), 0644); err != nil {
		t.Fatalf("write plist: %v", err)
	}

	// Read the key back through plutil rather than string-matching, so an
	// XML comment mentioning RunAtLoad can't make this pass spuriously.
	out, err := exec.Command("plutil", "-extract", "RunAtLoad", "raw", "-o", "-", path).CombinedOutput()
	if err != nil {
		t.Fatalf("plutil -extract RunAtLoad: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "false" {
		t.Errorf("RunAtLoad = %q, want \"false\" — the helper must not start at boot; "+
			"users who want WireGuide from login enable auto_start, which installs the GUI LaunchAgent", got)
	}
}

// TestLaunchdDemandLifecycle executes our generated plist through real launchd
// in a temporary per-user job. Its harmless fixture fails once, then exits 0.
// No root helper or VPN state is touched.
func TestLaunchdDemandLifecycle(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_LAUNCHD") != "1" {
		t.Skip("set WIREGUIDE_TEST_LAUNCHD=1 in a logged-in macOS session")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "runs")
	fixture := filepath.Join(dir, "helper")
	script := "#!/bin/sh\nif [ ! -f " + shellQuote(marker) + " ]; then echo first > " + shellQuote(marker) + "; exit 1; fi\necho restarted >> " + shellQuote(marker) + "\n"
	if err := os.WriteFile(fixture, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("com.wireguide.issue41.test-%d", os.Getpid())
	plist := generatePlistContent(fixture, testArgs())
	plist = strings.ReplaceAll(plist, daemonBinary, fixture)
	plist = strings.ReplaceAll(plist, daemonLabel, label)
	plist = strings.ReplaceAll(plist, "/var/log/wireguide-helper.log", filepath.Join(dir, "helper.log"))
	path := filepath.Join(dir, "helper.plist")
	if err := os.WriteFile(path, []byte(plist), 0600); err != nil {
		t.Fatal(err)
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	target := domain + "/" + label
	if out, err := exec.Command("launchctl", "bootstrap", domain, path).CombinedOutput(); err != nil {
		t.Fatalf("bootstrap: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("launchctl", "bootout", target).CombinedOutput(); err != nil {
			t.Errorf("probe cleanup: %v: %s", err, out)
		}
	})
	time.Sleep(time.Second)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("helper ran before explicit demand (stat error: %v)", err)
	}
	if out, err := exec.Command("launchctl", "kickstart", target).CombinedOutput(); err != nil {
		t.Fatalf("kickstart: %v: %s", err, out)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, _ := os.ReadFile(marker)
		if string(out) == "first\nrestarted\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("launchd did not restart failed helper: %q", out)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Give launchd longer than ThrottleInterval to prove a clean exit stays down.
	time.Sleep(6 * time.Second)
	out, err := os.ReadFile(marker)
	if err != nil || string(out) != "first\nrestarted\n" {
		t.Fatalf("helper restarted after successful exit: %q, %v", out, err)
	}
}

// Run the actual generated shell in a process where every privileged command
// is a shell function. No launchd jobs or system files are changed.
func TestDaemonInstallScript(t *testing.T) {
	for _, tt := range []struct {
		name      string
		upToDate  bool
		fail      string
		loaded    bool
		wantError bool
		want      string
	}{
		{"fresh install", false, "", false, false, "bootout\nprint\nrm\nmkdir\ncp\nxattr\nchown\nchmod\ncp\nchown\nchmod\nbootstrap\nkickstart\n"},
		{"already installed", true, "", false, false, "kickstart\n"},
		{"kickstart failure returned for bounded repair", true, "first-kickstart", false, true, "kickstart\n"},
		{"copy failure", false, "cp", false, true, "bootout\nprint\nrm\nmkdir\ncp\n"},
		{"purge failure", false, "rm", false, true, "bootout\nprint\nrm\n"},
		{"quarantine absent", false, "xattr", false, false, "bootout\nprint\nrm\nmkdir\ncp\nxattr\nchown\nchmod\ncp\nchown\nchmod\nbootstrap\nkickstart\n"},
		{"bootstrap failure", false, "bootstrap", false, true, "bootout\nprint\nrm\nmkdir\ncp\nxattr\nchown\nchmod\ncp\nchown\nchmod\nbootstrap\n"},
		{"teardown timeout", false, "", true, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			trace := filepath.Join(t.TempDir(), "trace")
			stubs := `
record() { printf '%s\n' "$1" >> "$TRACE"; [ "$FAIL" != "$1" ]; }
launchctl() {
    record "$1" || return 42
    case "$1" in
        print) [ "$LOADED" = true ]; return $? ;;
        kickstart)
            if [ "$FAIL" = first-kickstart ]; then FAIL=''; return 42; fi ;;
    esac
}
rm() { record rm; }
mkdir() { record mkdir; }
cp() { record cp; }
xattr() { record xattr; }
chown() { record chown; }
chmod() { record chmod; }
sleep() { :; }
`
			cmd := exec.Command("/bin/sh", "-c", stubs+daemonInstallScript("/tmp/app's binary", "/tmp/helper.plist", tt.upToDate))
			cmd.Env = append(os.Environ(), "TRACE="+trace, "FAIL="+tt.fail, fmt.Sprintf("LOADED=%t", tt.loaded))
			out, err := cmd.CombinedOutput()
			if (err != nil) != tt.wantError {
				t.Errorf("error = %v, wantError = %t; output: %s", err, tt.wantError, out)
			}
			got, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			if tt.loaded {
				if strings.Contains(string(got), "rm\n") || strings.Contains(string(got), "cp\n") {
					t.Errorf("changed files while old job was still loaded: %s", got)
				}
			} else if string(got) != tt.want {
				t.Errorf("command trace = %q, want %q", got, tt.want)
			}
		})
	}
}
