//go:build darwin

package elevate

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// testArgs returns a representative Args for plist generation.
func testArgs() Args {
	return Args{
		SocketPath: "/var/run/com.wireguide.helper.sock",
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

// plistExtract reads a key back through plutil so XML comments mentioning a
// key can't satisfy the assertion.
func plistExtract(t *testing.T, path, keypath string) string {
	t.Helper()
	out, err := exec.Command("plutil", "-extract", keypath, "raw", "-o", "-", path).CombinedOutput()
	if err != nil {
		t.Fatalf("plutil -extract %s: %v\n%s", keypath, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestPlistDeclaresLaunchdSocket pins the socket-activation contract: launchd
// binds the socket directly under /var/run (it does not create parent
// directories), private to the owning uid, and the boot behaviour is unchanged.
func TestPlistDeclaresLaunchdSocket(t *testing.T) {
	plist := generatePlistContent("/Library/PrivilegedHelperTools/com.wireguide.helper", testArgs())
	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, []byte(plist), 0644); err != nil {
		t.Fatal(err)
	}
	for keypath, want := range map[string]string{
		"Sockets.Listeners.SockPathName":  "/var/run/com.wireguide.helper.sock",
		"Sockets.Listeners.SockType":      "stream",
		"Sockets.Listeners.SockPathMode":  "384", // 0600
		"Sockets.Listeners.SockPathOwner": fmt.Sprint(os.Getuid()),
		"RunAtLoad":                       "false",
		"KeepAlive.AfterInitialDemand":    "true",
		"KeepAlive.SuccessfulExit":        "false",
	} {
		if got := plistExtract(t, path, keypath); got != want {
			t.Errorf("%s = %q, want %q", keypath, got, want)
		}
	}
	if got := plistExtract(t, path, "Sockets.Listeners.SockPathName"); filepath.Dir(got) != "/var/run" {
		t.Errorf("SockPathName %q must sit directly in /var/run", got)
	}
	if got := plistExtract(t, path, "Sockets.Listeners.SockPathName"); got != ipc.DarwinSocketPath {
		t.Errorf("SockPathName %q differs from ipc.DarwinSocketPath %q", got, ipc.DarwinSocketPath)
	}
}

// TestLaunchdDemandLifecycle executes our generated plist through real launchd
// in a temporary per-user job: loading it runs nothing (runs = 0), and the
// first connect to its socket launches it. The fixture fails once and is then
// restarted by KeepAlive. No root helper or VPN state is touched.
func TestLaunchdDemandLifecycle(t *testing.T) {
	if os.Getenv("WIREGUIDE_TEST_LAUNCHD") != "1" {
		t.Skip("set WIREGUIDE_TEST_LAUNCHD=1 in a logged-in macOS session")
	}
	// sun_path is limited to 104 bytes on darwin; t.TempDir is too long.
	dir, err := os.MkdirTemp("/tmp", "wg-demand-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	marker := filepath.Join(dir, "runs")
	sock := filepath.Join(dir, "helper.sock")
	fixture := filepath.Join(dir, "helper")
	script := "#!/bin/sh\nif [ ! -f " + shellQuote(marker) + " ]; then echo first > " + shellQuote(marker) + "; exit 1; fi\necho restarted >> " + shellQuote(marker) + "\nexit 0\n"
	if err := os.WriteFile(fixture, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("com.wireguide.issue41.test-%d", os.Getpid())
	plist := generatePlistContent(fixture, testArgs())
	// The socket path embeds the label, so rewrite it before the label.
	plist = strings.ReplaceAll(plist, ipc.DarwinSocketPath, sock)
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
		t.Fatalf("helper ran before any connect (stat error: %v)", err)
	}
	if out, _ := exec.Command("launchctl", "print", target).CombinedOutput(); !strings.Contains(string(out), "runs = 0") {
		t.Fatalf("expected runs = 0 after bootstrap:\n%s", out)
	}
	if err := daemonLoadedFromPrint(exec.Command("launchctl", "print", target).CombinedOutput()); err != nil {
		t.Fatalf("freshly bootstrapped job should pass the loaded check: %v", err)
	}
	// The connect itself is the demand.
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		out, _ := exec.Command("launchctl", "print", target).CombinedOutput()
		t.Fatalf("connect to launchd socket: %v\n%s", err, out)
	}
	defer c.Close()
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, _ := os.ReadFile(marker)
		if string(out) == "first\nrestarted\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect did not launch the job and have KeepAlive restart the failed run: %q", out)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Run the actual generated shell in a process where every privileged command
// is a shell function. No launchd jobs or system files are changed.
func TestDaemonInstallScript(t *testing.T) {
	for _, tt := range []struct {
		name      string
		fail      string
		loaded    bool
		wantError bool
		want      string
	}{
		{"fresh install", "", false, false, "bootout\nprint\nrm\nmkdir\ncp\nxattr\nchown\nchmod\ncp\nchown\nchmod\nbootstrap\nkickstart\n"},
		{"kickstart failure after bootstrap", "kickstart", false, true, "bootout\nprint\nrm\nmkdir\ncp\nxattr\nchown\nchmod\ncp\nchown\nchmod\nbootstrap\nkickstart\n"},
		{"copy failure", "cp", false, true, "bootout\nprint\nrm\nmkdir\ncp\n"},
		{"purge failure", "rm", false, true, "bootout\nprint\nrm\n"},
		{"quarantine absent", "xattr", false, false, "bootout\nprint\nrm\nmkdir\ncp\nxattr\nchown\nchmod\ncp\nchown\nchmod\nbootstrap\nkickstart\n"},
		{"bootstrap failure", "bootstrap", false, true, "bootout\nprint\nrm\nmkdir\ncp\nxattr\nchown\nchmod\ncp\nchown\nchmod\nbootstrap\n"},
		{"teardown timeout", "", true, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			trace := filepath.Join(t.TempDir(), "trace")
			stubs := `
record() { printf '%s\n' "$1" >> "$TRACE"; [ "$FAIL" != "$1" ]; }
launchctl() {
    record "$1" || return 42
    case "$1" in
        print) [ "$LOADED" = true ]; return $? ;;
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
			cmd := exec.Command("/bin/sh", "-c", stubs+daemonInstallScript("/tmp/app's binary", "/tmp/helper.plist"))
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

func TestAppBundleOf(t *testing.T) {
	for exe, want := range map[string]string{
		"/Applications/WireGuide.app/Contents/MacOS/wireguide": "/Applications/WireGuide.app",
		"/Users/u/Apps/Wire & Guide.app/Contents/MacOS/wg":     "/Users/u/Apps/Wire & Guide.app",
		"/Library/PrivilegedHelperTools/com.wireguide.helper":  "",
		"/Users/u/dev/wireguide/wireguide":                     "",
		"/Applications/NotAnApp/Contents/MacOS/wireguide":      "",
		"relative/X.app/Contents/MacOS/wireguide":              "",
		"/Applications/A\x01B.app/Contents/MacOS/wireguide":    "",
	} {
		if got := appBundleOf(exe); got != want {
			t.Errorf("appBundleOf(%q) = %q, want %q", exe, got, want)
		}
	}
}

// The plist pins the installing app bundle so an orphaned helper can
// uninstall itself. A dev run (exe outside a .app) omits the flag, and an
// install written by an older build (no flag) no longer matches, so it is
// detected as needing a reinstall exactly once.
func TestPlistCarriesAppBundle(t *testing.T) {
	const exe = "/Applications/Wire & Guide.app/Contents/MacOS/wireguide"
	withApp := generatePlistContent(exe, testArgs())
	dev := generatePlistContent("/Users/u/dev/wireguide", testArgs())
	if withApp == dev {
		t.Fatal("plist must differ when an app bundle is pinned")
	}
	if strings.Contains(dev, "--app-bundle") {
		t.Error("dev run must not pin an app bundle")
	}

	path := filepath.Join(t.TempDir(), "test.plist")
	if err := os.WriteFile(path, []byte(withApp), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint: %v\n%s", err, out)
	}
	if got, want := plistExtract(t, path, "ProgramArguments.5"), "--app-bundle=/Applications/Wire & Guide.app"; got != want {
		t.Errorf("ProgramArguments.5 = %q, want %q", got, want)
	}
}

// A symlinked executable (Homebrew's /opt/homebrew/bin/wireguide) resolves to
// the real bundle so all launch paths produce the same plist.
func TestAppBundleOfResolvesSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	macos := filepath.Join(root, "WireGuide.app", "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(macos, "wireguide")
	if err := os.WriteFile(real, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "bin-wireguide")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "WireGuide.app")
	if got := appBundleOf(link); got != want {
		t.Errorf("appBundleOf(symlink) = %q, want %q", got, want)
	}
}
