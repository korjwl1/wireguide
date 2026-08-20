//go:build darwin

package elevate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

// TestInstallScriptKickstarts pairs with RunAtLoad=false: `launchctl
// bootstrap` only registers the job, so without an explicit kickstart the
// helper never starts and installAndLoadDaemon's readiness poll times out
// with "daemon installed but socket not live after 6s".
func TestInstallScriptKickstarts(t *testing.T) {
	// Mirror the command construction in installAndLoadDaemon closely
	// enough to catch a bootstrap that lost its kickstart.
	src, err := os.ReadFile("spawn_darwin.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "launchctl bootstrap system %s") {
		t.Fatal("install script no longer bootstraps the daemon")
	}
	if !strings.Contains(s, "launchctl kickstart -k system/%s") {
		t.Error("install script bootstraps but never kickstarts; with RunAtLoad=false " +
			"the helper process would never start")
	}
}

// TestInstallScriptPurgesBeforeCopy pins the issue #41 fix ordering: the old
// daemon must be booted out and its binary+plist REMOVED before the fresh
// copy lands. Overwriting the ad-hoc-signed binary in place leaves a
// Background Task Management record keyed to the old binary's identity, and
// launchd then refuses to start the daemon — the admin-prompt loop from
// issue #41. bootout must also precede the copy so we never rewrite the
// binary of a still-running process.
func TestInstallScriptPurgesBeforeCopy(t *testing.T) {
	src, err := os.ReadFile("spawn_darwin.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	s := string(src)

	bootout := strings.Index(s, "launchctl bootout system/%s")
	purge := strings.Index(s, "rm -f %s %s")
	cp := strings.Index(s, "cp -f %s %s")
	switch {
	case purge == -1:
		t.Fatal("install script no longer purges the old binary+plist; " +
			"in-place overwrite re-breaks the BTM record (issue #41)")
	case bootout == -1 || cp == -1:
		t.Fatal("install script lost its bootout or copy step")
	case !(bootout < purge && purge < cp):
		t.Errorf("install script order must be bootout < purge < copy, got indexes %d/%d/%d",
			bootout, purge, cp)
	}
}

// TestKickstartOnlyPathEscalates guards the single-prompt guarantee: the
// kickstart-only fast path must fall back to the full install inside the
// same admin session (`|| { … }`), never strand the user with a failed
// kickstart that a second password prompt would be needed to repair.
func TestKickstartOnlyPathEscalates(t *testing.T) {
	src, err := os.ReadFile("spawn_darwin.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !strings.Contains(string(src), `launchctl kickstart -k system/%s 2>/dev/null || { %s; }`) {
		t.Error("kickstart-only path no longer escalates to the full install in the same admin session")
	}
}
