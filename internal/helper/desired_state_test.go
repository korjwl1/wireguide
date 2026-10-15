package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

func TestDesiredStateSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// Unsorted input with a duplicate and an empty entry.
	if err := saveDesiredState(dir, []string{"hotel", "office", "hotel", ""}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}
	got := loadDesiredState(dir)
	if len(got) != 2 || got[0] != "hotel" || got[1] != "office" {
		t.Fatalf("loadDesiredState = %v, want sorted [hotel office]", got)
	}
}

func TestSaveDesiredStateEmptyRemovesFile(t *testing.T) {
	dir := t.TempDir()
	if err := saveDesiredState(dir, []string{"office"}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}
	if err := saveDesiredState(dir, nil); err != nil {
		t.Fatalf("saveDesiredState(empty): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, desiredStateFile)); !os.IsNotExist(err) {
		t.Fatalf("desired-state file should be removed when the set is empty, stat err = %v", err)
	}
	if names := loadDesiredState(dir); len(names) != 0 {
		t.Fatalf("loadDesiredState after clear = %v, want empty", names)
	}
}

func TestDesiredStatePredatesBoot(t *testing.T) {
	boot := time.Now()
	cases := []struct {
		name    string
		modTime time.Time
		want    bool
	}{
		{"written an hour before boot", boot.Add(-time.Hour), true},
		{"written well after boot", boot.Add(time.Minute), false},
		{"written just before boot within slack", boot.Add(-time.Second), false},
		{"written just outside slack", boot.Add(-bootTimeSlack - 3*time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := desiredStatePredatesBoot(tc.modTime, boot); got != tc.want {
				t.Fatalf("desiredStatePredatesBoot(%v, %v) = %v, want %v",
					tc.modTime, boot, got, tc.want)
			}
		})
	}
}

func TestRestoreDesiredTunnels_ClearsFileFromPreviousBoot(t *testing.T) {
	dir := t.TempDir()
	if err := saveDesiredState(dir, []string{"office"}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}
	// Backdate the file an hour; current boot started a minute ago.
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, desiredStateFile), stale, stale); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	restoreBootTimeStub(t, func() (time.Time, error) {
		return time.Now().Add(-time.Minute), nil
	})

	h := &Helper{dataDir: dir, restoreOnStart: true}
	h.restoreDesiredTunnels()

	if _, err := os.Stat(filepath.Join(dir, desiredStateFile)); !os.IsNotExist(err) {
		t.Fatalf("desired-state file from a previous boot should be cleared, stat err = %v", err)
	}
}

func TestRestoreDesiredTunnels_SameBootKeepsFileWithoutStore(t *testing.T) {
	dir := t.TempDir()
	if err := saveDesiredState(dir, []string{"office"}); err != nil {
		t.Fatalf("saveDesiredState: %v", err)
	}

	// Boot an hour ago; the file (written now) belongs to this boot.
	restoreBootTimeStub(t, func() (time.Time, error) {
		return time.Now().Add(-time.Hour), nil
	})

	// No tunnel store configured (dev fallback path): the restore cannot
	// proceed and must LEAVE the file so later triggers can act on it.
	h := &Helper{dataDir: dir, restoreOnStart: true}
	h.restoreDesiredTunnels()

	if names := loadDesiredState(dir); len(names) != 1 || names[0] != "office" {
		t.Fatalf("desired-state after storeless restore = %v, want [office]", names)
	}
}

func restoreBootTimeStub(t *testing.T, fn func() (time.Time, error)) {
	t.Helper()
	prev := systemBootTimeNow
	systemBootTimeNow = fn
	t.Cleanup(func() { systemBootTimeNow = prev })
}

// pendingTestFirewall is an in-memory firewall.FirewallManager covering the
// calls the desired-state paths make; anything else panics on the nil embed.
type pendingTestFirewall struct {
	firewall.FirewallManager
	mu         sync.Mutex
	killSwitch bool
	dns        bool
	ksIfaces   []string // interface passed to each EnableKillSwitch
	dnsAllow   []firewall.DNSAllow
	dnsEnables int
}

func (f *pendingTestFirewall) IsKillSwitchEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitch
}

func (f *pendingTestFirewall) IsDNSProtectionEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dns
}

func (f *pendingTestFirewall) EnableKillSwitch(iface string, _ []string, _ []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killSwitch = true
	f.ksIfaces = append(f.ksIfaces, iface)
	return nil
}

func (f *pendingTestFirewall) EnableDNSProtection(allow []firewall.DNSAllow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsAllow = allow
	f.dns = len(allow) > 0
	f.dnsEnables++
	return nil
}

func (f *pendingTestFirewall) DisableDNSProtection() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dns = false
	f.dnsAllow = nil
	return nil
}

func (f *pendingTestFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killSwitch = false
	return nil
}

func newPendingTestHelper(t *testing.T, names ...string) *Helper {
	t.Helper()
	store := storage.NewTunnelStore(t.TempDir())
	for _, name := range names {
		cfg := &domain.WireGuardConfig{Name: name}
		cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		cfg.Interface.Address = []string{"10.0.0.2/24"}
		cfg.Peers = []domain.PeerConfig{{PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", AllowedIPs: []string{"10.0.0.0/24"}}}
		if err := store.Save(cfg); err != nil {
			t.Fatalf("store.Save(%s): %v", name, err)
		}
	}
	// The server is never served; teardown paths only ask it whether a GUI
	// is attached.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	// An empty Manager never touches the network: AllStatuses and
	// DisconnectTunnel only consult its in-memory tunnel map.
	return &Helper{
		server:          ipc.NewServer(ln),
		dataDir:         t.TempDir(),
		manager:         tunnel.NewManager(t.TempDir()),
		firewall:        &pendingTestFirewall{},
		activeCfgs:      make(map[string]*domain.WireGuardConfig),
		pendingDesired:  make(map[string]struct{}),
		userTunnelStore: store,
		restoreOnStart:  true,
	}
}

// stubRestoreConnect fails the listed tunnels and records the rest as
// connected, mirroring doConnectHeld's bookkeeping without a real tunnel.
func stubRestoreConnect(t *testing.T, fail ...string) {
	t.Helper()
	prev := restoreConnect
	restoreConnect = func(h *Helper, cfg *domain.WireGuardConfig) error {
		if slices.Contains(fail, cfg.Name) {
			return errors.New("no network yet")
		}
		h.mu.Lock()
		h.activeCfgs[cfg.Name] = cfg
		delete(h.pendingDesired, cfg.Name)
		h.mu.Unlock()
		h.persistDesiredState()
		return nil
	}
	t.Cleanup(func() { restoreConnect = prev })
}

func assertDesiredState(t *testing.T, h *Helper, want ...string) {
	t.Helper()
	got := loadDesiredState(h.dataDir)
	if !slices.Equal(got, want) {
		t.Fatalf("desired-state = %v, want %v", got, want)
	}
}

// A restore that fails for one tunnel must keep it listed after LATER
// transitions too, not only in the restore's own final write — otherwise the
// next unrelated connect drops it and wake triggers never retry it.
func TestRestoreDesiredTunnels_FailedEntrySurvivesLaterTransitions(t *testing.T) {
	h := newPendingTestHelper(t, "alpha", "bravo")
	if err := saveDesiredState(h.dataDir, []string{"alpha", "bravo"}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRestoreConnect(t, "alpha")

	h.restoreDesiredTunnels()
	assertDesiredState(t, h, "alpha", "bravo")
	if _, ok := h.pendingDesired["alpha"]; !ok {
		t.Fatalf("alpha should be pending after a failed restore, pending = %v", h.pendingDesired)
	}
	if _, ok := h.activeCfgs["alpha"]; ok {
		t.Fatal("a failed restore must not leave alpha in activeCfgs")
	}

	// The user connects another tunnel afterwards.
	h.mu.Lock()
	h.activeCfgs["charlie"] = &domain.WireGuardConfig{Name: "charlie"}
	h.mu.Unlock()
	h.persistDesiredState()
	assertDesiredState(t, h, "alpha", "bravo", "charlie")
}

func TestRestoreDesiredTunnels_DropsMissingConfig(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	if err := saveDesiredState(h.dataDir, []string{"alpha", "ghost"}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRestoreConnect(t, "alpha")

	h.restoreDesiredTunnels()
	assertDesiredState(t, h, "alpha")
}

func TestHandleDisconnect_WithdrawsPendingTunnel(t *testing.T) {
	h := newPendingTestHelper(t, "alpha", "bravo")
	h.pendingDesired["alpha"] = struct{}{}
	h.pendingDesired["bravo"] = struct{}{}
	h.persistDesiredState()

	params, _ := json.Marshal(ipc.DisconnectRequest{TunnelName: "alpha"})
	// alpha isn't up, so the teardown itself reports not-connected; the
	// pending withdrawal must still reach disk.
	_, _ = h.handleDisconnect(params)
	assertDesiredState(t, h, "bravo")

	_, _ = h.handleDisconnect(nil)
	assertDesiredState(t, h)
	if len(h.pendingDesired) != 0 {
		t.Fatalf("disconnect-all should clear pending, got %v", h.pendingDesired)
	}
}

func TestHandleRename_RekeysPendingTunnel(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.pendingDesired["alpha"] = struct{}{}
	h.persistDesiredState()

	params, _ := json.Marshal(ipc.RenameRequest{OldName: "alpha", NewName: "delta"})
	if _, err := h.handleRename(params); err != nil {
		t.Fatalf("handleRename: %v", err)
	}
	assertDesiredState(t, h, "delta")
	if _, ok := h.pendingDesired["delta"]; !ok {
		t.Fatalf("pending should follow the rename, got %v", h.pendingDesired)
	}
}

// The wake/network fallback: with nothing cached, reconnectFn connects the
// listed tunnels through the restore path and drops ones whose config is gone.
func TestReconnectFn_ConnectsPendingDesiredTunnels(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.pendingDesired["alpha"] = struct{}{}
	h.pendingDesired["ghost"] = struct{}{}
	h.persistDesiredState()
	stubRestoreConnect(t)

	if err := h.reconnectFn(context.Background(), ""); err != nil {
		t.Fatalf("reconnectFn: %v", err)
	}
	if h.activeCfgs["alpha"] == nil {
		t.Fatal("alpha should be active after the fallback reconnect")
	}
	if len(h.pendingDesired) != 0 {
		t.Fatalf("pending should be empty after connecting, got %v", h.pendingDesired)
	}
	assertDesiredState(t, h, "alpha")
}

// A retry that was queued before the user turned the tunnel off must not
// bring it back.
func TestConnectPendingDesired_SkipsWithdrawnTunnel(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.pendingDesired["alpha"] = struct{}{}
	h.persistDesiredState()
	var connects atomic.Int32
	prev := restoreConnect
	restoreConnect = func(*Helper, *domain.WireGuardConfig) error { connects.Add(1); return nil }
	t.Cleanup(func() { restoreConnect = prev })

	pending := h.pendingDesiredCfgs()
	params, _ := json.Marshal(ipc.DisconnectRequest{TunnelName: "alpha"})
	_, _ = h.handleDisconnect(params)

	if err := h.connectPendingDesired(context.Background(), pending["alpha"]); err != nil {
		t.Fatalf("connectPendingDesired: %v", err)
	}
	if n := connects.Load(); n != 0 {
		t.Fatalf("withdrawn tunnel was connected %d times", n)
	}
	assertDesiredState(t, h)
}

// Once shutdown has begun, a connect finishing late must not rewrite the
// file that cleanup() cleared.
func TestPersistDesiredState_NoWriteAfterShutdown(t *testing.T) {
	h := newPendingTestHelper(t)
	h.done = make(chan struct{})
	close(h.done)
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	h.persistDesiredState()
	assertDesiredState(t, h)
}

func stubRuleSaysOff(t *testing.T, off ...string) {
	t.Helper()
	prev := restoreRuleSaysOff
	restoreRuleSaysOff = func(_ *Helper, name string) bool { return slices.Contains(off, name) }
	t.Cleanup(func() { restoreRuleSaysOff = prev })
}

// While a reconnect has the kill switch suspended (and DNS rules may be
// absent), a write must record what the user has on, not the momentary
// "off".
func TestPersistDesiredState_RecordsFirewallIntentDuringSuspend(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	h.killSwitchWanted = true
	h.dnsProtectionWanted = true
	h.persistDesiredState()

	got := loadDesiredIntent(h.dataDir)
	if !got.KillSwitch || !got.DNSProtection {
		t.Fatalf("intent = %+v, want kill switch and DNS protection recorded", got)
	}
}

// The crash wiped the blockade; restore must put it back BEFORE connecting,
// so a failed restore still leaves the user blocked rather than leaking.
func TestRestoreDesiredTunnels_ReinstallsKillSwitchFirst(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{Tunnels: []string{"alpha"}, KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRuleSaysOff(t)
	fw := h.firewall.(*pendingTestFirewall)
	var ksAtConnect bool
	prev := restoreConnect
	restoreConnect = func(h *Helper, _ *domain.WireGuardConfig) error {
		ksAtConnect = h.firewall.IsKillSwitchEnabled()
		return errors.New("no network yet")
	}
	t.Cleanup(func() { restoreConnect = prev })

	h.restoreDesiredTunnels()
	if !ksAtConnect {
		t.Fatal("kill switch was not back on when the restore connect ran")
	}
	if !fw.IsKillSwitchEnabled() {
		t.Fatal("kill switch must stay on after a failed restore")
	}
	if got := loadDesiredIntent(h.dataDir); !got.KillSwitch || !slices.Equal(got.Tunnels, []string{"alpha"}) {
		t.Fatalf("intent after failed restore = %+v", got)
	}
}

func TestRestoreDesiredTunnels_SkipsTunnelRuledOff(t *testing.T) {
	h := newPendingTestHelper(t, "alpha", "bravo")
	if err := saveDesiredState(h.dataDir, []string{"alpha", "bravo"}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRuleSaysOff(t, "alpha")
	stubRestoreConnect(t)

	h.restoreDesiredTunnels()
	if h.activeCfgs["alpha"] != nil {
		t.Fatal("alpha's rule says off on this network; it must not be restored")
	}
	assertDesiredState(t, h, "bravo")
}

func TestConnectPendingDesired_RuleOffWithdraws(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.pendingDesired["alpha"] = struct{}{}
	h.persistDesiredState()
	stubRuleSaysOff(t, "alpha")
	stubRestoreConnect(t)

	cfgs := h.pendingDesiredCfgs()
	if err := h.connectPendingDesired(context.Background(), cfgs["alpha"]); err != nil {
		t.Fatal(err)
	}
	if h.activeCfgs["alpha"] != nil {
		t.Fatal("a rule-off pending tunnel must not connect")
	}
	assertDesiredState(t, h)
}

// A helper waiting to retry a restore must not idle-exit: cleanup would
// clear the file and nothing would retry until the GUI next starts it.
func TestArmShutdownTimer_StaysAliveWhileRestorePending(t *testing.T) {
	h := newPendingTestHelper(t)
	h.pendingDesired["alpha"] = struct{}{}
	h.armShutdownTimer(time.Millisecond, "test")
	h.mu.Lock()
	armed := h.shutdownTimer != nil
	h.mu.Unlock()
	if armed {
		t.Fatal("shutdown timer armed while a restore is pending")
	}
}

// After a reconnect with the kill switch on but no tunnel back up, resume
// must keep the blockade instead of logging and leaving traffic open.
func TestResumeFirewall_KeepsKillSwitchWithNoTunnel(t *testing.T) {
	h := newPendingTestHelper(t)
	h.killSwitchWanted = true
	if err := h.resumeFirewall(); err != nil {
		t.Fatalf("resumeFirewall: %v", err)
	}
	fw := h.firewall.(*pendingTestFirewall)
	if !fw.IsKillSwitchEnabled() || !slices.Equal(fw.ksIfaces, []string{""}) {
		t.Fatalf("kill switch enabled=%v ifaces=%v, want base blockade", fw.IsKillSwitchEnabled(), fw.ksIfaces)
	}
}

// A file entry that isn't pending (e.g. a tunnel a concurrent Disconnect
// just dropped from activeCfgs) must not be adopted as a retry.
func TestPendingDesiredCfgs_IgnoresFileOnlyEntries(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	if err := saveDesiredState(h.dataDir, []string{"alpha"}); err != nil {
		t.Fatal(err)
	}
	if cfgs := h.pendingDesiredCfgs(); len(cfgs) != 0 {
		t.Fatalf("pendingDesiredCfgs = %v, want none", cfgs)
	}
	if len(h.pendingDesired) != 0 {
		t.Fatalf("file-only entry adopted as pending: %v", h.pendingDesired)
	}
}

// Wake retry after a failed attempt: resume left the base blockade up and
// the monitor skipped the suspend, so the cached tunnel must reconnect
// through the path that lifts and rebuilds the kill switch.
func TestReconnectFn_ConnectsThroughKillSwitchPathWhenBlockadeUp(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	_ = h.firewall.EnableKillSwitch("", nil, nil)
	var used atomic.Int32
	prev := connectUnderKillSwitch
	connectUnderKillSwitch = func(*Helper, *domain.WireGuardConfig) error { used.Add(1); return nil }
	t.Cleanup(func() { connectUnderKillSwitch = prev })

	if err := h.reconnectFn(context.Background(), ""); err != nil {
		t.Fatalf("reconnectFn: %v", err)
	}
	if used.Load() != 1 {
		t.Fatalf("kill-switch connect path used %d times, want 1", used.Load())
	}
}

// Windows/Linux: a helper the GUI started fresh (logoff, Fast Startup,
// relaunch) must not restore, even though the boot time can't tell.
func TestRestoreDesiredTunnels_FreshStartClearsInsteadOfRestoring(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.restoreOnStart = false
	if err := saveDesiredState(h.dataDir, []string{"alpha"}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	var connects atomic.Int32
	prev := restoreConnect
	restoreConnect = func(*Helper, *domain.WireGuardConfig) error { connects.Add(1); return nil }
	t.Cleanup(func() { restoreConnect = prev })

	h.restoreDesiredTunnels()
	if connects.Load() != 0 {
		t.Fatal("fresh start restored a tunnel")
	}
	assertDesiredState(t, h)
}

// A wake retry tore alpha down and keeps trying to bring it back from the
// cache. The user's Disconnect must stick: success, and alpha leaves the
// cache and the file, so neither the retry nor a crash-restore revives it.
func TestHandleDisconnect_TunnelAlreadyDownDuringRetry(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	h.persistDesiredState()

	params, _ := json.Marshal(ipc.DisconnectRequest{TunnelName: "alpha"})
	if _, err := h.handleDisconnect(params); err != nil {
		t.Fatalf("disconnect of a cached, already-down tunnel should succeed: %v", err)
	}
	if h.activeCfgs["alpha"] != nil {
		t.Fatal("alpha must leave the cache")
	}
	assertDesiredState(t, h)

	// A tunnel the helper knows nothing about is still an error.
	params, _ = json.Marshal(ipc.DisconnectRequest{TunnelName: "ghost"})
	if _, err := h.handleDisconnect(params); err == nil {
		t.Fatal("disconnect of an unknown tunnel should still fail")
	}
}

// Kill switch turned off while a reconnect has it suspended: resume must
// not put it back, and the file must not record it as on.
func TestKillSwitchOffDuringSuspendIsNotUndoneByResume(t *testing.T) {
	h := newPendingTestHelper(t)
	_ = h.firewall.EnableKillSwitch("", nil, nil)
	if err := h.suspendFirewall(); err != nil {
		t.Fatal(err)
	}

	params, _ := json.Marshal(ipc.KillSwitchRequest{Enabled: false})
	if _, err := h.handleSetKillSwitch(params); err != nil {
		t.Fatal(err)
	}
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	h.persistDesiredState()
	if loadDesiredIntent(h.dataDir).KillSwitch {
		t.Fatal("file records the kill switch as on after the user turned it off")
	}
	if err := h.resumeFirewall(); err != nil {
		t.Fatal(err)
	}
	if h.firewall.IsKillSwitchEnabled() {
		t.Fatal("resume re-enabled a kill switch the user turned off")
	}
}

// A wake retry waiting on connectMu with a snapshot of activeCfgs must not
// reconnect a tunnel the user disconnected while it waited.
func TestReconnectFn_SkipsTunnelDisconnectedWhileWaiting(t *testing.T) {
	h := newPendingTestHelper(t)
	h.activeCfgs["alpha"] = &domain.WireGuardConfig{Name: "alpha"}
	_ = h.firewall.EnableKillSwitch("", nil, nil) // route connects through the stub below
	var connects atomic.Int32
	prev := connectUnderKillSwitch
	connectUnderKillSwitch = func(*Helper, *domain.WireGuardConfig) error { connects.Add(1); return nil }
	t.Cleanup(func() { connectUnderKillSwitch = prev })

	h.connectMu.Lock() // the user's Disconnect holds connectMu
	done := make(chan error, 1)
	go func() { done <- h.reconnectFn(context.Background(), "") }()
	time.Sleep(50 * time.Millisecond) // let the retry take its snapshot and block
	h.mu.Lock()
	delete(h.activeCfgs, "alpha") // what handleDisconnect does
	h.mu.Unlock()
	h.connectMu.Unlock()

	<-done
	if n := connects.Load(); n != 0 {
		t.Fatalf("retry reconnected a disconnected tunnel %d times", n)
	}
}
