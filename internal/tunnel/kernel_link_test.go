//go:build unix

package tunnel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

type fakeLinkBackend struct {
	mu sync.Mutex

	links map[int32]kernelLink

	dataDir string
	tunnel  string

	createErr   error
	createAfter error
	lookupErr   error
	nameErr     error
	aliasErr    error
	deleteErr   error

	creates       []int32
	createFlagsOK bool
	intentAtCall  []int32
	deletes       []int32
	aliases       []int32
	lookups       int
}

func newFakeLinkBackend() *fakeLinkBackend {
	return &fakeLinkBackend{links: map[int32]kernelLink{}}
}

func (f *fakeLinkBackend) add(l kernelLink) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links[l.Index] = l
}

func (f *fakeLinkBackend) has(index int32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.links[index]
	return ok
}

func (f *fakeLinkBackend) mutations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.creates) + len(f.deletes) + len(f.aliases)
}

func (f *fakeLinkBackend) LinkByIndex(index int32) (kernelLink, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if f.lookupErr != nil {
		return kernelLink{}, false, f.lookupErr
	}
	l, ok := f.links[index]
	return l, ok, nil
}

func (f *fakeLinkBackend) LinkByName(name string) (kernelLink, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nameErr != nil {
		return kernelLink{}, false, f.nameErr
	}
	for _, l := range f.links {
		if l.Name == name {
			return l, true, nil
		}
	}
	return kernelLink{}, false, nil
}

func (f *fakeLinkBackend) CreateWireGuard(name string, index int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, index)
	if f.dataDir != "" {
		path, _ := kernelIntentPaths(f.dataDir, kernelIntentBase(f.tunnel))
		in, err := readKernelIntent(path)
		if err != nil {
			f.intentAtCall = append(f.intentAtCall, -1)
		} else {
			f.intentAtCall = append(f.intentAtCall, in.IfIndex)
		}
	}
	if f.createErr != nil {
		return f.createErr
	}
	if _, ok := f.links[index]; ok {
		return errKernelLinkExists
	}
	for _, l := range f.links {
		if l.Name == name {
			return errKernelLinkExists
		}
	}
	f.links[index] = kernelLink{Index: index, Name: name, Kind: kernelLinkKind}
	return f.createAfter
}

func (f *fakeLinkBackend) SetAlias(index int32, alias string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aliases = append(f.aliases, index)
	if f.aliasErr != nil {
		return f.aliasErr
	}
	l, ok := f.links[index]
	if !ok {
		return errKernelLinkNotFound
	}
	l.Alias = alias
	f.links[index] = l
	return nil
}

func (f *fakeLinkBackend) DeleteIndex(index int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, index)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.links[index]; !ok {
		return errKernelLinkNotFound
	}
	delete(f.links, index)
	return nil
}

const (
	testTunnel = "home"
	testIface  = "wg-test0"
	idxA       = int32(1<<24 + 11)
	idxB       = int32(1<<24 + 22)
	idxC       = int32(1<<24 + 33)
)

func useFakeLinkBackend(t *testing.T, f *fakeLinkBackend) *int {
	t.Helper()
	calls := 0
	old := kernelLinkBackendFactory
	kernelLinkBackendFactory = func() (kernelLinkBackend, error) { calls++; return f, nil }
	t.Cleanup(func() { kernelLinkBackendFactory = old })
	return &calls
}

func useIndexSequence(t *testing.T, seq ...int32) {
	t.Helper()
	old := newKernelLinkIndex
	i := 0
	newKernelLinkIndex = func() int32 {
		v := seq[min(i, len(seq)-1)]
		i++
		return v
	}
	t.Cleanup(func() { newKernelLinkIndex = old })
}

func intentPath(dir string) string {
	p, _ := kernelIntentPaths(dir, kernelIntentBase(testTunnel))
	return p
}

func writeTestIntent(t *testing.T, dir string, index int32) {
	t.Helper()
	in := &kernelLinkIntent{Version: kernelLinkIntentVersion, Tunnel: testTunnel, IfName: testIface, IfIndex: index, Token: "tok", CreatedUnix: time.Now().Unix()}
	if err := writeKernelIntent(intentPath(dir), in); err != nil {
		t.Fatal(err)
	}
}

func intentExists(dir string) bool {
	_, err := os.Stat(intentPath(dir))
	return err == nil
}

func request(f *fakeLinkBackend, dir string) kernelLinkRequest {
	f.dataDir, f.tunnel = dir, testTunnel
	return kernelLinkRequest{backend: f, dataDir: dir, tunnel: testTunnel, name: testIface}
}

func ours(index int32, alias string) kernelLink {
	return kernelLink{Index: index, Name: testIface, Kind: kernelLinkKind, Alias: alias}
}

func TestRandomKernelLinkIndexRange(t *testing.T) {
	for range 1000 {
		v := randomKernelLinkIndex()
		if v < kernelLinkIndexMin || v > kernelLinkIndexMax {
			t.Fatalf("index %d out of range", v)
		}
	}
}

func TestKernelLinkC0NothingToRecover(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	calls := useFakeLinkBackend(t, f)
	recoverKernelLinkIntents(dir)
	if *calls != 0 || f.lookups != 0 {
		t.Fatalf("recovery without intents used netlink: factory=%d lookups=%d", *calls, f.lookups)
	}
}

func TestKernelLinkC1IntentWithoutLinkIsCleared(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.add(kernelLink{Index: 5, Name: testIface, Kind: kernelLinkKind})
	useFakeLinkBackend(t, f)
	writeTestIntent(t, dir, idxA)

	recoverKernelLinkIntents(dir)

	if intentExists(dir) {
		t.Fatal("intent for a link that never existed was kept")
	}
	if !f.has(5) || f.mutations() != 0 {
		t.Fatalf("foreign same-name link at another index was touched: %+v", f)
	}
}

func TestKernelLinkCrashCheckpointsDeleteOnlyOwnedIndex(t *testing.T) {
	tests := []struct {
		name      string
		link      kernelLink
		wantGone  bool
		wantKeep  bool
		wantNoDel bool
	}{
		{name: "C2 created without alias", link: ours(idxA, ""), wantGone: true},
		{name: "C3 alias set", link: ours(idxA, kernelOwnershipAlias(testTunnel)), wantGone: true},
		{name: "foreign alias at index", link: ours(idxA, "other-tool"), wantKeep: true, wantNoDel: true},
		{name: "other profile alias at index", link: ours(idxA, kernelOwnershipAlias("work")), wantKeep: true, wantNoDel: true},
		{name: "other kind at index", link: kernelLink{Index: idxA, Name: testIface, Kind: "veth"}, wantKeep: true, wantNoDel: true},
		{name: "other name at index", link: kernelLink{Index: idxA, Name: "eth7", Kind: kernelLinkKind}, wantKeep: true, wantNoDel: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeLinkBackend()
			f.add(tc.link)
			useFakeLinkBackend(t, f)
			writeTestIntent(t, dir, idxA)

			recoverKernelLinkIntents(dir)

			if got := !f.has(idxA); got != tc.wantGone {
				t.Fatalf("link gone = %v, want %v", got, tc.wantGone)
			}
			if intentExists(dir) != tc.wantKeep {
				t.Fatalf("intent kept = %v, want %v", intentExists(dir), tc.wantKeep)
			}
			if tc.wantNoDel && len(f.deletes) != 0 {
				t.Fatalf("foreign device received RTM_DELLINK: %v", f.deletes)
			}
		})
	}
}

func TestKernelLinkCreateHappyPathAndHandoff(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	useIndexSequence(t, idxA)
	h, err := createKernelLink(request(f, dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.links[idxA]; got != ours(idxA, kernelOwnershipAlias(testTunnel)) {
		t.Fatalf("created link = %+v", got)
	}
	if len(f.intentAtCall) != 1 || f.intentAtCall[0] != idxA {
		t.Fatalf("intent was not durable before RTM_NEWLINK: %v", f.intentAtCall)
	}
	if !intentExists(dir) {
		t.Fatal("intent removed before handoff")
	}
	if err := h.commitKernelLinkIntent(); err != nil {
		t.Fatal(err)
	}
	if intentExists(dir) {
		t.Fatal("intent kept after handoff")
	}
	_, lockPath := kernelIntentPaths(dir, kernelIntentBase(testTunnel))
	l, err := tryLockKernelIntent(lockPath)
	if err != nil {
		t.Fatalf("lock not released after handoff: %v", err)
	}
	l.unlock()
	if err := h.releaseKernelLink(); err != nil || f.has(idxA) {
		t.Fatalf("release: err=%v present=%v", err, f.has(idxA))
	}
	if err := h.releaseKernelLink(); err != nil || len(f.deletes) != 1 {
		t.Fatalf("release is not idempotent: err=%v deletes=%v", err, f.deletes)
	}
}

func TestKernelLinkNameEEXISTLeavesForeignUntouched(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.add(kernelLink{Index: 9, Name: testIface, Kind: kernelLinkKind})
	useIndexSequence(t, idxA)
	_, err := createKernelLink(request(f, dir))
	if !errors.Is(err, errKernelInterfaceConflict) {
		t.Fatalf("err = %v, want conflict", err)
	}
	if len(f.creates) != 1 || len(f.deletes) != 0 || len(f.aliases) != 0 || !f.has(9) {
		t.Fatalf("name collision mutated devices or retried: %+v", f)
	}
	if intentExists(dir) {
		t.Fatal("intent kept after a definitive EEXIST")
	}
}

func TestKernelLinkIndexEEXISTRetriesWithRewrittenIntent(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	foreign := kernelLink{Index: idxA, Name: "eth9", Kind: "veth"}
	f.add(foreign)
	useIndexSequence(t, idxA, idxB)
	h, err := createKernelLink(request(f, dir))
	if err != nil {
		t.Fatal(err)
	}
	if h.kernelLinkIndex() != idxB {
		t.Fatalf("index = %d, want %d", h.kernelLinkIndex(), idxB)
	}
	if len(f.intentAtCall) != 2 || f.intentAtCall[0] != idxA || f.intentAtCall[1] != idxB {
		t.Fatalf("intent not rewritten before retry: %v", f.intentAtCall)
	}
	if f.links[idxA] != foreign || len(f.deletes) != 0 {
		t.Fatalf("foreign device at the colliding index was touched")
	}
	h.unlock()
}

func TestKernelLinkIndexEEXISTBounded(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.add(kernelLink{Index: idxA, Name: "eth9", Kind: "veth"})
	useIndexSequence(t, idxA)
	_, err := createKernelLink(request(f, dir))
	if err == nil {
		t.Fatal("expected exhaustion error")
	}
	if len(f.creates) != kernelLinkCreateTries || len(f.deletes) != 0 {
		t.Fatalf("creates=%v deletes=%v", f.creates, f.deletes)
	}
	if intentExists(dir) {
		t.Fatal("intent kept after exhaustion")
	}
}

func TestKernelLinkUnknownCreateOutcome(t *testing.T) {
	t.Run("link exists is deleted by index", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeLinkBackend()
		f.createAfter = errors.New("ack lost")
		useIndexSequence(t, idxA)
		if _, err := createKernelLink(request(f, dir)); err == nil {
			t.Fatal("expected error")
		}
		if f.has(idxA) || intentExists(dir) {
			t.Fatalf("orphan left: present=%v intent=%v", f.has(idxA), intentExists(dir))
		}
	})
	t.Run("inspection failure keeps intent", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeLinkBackend()
		f.createAfter = errors.New("ack lost")
		f.lookupErr = errors.New("netlink down")
		useIndexSequence(t, idxA)
		if _, err := createKernelLink(request(f, dir)); err == nil {
			t.Fatal("expected error")
		}
		if !intentExists(dir) || len(f.deletes) != 0 {
			t.Fatalf("intent=%v deletes=%v", intentExists(dir), f.deletes)
		}
		f.lookupErr = nil
		useFakeLinkBackend(t, f)
		recoverKernelLinkIntents(dir)
		if f.has(idxA) || intentExists(dir) {
			t.Fatal("retry did not resolve the orphan")
		}
	})
}

func TestKernelLinkAliasAndConfigureFailuresDeleteByIndex(t *testing.T) {
	for _, tc := range []string{"alias", "configure"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeLinkBackend()
			req := request(f, dir)
			if tc == "alias" {
				f.aliasErr = errors.New("setlink failed")
			} else {
				req.configure = func() error { return errors.New("wgctrl failed") }
			}
			useIndexSequence(t, idxA)
			if _, err := createKernelLink(req); err == nil {
				t.Fatal("expected error")
			}
			if f.has(idxA) || intentExists(dir) || len(f.deletes) != 1 || f.deletes[0] != idxA {
				t.Fatalf("present=%v intent=%v deletes=%v", f.has(idxA), intentExists(dir), f.deletes)
			}
		})
	}
}

func TestKernelLinkCleanupFailureKeepsIntentAndRetries(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.deleteErr = errors.New("EBUSY")
	req := request(f, dir)
	req.configure = func() error { return errors.New("wgctrl failed") }
	useIndexSequence(t, idxA)
	if _, err := createKernelLink(req); err == nil {
		t.Fatal("expected error")
	}
	if !intentExists(dir) || !f.has(idxA) {
		t.Fatal("intent must survive a failed cleanup")
	}
	f.deleteErr = nil
	useFakeLinkBackend(t, f)
	recoverKernelLinkIntents(dir)
	if intentExists(dir) || f.has(idxA) {
		t.Fatal("retry did not clean up")
	}
	recoverKernelLinkIntents(dir)
}

func TestKernelLinkPrepareResolvesOrphanBeforeAliasCheck(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.add(ours(idxA, kernelOwnershipAlias(testTunnel)))
	writeTestIntent(t, dir, idxA)
	req := request(f, dir)
	sawOrphan := false
	req.prepare = func() error {
		_, sawOrphan, _ = f.LinkByName(testIface)
		return nil
	}
	useIndexSequence(t, idxB)
	h, err := createKernelLink(req)
	if err != nil {
		t.Fatal(err)
	}
	defer h.unlock()
	if sawOrphan || f.has(idxA) || !f.has(idxB) {
		t.Fatalf("orphan not resolved before prepare: saw=%v", sawOrphan)
	}
}

func TestKernelLinkPrepareRefusesUnresolvedIntent(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.add(ours(idxA, "other-tool"))
	writeTestIntent(t, dir, idxA)
	if _, err := createKernelLink(request(f, dir)); !errors.Is(err, errKernelLinkNotOwned) {
		t.Fatalf("err = %v", err)
	}
	in, err := readKernelIntent(intentPath(dir))
	if err != nil || in.IfIndex != idxA || len(f.creates) != 0 {
		t.Fatalf("pending intent was overwritten: %+v %v creates=%v", in, err, f.creates)
	}
}

func TestKernelLinkLiveCreationIsNotStale(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	useFakeLinkBackend(t, f)
	useIndexSequence(t, idxA)
	h, err := createKernelLink(request(f, dir))
	if err != nil {
		t.Fatal(err)
	}
	recoverKernelLinkIntents(dir)
	if !f.has(idxA) || !intentExists(dir) {
		t.Fatal("recovery deleted a live creation")
	}
	if _, err := createKernelLink(request(f, dir)); !errors.Is(err, errKernelLinkBusy) {
		t.Fatalf("second creator err = %v, want busy", err)
	}
	if err := h.commitKernelLinkIntent(); err != nil {
		t.Fatal(err)
	}
}

func TestKernelLinkProcessCrashReleasesLock(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	useFakeLinkBackend(t, f)
	useIndexSequence(t, idxA)
	h, err := createKernelLink(request(f, dir))
	if err != nil {
		t.Fatal(err)
	}
	// Closing the descriptor models the kernel dropping the flock at exit.
	h.lock.f.Close()
	recoverKernelLinkIntents(dir)
	if f.has(idxA) || intentExists(dir) {
		t.Fatal("orphan after crash was not recovered")
	}
}

func TestKernelLinkReplacedByNameIsUntouched(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	useIndexSequence(t, idxA)
	h, err := createKernelLink(request(f, dir))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	delete(f.links, idxA)
	f.links[idxC] = ours(idxC, kernelOwnershipAlias(testTunnel))
	f.mu.Unlock()
	if err := h.releaseKernelLink(); err != nil {
		t.Fatal(err)
	}
	if !f.has(idxC) || len(f.deletes) != 0 {
		t.Fatalf("device that took the name was deleted: %v", f.deletes)
	}
	if intentExists(dir) {
		t.Fatal("intent kept although our index is gone")
	}
}

func TestKernelLinkWithoutDataDirHasNoJournal(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	useIndexSequence(t, idxA)
	req := request(f, "")
	h, err := createKernelLink(req)
	if err != nil {
		t.Fatal(err)
	}
	if h.lock != nil || h.intentHeld || f.intentAtCall != nil {
		t.Fatal("standalone creation wrote a journal")
	}
	if _, err := os.Stat(filepath.Join(dir, kernelLinkIntentsDir)); !os.IsNotExist(err) {
		t.Fatal("unexpected intent dir")
	}
	if err := h.releaseKernelLink(); err != nil || f.has(idxA) {
		t.Fatal("release failed")
	}
}

func TestKernelLinkCorruptIntentQuarantined(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	useFakeLinkBackend(t, f)
	p := intentPath(dir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	recoverKernelLinkIntents(dir)
	if intentExists(dir) {
		t.Fatal("corrupt intent still enumerated")
	}
	if _, err := os.Stat(p + ".corrupt"); err != nil {
		t.Fatal("corrupt intent not preserved")
	}
	if f.mutations() != 0 {
		t.Fatal("corrupt intent caused mutation")
	}
}

type guardRecoveryMock struct {
	mockNetworkManager
	guard       network.LinkCleanupGuard
	dataDir     string
	nameDeletes []string
	cleanups    int
	removes     int
	resets      int
}

func (g *guardRecoveryMock) SetLinkCleanupGuard(guard network.LinkCleanupGuard) { g.guard = guard }
func (g *guardRecoveryMock) SetPersistentStateDir(dir string)                   { g.dataDir = dir }
func (g *guardRecoveryMock) ResetDNSToSystemDefault() error                     { g.resets++; return nil }
func (g *guardRecoveryMock) RemoveRoutes(string, []string, bool) error          { g.removes++; return nil }
func (g *guardRecoveryMock) Cleanup(iface string) error {
	g.cleanups++
	if g.guard != nil {
		if handled, err := g.guard(g.dataDir, iface); handled {
			return err
		}
	}
	g.nameDeletes = append(g.nameDeletes, iface)
	return nil
}

func useGuardRecoveryMock(t *testing.T) (*guardRecoveryMock, *int) {
	t.Helper()
	mock := &guardRecoveryMock{}
	created := 0
	old := newRecoveryManager
	newRecoveryManager = func() network.NetworkManager { created++; return mock }
	t.Cleanup(func() { newRecoveryManager = old })
	return mock, &created
}

func TestRecoverFromCrashIntentOnlyTouchesNothingElse(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.add(ours(idxA, ""))
	useFakeLinkBackend(t, f)
	_, created := useGuardRecoveryMock(t)
	writeTestIntent(t, dir, idxA)
	fw := &fakeFirewall{}

	if got := RecoverFromCrash(dir, fw); len(got) != 0 {
		t.Fatalf("intent-only recovery reported tunnels %v", got)
	}
	if fw.cleanupCalled != 0 || *created != 0 {
		t.Fatalf("intent-only recovery mutated firewall/network: fw=%d managers=%d", fw.cleanupCalled, *created)
	}
	if f.has(idxA) || intentExists(dir) {
		t.Fatal("intent-only orphan not removed")
	}
}

func TestRecoverFromCrashActiveStateUsesIndex(t *testing.T) {
	tests := []struct {
		name          string
		link          *kernelLink
		withIntent    bool
		wantGone      bool
		wantNameCalls int
	}{
		{name: "C4 state and intent", link: &kernelLink{Index: idxA, Name: testIface, Kind: kernelLinkKind, Alias: kernelOwnershipAlias(testTunnel)}, withIntent: true, wantGone: true},
		{name: "C5 state only", link: &kernelLink{Index: idxA, Name: testIface, Kind: kernelLinkKind, Alias: kernelOwnershipAlias(testTunnel)}, wantGone: true},
		{name: "C5 already gone", wantGone: true},
		{name: "C5 empty alias is not ours after handoff", link: &kernelLink{Index: idxA, Name: testIface, Kind: kernelLinkKind}},
		{name: "C5 foreign at index", link: &kernelLink{Index: idxA, Name: "eth3", Kind: "veth"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeLinkBackend()
			if tc.link != nil {
				f.add(*tc.link)
			}
			replacement := kernelLink{Index: 77, Name: testIface, Kind: kernelLinkKind, Alias: kernelOwnershipAlias(testTunnel)}
			f.add(replacement)
			useFakeLinkBackend(t, f)
			mock, _ := useGuardRecoveryMock(t)
			if tc.withIntent {
				writeTestIntent(t, dir, idxA)
			}
			if err := SaveActiveState(dir, &ActiveTunnelState{TunnelName: testTunnel, InterfaceName: testIface, KernelIfindex: idxA}); err != nil {
				t.Fatal(err)
			}
			fw := &fakeFirewall{}
			RecoverFromCrash(dir, fw)

			if gone := !f.has(idxA); gone != tc.wantGone {
				t.Fatalf("gone=%v want %v", gone, tc.wantGone)
			}
			if !f.has(77) {
				t.Fatal("same-name device at another index was deleted")
			}
			if len(mock.nameDeletes) != 0 {
				t.Fatalf("kernel journal fell back to name deletion: %v", mock.nameDeletes)
			}
			for _, d := range f.deletes {
				if d != idxA {
					t.Fatalf("deleted unrelated index %d", d)
				}
			}
			if fw.cleanupCalled != 1 {
				t.Fatalf("completed-state recovery must keep firewall cleanup: %d", fw.cleanupCalled)
			}
			if intentExists(dir) {
				t.Fatal("intent left after C4 recovery")
			}
			if len(LoadActiveState(dir)) != 0 {
				t.Fatal("state kept after recovery")
			}
		})
	}
}

func TestRecoverFromCrashKernelDeleteFailureKeepsJournal(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	f.add(ours(idxA, kernelOwnershipAlias(testTunnel)))
	f.deleteErr = errors.New("EBUSY")
	useFakeLinkBackend(t, f)
	mock, _ := useGuardRecoveryMock(t)
	if err := SaveActiveState(dir, &ActiveTunnelState{TunnelName: testTunnel, InterfaceName: testIface, KernelIfindex: idxA}); err != nil {
		t.Fatal(err)
	}
	RecoverFromCrash(dir, nil)
	if len(LoadActiveState(dir)) != 1 || len(mock.nameDeletes) != 0 {
		t.Fatal("failed index deletion must keep the journal and never delete by name")
	}
	f.deleteErr = nil
	handled, err := kernelRecoveryLinkGuard(dir, testIface)
	if !handled || err != nil || f.has(idxA) {
		t.Fatalf("adoption retry guard: handled=%v err=%v", handled, err)
	}
}

func TestRecoverFromCrashLegacyJournalKeepsNameCleanup(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	calls := useFakeLinkBackend(t, f)
	mock, _ := useGuardRecoveryMock(t)
	legacy := `{"tunnel_name":"home","interface_name":"wg-test0","dns_servers_original":null,"full_tunnel":false}`
	sdir := filepath.Join(dir, tunnelStatesDir)
	if err := os.MkdirAll(sdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdir, stateFileName("home")), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	st := LoadActiveState(dir)
	if len(st) != 1 || st[0].KernelIfindex != 0 {
		t.Fatalf("legacy decode: %+v", st)
	}
	RecoverFromCrash(dir, nil)
	if len(mock.nameDeletes) != 1 || mock.nameDeletes[0] != testIface || *calls != 0 {
		t.Fatalf("legacy journal: nameDeletes=%v netlink=%d", mock.nameDeletes, *calls)
	}
}

func TestActiveStateKernelIfindexRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveState(dir, &ActiveTunnelState{TunnelName: "a", InterfaceName: "wg-a", KernelIfindex: idxB}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, tunnelStatesDir, stateFileName("a")))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil || raw["kernel_ifindex"] != float64(idxB) {
		t.Fatalf("kernel_ifindex not persisted: %s", data)
	}
	if st := LoadActiveState(dir); len(st) != 1 || st[0].KernelIfindex != idxB {
		t.Fatalf("decode: %+v", st)
	}
	if err := SaveActiveState(dir, &ActiveTunnelState{TunnelName: "b", InterfaceName: "utun3"}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, tunnelStatesDir, stateFileName("b")))
	raw = nil
	_ = json.Unmarshal(data, &raw)
	if _, ok := raw["kernel_ifindex"]; ok {
		t.Fatal("userspace journal gained kernel_ifindex")
	}
}

// fakeOwnedKernel is a kernelBackend backed by a real kernelLinkHandle.
type fakeOwnedKernel struct{ *kernelLinkHandle }

func (fakeOwnedKernel) Start() error   { return nil }
func (k fakeOwnedKernel) Close() error { return k.releaseKernelLink() }
func (fakeOwnedKernel) Status(string, time.Time) (*ConnectionStatus, error) {
	return nil, errors.New("n/a")
}
func (fakeOwnedKernel) CurrentEndpointIPs() ([]string, error) { return nil, nil }

type stateProbeNetMgr struct {
	mockNetworkManager
	dataDir     string
	guard       network.LinkCleanupGuard
	seen        []int32
	addRoutes   error
	nameDeletes int
	intentSeen  []bool
}

func (s *stateProbeNetMgr) probe() {
	data, err := os.ReadFile(filepath.Join(s.dataDir, tunnelStatesDir, stateFileName(testTunnel)))
	if err != nil {
		s.seen = append(s.seen, -1)
		return
	}
	var st ActiveTunnelState
	_ = json.Unmarshal(data, &st)
	s.seen = append(s.seen, st.KernelIfindex)
	s.intentSeen = append(s.intentSeen, intentExists(s.dataDir))
}

func (s *stateProbeNetMgr) SetLinkCleanupGuard(g network.LinkCleanupGuard) { s.guard = g }
func (s *stateProbeNetMgr) SetMTU(string, int) error                       { s.probe(); return nil }
func (s *stateProbeNetMgr) SetDNS(string, []string) error                  { s.probe(); return nil }
func (s *stateProbeNetMgr) AddRoutes(string, []string, bool, []string, string, string) error {
	s.probe()
	return s.addRoutes
}
func (s *stateProbeNetMgr) Cleanup(iface string) error {
	if s.guard != nil {
		if handled, err := s.guard(s.dataDir, iface); handled {
			return err
		}
	}
	s.nameDeletes++
	return nil
}

func kernelTestManager(t *testing.T, dir string, f *fakeLinkBackend, nm *stateProbeNetMgr) *Manager {
	t.Helper()
	useIndexSequence(t, idxA)
	factory := func(cfg *domain.WireGuardConfig) (*Engine, error) {
		h, err := createKernelLink(request(f, dir))
		if err != nil {
			return nil, err
		}
		return &Engine{kernel: fakeOwnedKernel{h}, ifaceName: testIface}, nil
	}
	nm.dataDir = dir
	return &Manager{
		dataDir:       dir,
		tunnels:       make(map[string]*tunnelEntry),
		netMgrFactory: func() network.NetworkManager { return nm },
		engineFactory: factory,
	}
}

func kernelTestConfig() *domain.WireGuardConfig {
	cfg := testConfig(testTunnel)
	cfg.Interface.DNS = []string{"10.0.0.53"}
	return cfg
}

func TestConnectPersistsKernelIfindexInEveryState(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	nm := &stateProbeNetMgr{}
	m := kernelTestManager(t, dir, f, nm)
	if err := m.Connect(kernelTestConfig()); err != nil {
		t.Fatal(err)
	}
	if len(nm.seen) < 3 {
		t.Fatalf("probes = %v", nm.seen)
	}
	for i, v := range nm.seen {
		if v != idxA {
			t.Fatalf("state write %d had kernel_ifindex %d", i, v)
		}
		if nm.intentSeen[i] {
			t.Fatalf("intent survived handoff at probe %d", i)
		}
	}
	st := LoadActiveState(dir)
	if len(st) != 1 || st[0].KernelIfindex != idxA {
		t.Fatalf("final state: %+v", st)
	}
	if err := m.DisconnectTunnel(testTunnel); err != nil {
		t.Fatal(err)
	}
	if f.has(idxA) || nm.nameDeletes != 0 {
		t.Fatalf("disconnect: present=%v nameDeletes=%d", f.has(idxA), nm.nameDeletes)
	}
}

func TestConnectRollbackDeletesKernelLinkByIndex(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	nm := &stateProbeNetMgr{addRoutes: errors.New("route failure")}
	m := kernelTestManager(t, dir, f, nm)
	if err := m.Connect(kernelTestConfig()); err == nil {
		t.Fatal("expected failure")
	}
	if f.has(idxA) || nm.nameDeletes != 0 || len(f.deletes) != 1 {
		t.Fatalf("rollback: present=%v nameDeletes=%d deletes=%v", f.has(idxA), nm.nameDeletes, f.deletes)
	}
	if intentExists(dir) {
		t.Fatal("intent left after rollback")
	}
}

func TestConnectPreSaveFailureKeepsIntentWhenCleanupFails(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	nm := &stateProbeNetMgr{}
	m := kernelTestManager(t, dir, f, nm)
	sdir := filepath.Join(dir, tunnelStatesDir)
	if err := os.WriteFile(sdir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.deleteErr = errors.New("EBUSY")
	if err := m.Connect(kernelTestConfig()); err == nil {
		t.Fatal("expected save failure")
	}
	if !intentExists(dir) || !f.has(idxA) {
		t.Fatal("C3 failure before handoff must keep the intent when deletion fails")
	}
	f.deleteErr = nil
	useFakeLinkBackend(t, f)
	recoverKernelLinkIntents(dir)
	if intentExists(dir) || f.has(idxA) {
		t.Fatal("intent recovery did not finish the cleanup")
	}
}

func TestKernelLinkEEXISTNeverDeletesLookalikeAtChosenIndex(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	lookalike := ours(idxA, "")
	f.add(lookalike)
	useIndexSequence(t, idxA)
	if _, err := createKernelLink(request(f, dir)); !errors.Is(err, errKernelInterfaceConflict) {
		t.Fatalf("err = %v", err)
	}
	if len(f.deletes) != 0 || f.links[idxA] != lookalike || intentExists(dir) {
		t.Fatalf("definitive EEXIST mutated a device: deletes=%v intent=%v", f.deletes, intentExists(dir))
	}
}

func TestMultiTunnelDeleteFailureKeepsKernelRecoveryJournal(t *testing.T) {
	dir := t.TempDir()
	f := newFakeLinkBackend()
	nm := &stateProbeNetMgr{}
	m := kernelTestManager(t, dir, f, nm)
	if err := m.Connect(kernelTestConfig()); err != nil {
		t.Fatal(err)
	}
	other := testConfig("other")
	other.Interface.DNS = []string{"10.0.0.54"}
	m.mu.Lock()
	m.tunnels["other"] = &tunnelEntry{cfg: other, state: domain.StateConnected}
	m.mu.Unlock()
	f.deleteErr = errors.New("temporary DELLINK failure")
	if err := m.DisconnectTunnel(testTunnel); err != nil {
		t.Fatal(err)
	}
	states := LoadActiveState(dir)
	if !f.has(idxA) || len(states) != 1 || states[0].KernelIfindex != idxA || len(m.pendingNetworkCleanup) != 1 {
		t.Fatalf("lost failed deletion recovery: present=%v states=%+v pending=%d", f.has(idxA), states, len(m.pendingNetworkCleanup))
	}
	m.mu.Lock()
	delete(m.tunnels, "other")
	m.mu.Unlock()
	f.deleteErr = nil
	m.RetryPendingDNSCleanupAt(time.Now().Add(2 * time.Second))
	if f.has(idxA) || len(LoadActiveState(dir)) != 0 || len(m.pendingNetworkCleanup) != 0 || nm.nameDeletes != 0 {
		t.Fatalf("guarded retry failed: link=%v states=%+v pending=%d names=%d", f.has(idxA), LoadActiveState(dir), len(m.pendingNetworkCleanup), nm.nameDeletes)
	}
}
