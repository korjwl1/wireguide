//go:build !windows

package tunnel

import (
	"path/filepath"
	"testing"
)

func TestRecoveryGuardKeepsOnlyItsOriginalIndexAuthority(t *testing.T) {
	dir := t.TempDir()
	backend := newFakeLinkBackend()
	useFakeLinkBackend(t, backend)
	original := ActiveTunnelState{TunnelName: testTunnel, InterfaceName: testIface, KernelIfindex: idxA}
	mgr := &guardRecoveryMock{dataDir: dir}
	installKernelLinkGuard(mgr, &original)
	original.KernelIfindex = idxB
	backend.add(ours(idxB, kernelOwnershipAlias(testTunnel)))
	if err := SaveActiveState(dir, &original); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Cleanup(testIface); err != nil {
		t.Fatal(err)
	}
	if !backend.has(idxB) || len(backend.deletes) != 0 || len(mgr.nameDeletes) != 0 {
		t.Fatalf("old guard followed a new journal/link: deleted=%v names=%v", backend.deletes, mgr.nameDeletes)
	}
	if err := mgr.Cleanup("unrelated0"); err == nil || len(mgr.nameDeletes) != 0 {
		t.Fatalf("wrong interface fell through to name deletion: %v %v", err, mgr.nameDeletes)
	}
}

func TestForeignIntentIsQuarantinedWithoutBlockingFreshCreation(t *testing.T) {
	dir := t.TempDir()
	backend := newFakeLinkBackend()
	foreign := kernelLink{Index: idxA, Name: "foreign0", Kind: "veth", Alias: "other-tool"}
	backend.add(foreign)
	writeTestIntent(t, dir, idxA)
	useIndexSequence(t, idxB)
	handle, err := createKernelLink(request(backend, dir))
	if err != nil {
		t.Fatal(err)
	}
	if backend.links[idxA] != foreign || len(backend.deletes) != 0 || handle.kernelLinkIndex() != idxB {
		t.Fatalf("foreign link touched or retry blocked: %+v", backend)
	}
	preserved, err := filepath.Glob(intentPath(dir) + ".foreign-*")
	if err != nil || len(preserved) != 1 {
		t.Fatalf("retired intent not preserved: %v %v", preserved, err)
	}
	if err := handle.releaseKernelLink(); err != nil {
		t.Fatal(err)
	}
	if backend.links[idxA] != foreign {
		t.Fatal("foreign link deleted on final cleanup")
	}
}
