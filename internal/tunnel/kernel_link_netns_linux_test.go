//go:build linux

package tunnel

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestNetlinkKernelLinkBackendInNetns exercises the real rtnetlink backend.
// It never runs by default. Run it only inside a throwaway namespace, e.g.
//
//	WIREGUIDE_NETNS_TEST=1 unshare -rn go test -run NetlinkKernelLinkBackendInNetns ./internal/tunnel
//
// It additionally refuses to run unless the namespace contains only "lo".
func TestNetlinkKernelLinkBackendInNetns(t *testing.T) {
	if os.Getenv("WIREGUIDE_NETNS_TEST") != "1" {
		t.Skip("set WIREGUIDE_NETNS_TEST=1 and run under unshare -rn")
	}
	dev, err := os.ReadFile("/proc/self/net/dev")
	if err != nil {
		t.Skipf("cannot inspect namespace: %v", err)
	}
	var ifaces []string
	for _, line := range strings.Split(string(dev), "\n")[2:] {
		if name, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			ifaces = append(ifaces, name)
		}
	}
	if len(ifaces) != 1 || ifaces[0] != "lo" {
		t.Skipf("refusing to run outside an empty network namespace: %v", ifaces)
	}

	b, _ := defaultKernelLinkBackend()
	const name = "wgtest0"
	index := randomKernelLinkIndex()
	if err := b.CreateWireGuard(name, index); err != nil {
		t.Skipf("wireguard link creation unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = b.DeleteIndex(index) })

	link, found, err := b.LinkByIndex(index)
	if err != nil || !found || link.Name != name || link.Kind != kernelLinkKind || link.Alias != "" {
		t.Fatalf("LinkByIndex = %+v %v %v", link, found, err)
	}
	if err := b.CreateWireGuard(name, randomKernelLinkIndex()); !errors.Is(err, errKernelLinkExists) {
		t.Fatalf("name collision err = %v", err)
	}
	if err := b.CreateWireGuard("wgtest1", index); !errors.Is(err, errKernelLinkExists) {
		t.Fatalf("index collision err = %v", err)
	}
	if err := b.SetAlias(index, kernelOwnershipAlias("netns")); err != nil {
		t.Fatal(err)
	}
	if link, _, _ = b.LinkByName(name); link.Index != index || link.Alias != kernelOwnershipAlias("netns") {
		t.Fatalf("LinkByName = %+v", link)
	}
	if err := deleteOwnedKernelLink(b, index, name, kernelOwnershipAlias("other"), false); !errors.Is(err, errKernelLinkNotOwned) {
		t.Fatalf("foreign-alias delete err = %v", err)
	}
	if err := deleteOwnedKernelLink(b, index, name, kernelOwnershipAlias("netns"), false); err != nil {
		t.Fatal(err)
	}
	if _, found, err := b.LinkByIndex(index); found || err != nil {
		t.Fatalf("link still present: %v %v", found, err)
	}
	if err := b.DeleteIndex(index); !errors.Is(err, errKernelLinkNotFound) {
		t.Fatalf("second delete err = %v", err)
	}
}
