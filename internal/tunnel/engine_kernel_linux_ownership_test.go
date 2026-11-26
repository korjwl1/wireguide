//go:build linux

package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
)

// installFakeIP puts a shell script named `ip` at the front of PATH. The
// script serves links as `ip -j -d link show` output, records every
// invocation, and fails `ip link add` when addExit is non-zero.
func installFakeIP(t *testing.T, links string, addExit int) string {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	linksPath := filepath.Join(dir, "links.json")
	if err := os.WriteFile(linksPath, []byte(links), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "ip")
	body := `#!/bin/sh
printf '%s\n' "$*" >> "$WIREGUIDE_TEST_IP_CALLS"
case "$1 $2" in
"-j -d")
	cat "$WIREGUIDE_TEST_IP_LINKS"
	;;
"link add")
	exit "${WIREGUIDE_TEST_IP_ADD_EXIT:-0}"
	;;
esac
exit 0
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WIREGUIDE_TEST_IP_CALLS", calls)
	t.Setenv("WIREGUIDE_TEST_IP_LINKS", linksPath)
	t.Setenv("WIREGUIDE_TEST_IP_ADD_EXIT", strconv.Itoa(addExit))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return calls
}

func linkJSON(ifname, alias, kind string) string {
	return `[{"ifname":"` + ifname + `","ifalias":"` + alias + `","linkinfo":{"info_kind":"` + kind + `"}}]`
}

func TestPrepareKernelInterface(t *testing.T) {
	const (
		iface  = "wg-test"
		tunnel = "home"
	)

	tests := []struct {
		name       string
		links      string
		wantErr    error
		wantHint   string
		wantDelete bool
	}{
		{
			name:  "absent interface needs no cleanup",
			links: "[]",
		},
		{
			name:    "matching marker does not prove a stale interface",
			links:   linkJSON(iface, kernelOwnershipAliasPrefix+tunnel, "wireguard"),
			wantErr: errKernelInterfaceConflict,
		},
		{
			name:     "markerless wireguard link names the manual cleanup",
			links:    linkJSON(iface, "", "wireguard"),
			wantErr:  errKernelInterfaceConflict,
			wantHint: "ip link delete dev " + iface,
		},
		{
			name:    "unrelated alias is a conflict",
			links:   linkJSON(iface, "other-tool", "wireguard"),
			wantErr: errKernelInterfaceConflict,
		},
		{
			name:    "non-wireguard link is a conflict",
			links:   linkJSON(iface, kernelOwnershipAliasPrefix+tunnel, "veth"),
			wantErr: errKernelInterfaceConflict,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := installFakeIP(t, tc.links, 0)

			err := prepareKernelInterface(iface, tunnel)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("prepareKernelInterface: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("prepareKernelInterface error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantHint != "" && (err == nil || !strings.Contains(err.Error(), tc.wantHint)) {
				t.Fatalf("prepareKernelInterface error = %v, want it to mention %q", err, tc.wantHint)
			}

			log, err := os.ReadFile(calls)
			if err != nil {
				t.Fatalf("reading fake ip log: %v", err)
			}
			deleted := strings.Contains(string(log), "link delete dev "+iface)
			if deleted != tc.wantDelete {
				t.Fatalf("delete called = %v, want %v (calls: %q)", deleted, tc.wantDelete, log)
			}
		})
	}
}

func TestNewKernelEnginePreservesExistingInterface(t *testing.T) {
	const tunnel = "home"
	name := platformTUNName("linux", tunnel)
	calls := installFakeIP(t, linkJSON(name, kernelOwnershipAliasPrefix+tunnel, "wireguard"), 1)

	cfg := &config.WireGuardConfig{Name: tunnel}
	if _, err := newKernelEngine(cfg, cfg, nil, nil); err == nil {
		t.Fatal("newKernelEngine succeeded, want a creation error")
	}

	log, err := os.ReadFile(calls)
	if err != nil {
		t.Fatalf("reading fake ip log: %v", err)
	}
	callsText := string(log)
	if strings.Contains(callsText, "link delete") || strings.Contains(callsText, "link add") {
		t.Fatalf("existing interface must not be deleted or replaced: %q", callsText)
	}
}
