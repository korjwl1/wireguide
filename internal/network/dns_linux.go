//go:build linux

package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/domain"
)

func (m *LinuxManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}

	// Split DNS ("~domain" tokens) is resolved-only: the other backends can
	// only express a global resolver, so they must never be used for it.
	if parsed := domain.ParseDNSEntries(servers); len(parsed.Match) > 0 {
		return setSplitDNSResolvectl(ifaceName, parsed)
	}

	// Separate DNS IPs from search domains (H9)
	var dnsIPs, searchDomains []string
	for _, s := range servers {
		if net.ParseIP(s) != nil {
			dnsIPs = append(dnsIPs, s)
			continue
		}
		// Non-IP entries are search domains. Validate before use: these
		// strings are written verbatim into resolv.conf / resolvconf
		// stdin, so an entry containing a newline (e.g.
		// "foo\nnameserver 6.6.6.6") would inject a rogue nameserver.
		if !isValidSearchDomain(s) {
			slog.Warn("skipping invalid DNS search domain", "value", s)
			continue
		}
		searchDomains = append(searchDomains, s)
	}

	// Try systemd-resolved first
	if tryResolvectl(ifaceName, dnsIPs, searchDomains) {
		return nil
	}

	// H9: Fallback to resolvconf if available
	if tryResolvconf(ifaceName, dnsIPs, searchDomains) {
		return nil
	}

	// Final fallback: rewrite /etc/resolv.conf directly. NEVER use `sh -c "echo ..."`
	// here -- server strings are attacker-influenced and would allow shell
	// injection. Use os.WriteFile with atomic rename.

	// M7: Check if /etc/resolv.conf is a symlink. If so, refuse to overwrite
	// and warn the user.
	if isSymlink("/etc/resolv.conf") {
		slog.Warn("/etc/resolv.conf is a symlink, refusing to overwrite directly; DNS may not work as expected. Install resolvconf or systemd-resolved.")
		return fmt.Errorf("/etc/resolv.conf is a symlink; install resolvectl or resolvconf for DNS management")
	}

	// Capture the original resolv.conf only once. A second SetDNS without
	// an intervening RestoreDNS (reconnect, network-change re-apply) would
	// otherwise save WireGuide's own nameservers as the "original".
	if !m.origDNSCaptured {
		// Every adapter shares the first session's durable baseline.
		if m.dataDir != "" {
			data, err := os.ReadFile(filepath.Join(m.dataDir, dnsStateFile))
			if err == nil {
				if err := json.Unmarshal(data, &m.origDNS); err != nil {
					return fmt.Errorf("reading original DNS journal: %w", err)
				}
				m.origDNSCaptured = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if !m.origDNSCaptured {
			origData, err := os.ReadFile("/etc/resolv.conf")
			if err != nil {
				return fmt.Errorf("capturing original DNS: %w", err)
			}
			m.origDNS = strings.Split(strings.TrimSuffix(string(origData), "\n"), "\n")
			if err := m.persistOrigDNS(); err != nil {
				return err
			}
			m.origDNSCaptured = true
		}
	}

	var lines []string
	for _, s := range dnsIPs {
		lines = append(lines, "nameserver "+s)
	}
	// H9: Include search domains
	if len(searchDomains) > 0 {
		lines = append(lines, "search "+strings.Join(searchDomains, " "))
	}
	content := strings.Join(lines, "\n") + "\n"
	return writeResolvConf(content)
}

// setSplitDNSResolvectl configures split DNS via systemd-resolved only. A
// missing resolvectl or a failed dns/domain command yields
// ErrSplitDNSUnsupported; resolvconf and resolv.conf rewriting are global
// and never used here.
func setSplitDNSResolvectl(ifaceName string, p domain.DNSEntries) error {
	if len(p.Servers) == 0 {
		return fmt.Errorf("split DNS requires at least one DNS server address")
	}
	for _, d := range append(append([]string(nil), p.Match...), p.Search...) {
		if !isValidSearchDomain(d) {
			return fmt.Errorf("invalid split DNS domain %q", d)
		}
	}
	cmds := resolvectlSplitCommands(ifaceName, p)
	for i, args := range cmds {
		if err := splitDNSRunCmd("resolvectl", args...); err != nil {
			if i > 0 {
				// dns succeeded but a later step failed: a link with servers
				// and no routing domain becomes a default-route resolver,
				// i.e. a global override. Undo it (best effort).
				if rerr := splitDNSRunCmd("resolvectl", "revert", ifaceName); rerr != nil {
					slog.Warn("resolvectl revert after partial split DNS failed", "iface", ifaceName, "error", rerr)
				}
			}
			if errors.Is(err, exec.ErrNotFound) {
				return fmt.Errorf("%w: resolvectl unavailable", ErrSplitDNSUnsupported)
			}
			return fmt.Errorf("configuring split DNS with resolvectl: %w", err)
		}
	}
	return nil
}

// tryResolvectl attempts to set DNS via systemd-resolved. Returns true on success.
func tryResolvectl(ifaceName string, dnsIPs, searchDomains []string) bool {
	if len(dnsIPs) == 0 {
		return false
	}
	args := []string{"dns", ifaceName}
	args = append(args, dnsIPs...)
	if err := runCmd("resolvectl", args...); err != nil {
		return false
	}
	// Set catch-all routing domain so systemd-resolved actually sends
	// queries to our DNS servers.
	domains := []string{"~."}
	domains = append(domains, searchDomains...)
	_ = runCmd("resolvectl", append([]string{"domain", ifaceName}, domains...)...)
	return true
}

// resolvconfIfacePrefix returns the interface prefix from /etc/resolvconf/interface-order,
// matching wg-quick's resolvconf_iface_prefix(). This controls DNS priority ordering
// on Debian/Ubuntu systems with openresolv. Returns empty string if not applicable.
func resolvconfIfacePrefix() string {
	path, err := exec.LookPath("resolvconf")
	if err != nil || path == "" {
		return ""
	}
	// Only apply prefix for real openresolv, not systemd-resolved's shim (a symlink).
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	data, err := os.ReadFile("/etc/resolvconf/interface-order")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "*") {
			prefix := strings.TrimSuffix(line, "*")
			if len(prefix) > 0 {
				return prefix + "."
			}
		}
	}
	return ""
}

// tryResolvconf attempts to set DNS via the resolvconf utility (H9).
// Returns true on success.
func tryResolvconf(ifaceName string, dnsIPs, searchDomains []string) bool {
	path, err := exec.LookPath("resolvconf")
	if err != nil || path == "" {
		return false
	}

	var input strings.Builder
	for _, ip := range dnsIPs {
		fmt.Fprintf(&input, "nameserver %s\n", ip)
	}
	if len(searchDomains) > 0 {
		fmt.Fprintf(&input, "search %s\n", strings.Join(searchDomains, " "))
	}

	prefixedName := resolvconfIfacePrefix() + ifaceName
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "resolvconf", "-a", prefixedName, "-m", "0", "-x")
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Warn("resolvconf failed", "error", err, "output", strings.TrimSpace(string(out)))
		return false
	}
	return true
}

// isSymlink returns true if the given path is a symbolic link (M7).
func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

// persistOrigDNS saves original DNS state to disk (M8).
func (m *LinuxManager) persistOrigDNS() error {
	if m.dataDir == "" {
		return nil
	}
	data, err := json.Marshal(m.origDNS)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(m.dataDir, dnsStateFile), data, 0600)
}

// loadPersistedDNS reads original DNS state from disk (M8).
func (m *LinuxManager) loadPersistedDNS() ([]string, error) {
	if m.dataDir == "" {
		return nil, nil
	}
	path := filepath.Join(m.dataDir, dnsStateFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var dns []string
	if err := json.Unmarshal(data, &dns); err != nil {
		return nil, fmt.Errorf("reading original DNS journal: %w", err)
	}
	return dns, nil
}

// clearPersistedDNS removes the persisted DNS state file.
func (m *LinuxManager) clearPersistedDNS() error {
	if m.dataDir == "" {
		return nil
	}
	path := filepath.Join(m.dataDir, dnsStateFile)
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ResetDNSToSystemDefault clears DNS overrides without relying on in-memory
// state. Used by crash recovery. On Linux with systemd-resolved this reverts
// the interface; on the resolv.conf fallback path it restores from persisted
// state (M8).
func (m *LinuxManager) ResetDNSToSystemDefault() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var failures []error
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "wg") || strings.HasPrefix(iface.Name, "utun") {
			if err := m.RemoveInterfaceDNS(iface.Name); err != nil {
				failures = append(failures, err)
			}
		}
	}
	persisted, readErr := m.loadPersistedDNS()
	if readErr != nil {
		failures = append(failures, readErr)
	}
	if len(persisted) > 0 {
		if isSymlink("/etc/resolv.conf") {
			failures = append(failures, errors.New("resolv.conf changed to a symlink; original DNS retained for recovery"))
		} else if err := writeResolvConf(strings.Join(persisted, "\n") + "\n"); err != nil {
			failures = append(failures, err)
		} else if err := m.clearPersistedDNS(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (m *LinuxManager) RestoreDNS(ifaceName string) error {
	if err := m.RemoveInterfaceDNS(ifaceName); err != nil {
		return err
	}

	// Restore from in-memory state
	if len(m.origDNS) == 0 {
		// M8: Try loading from persisted state
		var err error
		m.origDNS, err = m.loadPersistedDNS()
		if err != nil {
			return err
		}
	}
	if len(m.origDNS) == 0 {
		return nil
	}
	content := strings.Join(m.origDNS, "\n") + "\n"
	if isSymlink("/etc/resolv.conf") {
		return errors.New("resolv.conf changed to a symlink; original DNS retained for recovery")
	}
	if err := writeResolvConf(content); err != nil {
		return err
	}
	if err := m.clearPersistedDNS(); err != nil {
		return err
	}
	// Allow the next SetDNS to capture a fresh original snapshot.
	m.origDNS = nil
	m.origDNSCaptured = false
	return nil
}

func isValidSearchDomain(s string) bool {
	return len(s) <= 253 && searchDomainRegex.MatchString(s)
}

// writeResolvConf publishes through a private temporary file in /etc.
func writeResolvConf(content string) error {
	return atomicfile.WriteFile("/etc/resolv.conf", []byte(content), 0644)
}

// RemoveInterfaceDNS withdraws resolvconf's per-link contribution even while
// sibling tunnels keep their global DNS policy.
func (m *LinuxManager) RemoveInterfaceDNS(ifaceName string) error {
	var failures []error
	if path, err := exec.LookPath("resolvconf"); err == nil && path != "" {
		if err := runCmd("resolvconf", "-d", resolvconfIfacePrefix()+ifaceName, "-f"); err != nil {
			failures = append(failures, err)
		}
	}
	// The kernel may already have deleted the interface. resolved drops its
	// link state in that case; a missing-link revert needs no recovery.
	if _, err := net.InterfaceByName(ifaceName); err == nil {
		if path, err := exec.LookPath("resolvectl"); err == nil && path != "" {
			if err := runCmd("resolvectl", "revert", ifaceName); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}
