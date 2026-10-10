//go:build darwin

package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/korjwl1/wireguide/internal/domain"
)

// splitDNSKeyPrefix is the dynamic-store namespace owned by this app. The
// stale-key sweep only ever removes keys under it.
const splitDNSKeyPrefix = "State:/Network/Service/com.wireguide."

const (
	splitKindMatch  = "match"  // "~name" domains: routing only (NoSearch 1)
	splitKindSearch = "search" // plain names in split mode: match + search (NoSearch 0)

	// maxSplitDNSDomainLen is the DNS name length limit.
	maxSplitDNSDomainLen = 253

	// maxScutilLine bounds one stdin line. scutil reads with a 2048-byte
	// buffer and silently drops the rest of a longer line, which would
	// install a truncated (and so wrong) server or domain list.
	maxScutilLine = 2000
)

var (
	// utunIfaceRegex is the only interface shape split DNS keys are built
	// from. Configs arrive over IPC, so the name is re-validated here.
	utunIfaceRegex = regexp.MustCompile(`^utun[0-9]+$`)

	// staleSplitKeyRegex matches one line of `scutil list` output and
	// captures a key under our prefix.
	// showEntryRegex matches one array element of `scutil show` output.
	showEntryRegex = regexp.MustCompile(`^\s*\d+\s*:\s*(\S+)\s*$`)

	staleSplitKeyRegex = regexp.MustCompile(`=\s*(State:/Network/Service/com\.wireguide\.[A-Za-z0-9._-]+/DNS)\s*$`)
)

// scutilExec feeds a script to /usr/sbin/scutil on stdin and returns its
// stdout. It is a var so tests never touch the real dynamic store. scutil
// exits 0 even when a command fails, so callers must inspect the output.
var scutilExec = func(script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/scutil")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("scutil: timed out after %s (%s)", cmdTimeout, strings.TrimSpace(string(out)))
		}
		return out, fmt.Errorf("scutil: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// hasSplitDNSToken reports whether any entry is a "~name" routing token.
// networksetup code paths use it as a last-line guard.
func hasSplitDNSToken(entries []string) bool {
	for _, e := range entries {
		if strings.HasPrefix(strings.TrimSpace(e), "~") {
			return true
		}
	}
	return false
}

// splitDNSKey builds the dynamic-store key for one tunnel and kind.
func splitDNSKey(iface, kind string) (string, error) {
	if !utunIfaceRegex.MatchString(iface) {
		return "", fmt.Errorf("invalid interface name %q for split DNS", iface)
	}
	return splitDNSKeyPrefix + iface + "." + kind + "/DNS", nil
}

// buildSplitDNSScript renders the scutil script that installs one
// supplemental resolver key. Servers, domains and the interface are all
// re-validated here: a newline or whitespace in any token would otherwise
// inject extra commands into a root scutil session (for example overwriting
// the global DNS keys).
func buildSplitDNSScript(iface, kind string, servers, domains []string, noSearch bool) (string, error) {
	key, err := splitDNSKey(iface, kind)
	if err != nil {
		return "", err
	}
	if len(servers) == 0 {
		return "", fmt.Errorf("split DNS requires at least one server address")
	}
	if len(domains) == 0 {
		return "", fmt.Errorf("split DNS key %s has no domains", kind)
	}
	for _, s := range servers {
		if net.ParseIP(s) == nil || strings.ContainsAny(s, " \t\r\n\"'\\") {
			return "", fmt.Errorf("invalid split DNS server %q", s)
		}
	}
	for _, d := range domains {
		if len(d) > maxSplitDNSDomainLen || !validHostnameRegex.MatchString(d) {
			return "", fmt.Errorf("invalid split DNS domain %q", d)
		}
	}
	ns := 0
	if noSearch {
		ns = 1
	}
	var b strings.Builder
	b.WriteString("d.init\n")
	fmt.Fprintf(&b, "d.add ServerAddresses * %s\n", strings.Join(servers, " "))
	fmt.Fprintf(&b, "d.add SupplementalMatchDomains * %s\n", strings.Join(domains, " "))
	fmt.Fprintf(&b, "d.add SupplementalMatchDomainsNoSearch # %d\n", ns)
	fmt.Fprintf(&b, "set %s\n", key)
	b.WriteString("quit\n")
	script := b.String()
	for _, line := range strings.Split(script, "\n") {
		if len(line) > maxScutilLine {
			return "", fmt.Errorf("split DNS %s list too long for scutil (%d bytes, max %d)", kind, len(line), maxScutilLine)
		}
	}
	return script, nil
}

// verifySplitDNSShow checks that the `scutil show` output of an installed
// key contains every server and domain. scutil exits 0 and prints nothing
// when it mangles a command, so the read-back is the only reliable check.
func verifySplitDNSShow(show string, servers, domains []string) error {
	have := make(map[string]bool)
	haveIP := make(map[string]bool)
	for _, line := range strings.Split(show, "\n") {
		mt := showEntryRegex.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if mt == nil {
			continue
		}
		have[strings.ToLower(mt[1])] = true
		if ip := net.ParseIP(mt[1]); ip != nil {
			haveIP[ip.String()] = true
		}
	}
	for _, s := range servers {
		if ip := net.ParseIP(s); ip == nil || !haveIP[ip.String()] {
			return fmt.Errorf("server %s missing", s)
		}
	}
	for _, d := range domains {
		if !have[strings.ToLower(d)] {
			return fmt.Errorf("domain %s missing", d)
		}
	}
	return nil
}

// setSplitDNS installs supplemental resolvers for the tunnel: one key for
// the "~" routing domains and, when plain hostnames were given, a second
// key whose domains also act as search domains. System DNS (networksetup,
// preferences) is never touched.
func (m *DarwinManager) setSplitDNS(ifaceName string, p domain.DNSEntries) error {
	if len(p.Servers) == 0 {
		return fmt.Errorf("split DNS requires at least one DNS server address")
	}
	for _, d := range p.Match {
		if strings.HasSuffix(strings.ToLower(d), ".local") {
			slog.Warn("split DNS match domain ends in .local; macOS may resolve it via mDNS instead of the tunnel resolver", "domain", d)
		}
	}

	type keySpec struct {
		kind     string
		domains  []string
		noSearch bool
	}
	specs := []keySpec{{splitKindMatch, p.Match, true}}
	if len(p.Search) > 0 {
		specs = append(specs, keySpec{splitKindSearch, p.Search, false})
	}

	// Build every script first so a rejected token installs nothing.
	scripts := make([]string, len(specs))
	for i, sp := range specs {
		s, err := buildSplitDNSScript(ifaceName, sp.kind, p.Servers, sp.domains, sp.noSearch)
		if err != nil {
			return err
		}
		scripts[i] = s
	}

	for i, sp := range specs {
		key, _ := splitDNSKey(ifaceName, sp.kind)
		out, err := scutilExec(scripts[i])
		if err != nil {
			_ = m.removeSplitDNS(ifaceName)
			return fmt.Errorf("installing split DNS: %w", err)
		}
		if msg := strings.TrimSpace(string(out)); msg != "" {
			_ = m.removeSplitDNS(ifaceName)
			return fmt.Errorf("installing split DNS: scutil: %s", msg)
		}
		// scutil exits 0 on failure, so read the key back.
		show, err := scutilExec("show " + key + "\nquit\n")
		if err != nil {
			_ = m.removeSplitDNS(ifaceName)
			return fmt.Errorf("split DNS key %s not found after install", key)
		}
		if verr := verifySplitDNSShow(string(show), p.Servers, sp.domains); verr != nil {
			_ = m.removeSplitDNS(ifaceName)
			return fmt.Errorf("split DNS key %s incomplete after install: %w", key, verr)
		}
	}
	flushDNSCache()
	slog.Info("split DNS installed", "iface", ifaceName, "servers", p.Servers, "match", p.Match, "search", p.Search)
	return nil
}

// RemoveSplitDNS removes the tunnel's split-DNS keys. Idempotent and
// derived from the interface name only.
func (m *DarwinManager) RemoveSplitDNS(ifaceName string) error {
	return m.removeSplitDNS(ifaceName)
}

func (m *DarwinManager) removeSplitDNS(ifaceName string) error {
	if !utunIfaceRegex.MatchString(ifaceName) {
		// Nothing of ours can exist under a name we would never create.
		return nil
	}
	var firstErr error
	removed := false
	for _, kind := range []string{splitKindMatch, splitKindSearch} {
		key, _ := splitDNSKey(ifaceName, kind)
		gone, err := removeSplitKey(key)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		removed = removed || gone
	}
	if removed {
		flushDNSCache()
	}
	return firstErr
}

// removeSplitKey removes one key. gone reports whether a key actually
// existed; "No such key" is success.
func removeSplitKey(key string) (gone bool, err error) {
	out, err := scutilExec("remove " + key + "\nquit\n")
	if err != nil {
		return false, fmt.Errorf("removing %s: %w", key, err)
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return true, nil
	}
	if strings.Contains(msg, "No such key") {
		return false, nil
	}
	return false, fmt.Errorf("removing %s: scutil: %s", key, msg)
}

// CleanupStaleSplitDNS removes every com.wireguide.* DNS key left in the
// dynamic store, e.g. by a crashed helper. Only keys under our prefix are
// ever touched. Safe at helper start: tunnels from a dead process are gone.
func CleanupStaleSplitDNS() error {
	out, err := scutilExec("list State:/Network/Service/com\\.wireguide\\..*/DNS\nquit\n")
	if err != nil {
		return fmt.Errorf("listing split DNS keys: %w", err)
	}
	var firstErr error
	removed := false
	for _, line := range strings.Split(string(out), "\n") {
		mt := staleSplitKeyRegex.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if mt == nil || !strings.HasPrefix(mt[1], splitDNSKeyPrefix) {
			continue
		}
		gone, err := removeSplitKey(mt[1])
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if gone {
			slog.Info("removed stale split DNS key", "key", mt[1])
			removed = true
		}
	}
	if removed {
		flushDNSCache()
	}
	return firstErr
}
