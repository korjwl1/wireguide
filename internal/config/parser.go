package config

import (
	"bufio"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// MaxConfigSize is the hard cap on a single .conf file. A legitimate
// WireGuard config is rarely more than a few KiB; the 1 MiB ceiling
// here is generous enough for the largest realistic split-tunnel setup
// (hundreds of /32 routes spelt out) while denying an attacker the
// ability to OOM the helper by sending a 1 GB "config".
const MaxConfigSize = 1 << 20 // 1 MiB

// MaxAllowedIPsPerPeer is the per-peer cap on AllowedIPs entries. A
// realistic peer has 1-10 CIDRs; 10K entries is far beyond legitimate
// use but still lets a power user spell out every /32 in a /16 (65K
// would be too permissive). Caps the O(N) work the validator does
// per peer.
const MaxAllowedIPsPerPeer = 10000

// Parse parses a WireGuard .conf file content into a WireGuardConfig.
func Parse(content string) (*WireGuardConfig, error) {
	// Reject oversized inputs before any work — defends against malicious
	// or accidentally-huge .conf files used as a DoS vector. The 1 MiB
	// limit lines up with bufio.Scanner's buffer cap below.
	if len(content) > MaxConfigSize {
		return nil, fmt.Errorf("config too large: %d bytes (max %d)", len(content), MaxConfigSize)
	}
	// Strip UTF-8 BOM if present (common when files are saved by Windows editors).
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")

	cfg := &WireGuardConfig{}
	var currentSection string
	var currentPeer *PeerConfig

	scanner := bufio.NewScanner(strings.NewReader(content))
	// bufio's default 64 KiB token cap is hit by configs with very
	// long AllowedIPs lists — legitimate when a peer covers a lot of
	// /32 routes. Bump to 1 MiB; the file as a whole is already
	// bounded by the config-import filesize check.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		// Reject embedded NULs anywhere in the line. They survive
		// TrimSpace and break the round-trip serialization (NUL is
		// our internal scriptSeparator) — far better to fail fast
		// here than to corrupt data on save.
		if strings.ContainsRune(line, 0) {
			return nil, fmt.Errorf("line %d: NUL byte in value", lineNum)
		}

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section headers
		lower := strings.ToLower(line)
		if lower == "[interface]" {
			currentSection = "interface"
			continue
		}
		if lower == "[peer]" {
			currentSection = "peer"
			peer := PeerConfig{}
			cfg.Peers = append(cfg.Peers, peer)
			currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			continue
		}

		// Key = Value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: invalid syntax: %q", lineNum, line)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "interface":
			if err := parseInterfaceKey(&cfg.Interface, key, value, lineNum); err != nil {
				return nil, err
			}
		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("line %d: key %q outside of section", lineNum, key)
			}
			if err := parsePeerKey(currentPeer, key, value, lineNum); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("line %d: key %q outside of any section", lineNum, key)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// Validate that an [Interface] section was present with at least a PrivateKey.
	// A config without [Interface] is structurally invalid and would cause
	// downstream failures when wireguard-go tries to use an empty key.
	if cfg.Interface.PrivateKey == "" {
		return nil, fmt.Errorf("config has no [Interface] section or missing PrivateKey")
	}

	return cfg, nil
}

func parseInterfaceKey(iface *InterfaceConfig, key, value string, lineNum int) error {
	switch strings.ToLower(key) {
	case "privatekey":
		iface.PrivateKey = value
	case "address":
		iface.Address = append(iface.Address, splitAndTrim(value)...)
	case "dns":
		iface.DNS = append(iface.DNS, splitAndTrim(value)...)
	case "mtu":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("line %d: invalid MTU value: %q", lineNum, value)
		}
		iface.MTU = n
	case "listenport":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("line %d: invalid ListenPort value: %q", lineNum, value)
		}
		iface.ListenPort = n
	case "table":
		iface.Table = value
	case "fwmark":
		iface.FwMark = value
	case "preup":
		iface.PreUp = appendScriptLine(iface.PreUp, value)
	case "postup":
		iface.PostUp = appendScriptLine(iface.PostUp, value)
	case "predown":
		iface.PreDown = appendScriptLine(iface.PreDown, value)
	case "postdown":
		iface.PostDown = appendScriptLine(iface.PostDown, value)
	default:
		slog.Warn("ignoring unknown [Interface] key", "line", lineNum, "key", key)
		if iface.ExtraKeys == nil {
			iface.ExtraKeys = make(map[string]string)
		}
		iface.ExtraKeys[key] = value
	}
	return nil
}

func parsePeerKey(peer *PeerConfig, key, value string, lineNum int) error {
	switch strings.ToLower(key) {
	case "publickey":
		peer.PublicKey = value
	case "presharedkey":
		peer.PresharedKey = value
	case "endpoint":
		peer.Endpoint = value
	case "allowedips":
		add := splitAndTrim(value)
		// Per-peer cap so a malicious config can't drive the validator's
		// O(N) per-peer scan into denial-of-service territory.
		if len(peer.AllowedIPs)+len(add) > MaxAllowedIPsPerPeer {
			return fmt.Errorf("AllowedIPs exceeds per-peer cap (%d)", MaxAllowedIPsPerPeer)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, add...)
	case "persistentkeepalive":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("line %d: invalid PersistentKeepalive value: %q", lineNum, value)
		}
		peer.PersistentKeepalive = n
	default:
		slog.Warn("ignoring unknown [Peer] key", "line", lineNum, "key", key)
		if peer.ExtraKeys == nil {
			peer.ExtraKeys = make(map[string]string)
		}
		peer.ExtraKeys[key] = value
	}
	return nil
}

// Serialize converts a WireGuardConfig back to .conf file format.
// Multiple Pre/PostUp/Down commands (joined with " ; " internally) are
// written as separate lines, matching wg-quick's multi-line convention.
func Serialize(cfg *WireGuardConfig) string {
	var b strings.Builder

	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + cfg.Interface.PrivateKey + "\n")
	if len(cfg.Interface.Address) > 0 {
		b.WriteString("Address = " + strings.Join(cfg.Interface.Address, ", ") + "\n")
	}
	if len(cfg.Interface.DNS) > 0 {
		b.WriteString("DNS = " + strings.Join(cfg.Interface.DNS, ", ") + "\n")
	}
	if cfg.Interface.MTU > 0 {
		b.WriteString("MTU = " + strconv.Itoa(cfg.Interface.MTU) + "\n")
	}
	if cfg.Interface.ListenPort > 0 {
		b.WriteString("ListenPort = " + strconv.Itoa(cfg.Interface.ListenPort) + "\n")
	}
	if cfg.Interface.Table != "" {
		b.WriteString("Table = " + cfg.Interface.Table + "\n")
	}
	if cfg.Interface.FwMark != "" {
		b.WriteString("FwMark = " + cfg.Interface.FwMark + "\n")
	}
	writeScriptLines(&b, "PreUp", cfg.Interface.PreUp)
	writeScriptLines(&b, "PostUp", cfg.Interface.PostUp)
	writeScriptLines(&b, "PreDown", cfg.Interface.PreDown)
	writeScriptLines(&b, "PostDown", cfg.Interface.PostDown)
	for k, v := range cfg.Interface.ExtraKeys {
		b.WriteString(k + " = " + v + "\n")
	}

	for _, peer := range cfg.Peers {
		b.WriteString("\n[Peer]\n")
		b.WriteString("PublicKey = " + peer.PublicKey + "\n")
		if peer.PresharedKey != "" {
			b.WriteString("PresharedKey = " + peer.PresharedKey + "\n")
		}
		if peer.Endpoint != "" {
			b.WriteString("Endpoint = " + peer.Endpoint + "\n")
		}
		if len(peer.AllowedIPs) > 0 {
			b.WriteString("AllowedIPs = " + strings.Join(peer.AllowedIPs, ", ") + "\n")
		}
		if peer.PersistentKeepalive > 0 {
			b.WriteString("PersistentKeepalive = " + strconv.Itoa(peer.PersistentKeepalive) + "\n")
		}
		for k, v := range peer.ExtraKeys {
			b.WriteString(k + " = " + v + "\n")
		}
	}

	return b.String()
}

// scriptSeparator is a sentinel used to join/split multiple Pre/PostUp/Down
// script lines internally. It must not appear in any legitimate script command.
// Using a NUL byte ensures collision-free round-tripping.
const scriptSeparator = "\x00"

// appendScriptLine joins multiple Pre/PostUp/Down values with the internal
// separator so they can be stored in a single string field.
func appendScriptLine(existing, value string) string {
	if existing == "" {
		return value
	}
	return existing + scriptSeparator + value
}

// writeScriptLines writes Pre/PostUp/Down values back as separate lines,
// splitting on the internal separator. This round-trips correctly with
// wg-quick's multi-line convention without colliding with ` ; ` in scripts.
func writeScriptLines(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	for _, part := range strings.Split(value, scriptSeparator) {
		b.WriteString(key + " = " + part + "\n")
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
