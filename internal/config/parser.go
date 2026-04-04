package config

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// Parse parses a WireGuard .conf file content into a WireGuardConfig.
func Parse(content string) (*WireGuardConfig, error) {
	cfg := &WireGuardConfig{}
	var currentSection string
	var currentPeer *PeerConfig

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

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

	return cfg, nil
}

func parseInterfaceKey(iface *InterfaceConfig, key, value string, lineNum int) error {
	switch strings.ToLower(key) {
	case "privatekey":
		iface.PrivateKey = value
	case "address":
		iface.Address = splitAndTrim(value)
	case "dns":
		iface.DNS = splitAndTrim(value)
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
		iface.PreUp = value
	case "postup":
		iface.PostUp = value
	case "predown":
		iface.PreDown = value
	case "postdown":
		iface.PostDown = value
	default:
		return fmt.Errorf("line %d: unknown [Interface] key: %q", lineNum, key)
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
		peer.AllowedIPs = splitAndTrim(value)
	case "persistentkeepalive":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("line %d: invalid PersistentKeepalive value: %q", lineNum, value)
		}
		peer.PersistentKeepalive = n
	default:
		return fmt.Errorf("line %d: unknown [Peer] key: %q", lineNum, key)
	}
	return nil
}

// Serialize converts a WireGuardConfig back to .conf file format.
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
	if cfg.Interface.PreUp != "" {
		b.WriteString("PreUp = " + cfg.Interface.PreUp + "\n")
	}
	if cfg.Interface.PostUp != "" {
		b.WriteString("PostUp = " + cfg.Interface.PostUp + "\n")
	}
	if cfg.Interface.PreDown != "" {
		b.WriteString("PreDown = " + cfg.Interface.PreDown + "\n")
	}
	if cfg.Interface.PostDown != "" {
		b.WriteString("PostDown = " + cfg.Interface.PostDown + "\n")
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
	}

	return b.String()
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
