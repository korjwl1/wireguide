package config

import "net"

// WireGuardConfig represents a complete WireGuard configuration file.
type WireGuardConfig struct {
	Name      string          // Tunnel name (derived from filename)
	Interface InterfaceConfig // [Interface] section
	Peers     []PeerConfig    // [Peer] sections (1 or more)
}

// InterfaceConfig represents the [Interface] section of a .conf file.
type InterfaceConfig struct {
	PrivateKey string   // Required: Base64-encoded 32-byte key
	Address    []string // Required: CIDR addresses (e.g., "10.0.0.2/24")
	DNS        []string // Optional: DNS server addresses
	MTU        int      // Optional: defaults to 0 (auto)
	ListenPort int      // Optional: defaults to 0 (random)
	Table      string   // Optional: routing table
	FwMark     string   // Optional: firewall mark
	PreUp      string   // Optional: script to run before interface up
	PostUp     string   // Optional: script to run after interface up
	PreDown    string   // Optional: script to run before interface down
	PostDown   string   // Optional: script to run after interface down
}

// PeerConfig represents a [Peer] section of a .conf file.
type PeerConfig struct {
	PublicKey           string   // Required: Base64-encoded 32-byte key
	PresharedKey        string   // Optional: Base64-encoded 32-byte key
	Endpoint            string   // Optional: host:port
	AllowedIPs          []string // Required: CIDR addresses
	PersistentKeepalive int      // Optional: seconds, 0 = disabled
}

// HasScripts returns true if any Pre/PostUp/Down scripts are defined.
func (c *WireGuardConfig) HasScripts() bool {
	return c.Interface.PreUp != "" ||
		c.Interface.PostUp != "" ||
		c.Interface.PreDown != "" ||
		c.Interface.PostDown != ""
}

// Scripts returns all defined script commands with their hook names.
func (c *WireGuardConfig) Scripts() []Script {
	var scripts []Script
	if c.Interface.PreUp != "" {
		scripts = append(scripts, Script{Hook: "PreUp", Command: c.Interface.PreUp})
	}
	if c.Interface.PostUp != "" {
		scripts = append(scripts, Script{Hook: "PostUp", Command: c.Interface.PostUp})
	}
	if c.Interface.PreDown != "" {
		scripts = append(scripts, Script{Hook: "PreDown", Command: c.Interface.PreDown})
	}
	if c.Interface.PostDown != "" {
		scripts = append(scripts, Script{Hook: "PostDown", Command: c.Interface.PostDown})
	}
	return scripts
}

// Script represents a Pre/PostUp/Down hook command.
type Script struct {
	Hook    string // "PreUp", "PostUp", "PreDown", "PostDown"
	Command string // Shell command to execute
}

// IsFullTunnel returns true if any peer routes all traffic (0.0.0.0/0 or ::/0).
func (c *WireGuardConfig) IsFullTunnel() bool {
	for _, peer := range c.Peers {
		for _, ip := range peer.AllowedIPs {
			_, cidr, err := net.ParseCIDR(ip)
			if err != nil {
				continue
			}
			ones, bits := cidr.Mask.Size()
			if ones == 0 && (bits == 32 || bits == 128) {
				return true
			}
		}
	}
	return false
}
