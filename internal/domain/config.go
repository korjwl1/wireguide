// Package domain holds the core types of the WireGuide application.
// These are pure value objects with no external dependencies — they can be
// used freely from any package without creating import cycles.
package domain

import "net"

// WireGuardConfig represents a complete WireGuard configuration file.
type WireGuardConfig struct {
	Name      string          `json:"name"`      // Tunnel name (derived from filename)
	Interface InterfaceConfig `json:"interface"` // [Interface] section
	Peers     []PeerConfig    `json:"peers"`     // [Peer] sections (1 or more)
}

// InterfaceConfig represents the [Interface] section of a .conf file.
type InterfaceConfig struct {
	PrivateKey string   `json:"private_key"`           // Required: Base64-encoded 32-byte key
	Address    []string `json:"address"`               // Required: CIDR addresses (e.g., "10.0.0.2/24")
	DNS        []string `json:"dns,omitempty"`         // Optional: DNS servers and/or search domains
	MTU        int      `json:"mtu,omitempty"`         // Optional: 0 = auto-detect
	ListenPort int      `json:"listen_port,omitempty"` // Optional: 0 = random
	Table      string   `json:"table,omitempty"`       // Optional: routing table
	FwMark     string   `json:"fw_mark,omitempty"`     // Optional: firewall mark
	PreUp      string   `json:"pre_up,omitempty"`      // Optional: script before interface up
	PostUp     string   `json:"post_up,omitempty"`     // Optional: script after interface up
	PreDown    string   `json:"pre_down,omitempty"`    // Optional: script before interface down
	PostDown   string   `json:"post_down,omitempty"`   // Optional: script after interface down
	ExtraKeys  map[string]string `json:"extra_keys,omitempty"` // Unrecognized keys preserved for round-tripping
}

// PeerConfig represents a [Peer] section of a .conf file.
type PeerConfig struct {
	PublicKey           string   `json:"public_key"`                     // Required: Base64-encoded 32-byte key
	PresharedKey        string   `json:"preshared_key,omitempty"`        // Optional
	Endpoint            string   `json:"endpoint,omitempty"`             // Optional: host:port
	AllowedIPs          []string `json:"allowed_ips"`                    // Required: CIDR list
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"` // Optional: seconds (0 = disabled)
	ExtraKeys           map[string]string `json:"extra_keys,omitempty"` // Unrecognized keys preserved for round-tripping
}

// HasScripts returns true if any Pre/PostUp/Down scripts are defined.
func (c *WireGuardConfig) HasScripts() bool {
	return c.Interface.PreUp != "" ||
		c.Interface.PostUp != "" ||
		c.Interface.PreDown != "" ||
		c.Interface.PostDown != ""
}

// Script represents a Pre/PostUp/Down hook command.
type Script struct {
	Hook    string `json:"hook"`    // "PreUp" | "PostUp" | "PreDown" | "PostDown"
	Command string `json:"command"` // Shell command to execute
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

// Endpoints returns all non-empty peer endpoints. Used for bypass route setup
// on full-tunnel mode — we need to add host routes for every peer endpoint,
// not just the first one (multi-peer site-to-site configs).
func (c *WireGuardConfig) Endpoints() []string {
	var eps []string
	for _, p := range c.Peers {
		if p.Endpoint != "" {
			eps = append(eps, p.Endpoint)
		}
	}
	return eps
}
