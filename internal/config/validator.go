package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
)

// ValidationError represents a single validation issue.
type ValidationError struct {
	Field   string // e.g., "Interface.PrivateKey", "Peer[0].PublicKey"
	Message string // Human-readable error
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult holds all validation errors found.
type ValidationResult struct {
	Errors []ValidationError
}

func (r *ValidationResult) addError(field, message string) {
	r.Errors = append(r.Errors, ValidationError{Field: field, Message: message})
}

// IsValid returns true if no errors were found.
func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// Validate checks a WireGuardConfig for correctness and returns all errors found.
func Validate(cfg *WireGuardConfig) *ValidationResult {
	result := &ValidationResult{}

	// Interface validation
	validateInterface(&cfg.Interface, result)

	// Must have at least one peer
	if len(cfg.Peers) == 0 {
		result.addError("Peer", "at least one [Peer] section is required")
	}

	// Peer validation
	for i := range cfg.Peers {
		validatePeer(&cfg.Peers[i], i, result)
	}

	return result
}

func validateInterface(iface *InterfaceConfig, result *ValidationResult) {
	// PrivateKey: required, Base64-encoded 32 bytes
	if iface.PrivateKey == "" {
		result.addError("Interface.PrivateKey", "PrivateKey is required")
	} else if !isValidWireGuardKey(iface.PrivateKey) {
		result.addError("Interface.PrivateKey", "invalid key format (must be Base64-encoded 32 bytes)")
	}

	// Address: required, valid CIDR
	if len(iface.Address) == 0 {
		result.addError("Interface.Address", "Address is required")
	} else {
		for _, addr := range iface.Address {
			if _, _, err := net.ParseCIDR(addr); err != nil {
				result.addError("Interface.Address", fmt.Sprintf("invalid CIDR format: %q", addr))
			}
		}
	}

	// DNS: optional, valid IP addresses
	for _, dns := range iface.DNS {
		if net.ParseIP(dns) == nil {
			result.addError("Interface.DNS", fmt.Sprintf("invalid DNS address: %q", dns))
		}
	}

	// MTU: optional, valid range
	if iface.MTU != 0 && (iface.MTU < 576 || iface.MTU > 65535) {
		result.addError("Interface.MTU", fmt.Sprintf("MTU must be between 576 and 65535, got %d", iface.MTU))
	}

	// ListenPort: optional, valid range
	if iface.ListenPort != 0 && (iface.ListenPort < 1 || iface.ListenPort > 65535) {
		result.addError("Interface.ListenPort", fmt.Sprintf("ListenPort must be between 1 and 65535, got %d", iface.ListenPort))
	}
}

func validatePeer(peer *PeerConfig, index int, result *ValidationResult) {
	prefix := fmt.Sprintf("Peer[%d]", index)

	// PublicKey: required
	if peer.PublicKey == "" {
		result.addError(prefix+".PublicKey", "PublicKey is required")
	} else if !isValidWireGuardKey(peer.PublicKey) {
		result.addError(prefix+".PublicKey", "invalid key format (must be Base64-encoded 32 bytes)")
	}

	// PresharedKey: optional, but if present must be valid
	if peer.PresharedKey != "" && !isValidWireGuardKey(peer.PresharedKey) {
		result.addError(prefix+".PresharedKey", "invalid key format (must be Base64-encoded 32 bytes)")
	}

	// Endpoint: optional, but if present must be host:port
	if peer.Endpoint != "" {
		if err := validateEndpoint(peer.Endpoint); err != nil {
			result.addError(prefix+".Endpoint", err.Error())
		}
	}

	// AllowedIPs: required, valid CIDR
	if len(peer.AllowedIPs) == 0 {
		result.addError(prefix+".AllowedIPs", "AllowedIPs is required")
	} else {
		for _, ip := range peer.AllowedIPs {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				result.addError(prefix+".AllowedIPs", fmt.Sprintf("invalid CIDR format: %q", ip))
			}
		}
	}

	// PersistentKeepalive: optional, valid range
	if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
		result.addError(prefix+".PersistentKeepalive",
			fmt.Sprintf("must be between 0 and 65535, got %d", peer.PersistentKeepalive))
	}
}

func isValidWireGuardKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	return len(decoded) == 32
}

func validateEndpoint(endpoint string) error {
	// Endpoint can be host:port or [ipv6]:port
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint format: %q (expected host:port)", endpoint)
	}
	if host == "" {
		return fmt.Errorf("endpoint host is empty")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid endpoint port: %q", portStr)
	}
	return nil
}

// ErrorMessages returns human-readable error strings for all validation errors.
func (r *ValidationResult) ErrorMessages() []string {
	msgs := make([]string, len(r.Errors))
	for i, e := range r.Errors {
		msgs[i] = e.Error()
	}
	return msgs
}

// HasScriptWarnings returns true if the config contains executable scripts.
func HasScriptWarnings(cfg *WireGuardConfig) bool {
	return cfg.HasScripts()
}
