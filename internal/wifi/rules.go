package wifi

// Rules defines WiFi auto-connect behavior.
type Rules struct {
	Enabled              bool              `json:"enabled"`
	DefaultTunnel        string            `json:"default_tunnel"`         // Tunnel to connect on untrusted networks
	AutoConnectUntrusted bool              `json:"auto_connect_untrusted"` // Connect VPN on unknown SSIDs
	TrustedSSIDs         []string          `json:"trusted_ssids"`          // SSIDs where VPN is NOT needed
	SSIDTunnelMap        map[string]string `json:"ssid_tunnel_map"`        // SSID → specific tunnel name
}

// DefaultRules returns empty rules (feature disabled).
func DefaultRules() *Rules {
	return &Rules{
		Enabled:       false,
		SSIDTunnelMap: make(map[string]string),
	}
}

// Action determines what to do when connected to the given SSID.
func (r *Rules) Action(ssid string) (action string, tunnelName string) {
	if !r.Enabled || ssid == "" {
		return "none", ""
	}

	// Check trusted SSIDs — disconnect VPN
	for _, trusted := range r.TrustedSSIDs {
		if trusted == ssid {
			return "disconnect", ""
		}
	}

	// Check SSID → tunnel mapping
	if tunnel, ok := r.SSIDTunnelMap[ssid]; ok {
		return "connect", tunnel
	}

	// Unknown SSID + auto-connect enabled → use default tunnel
	if r.AutoConnectUntrusted && r.DefaultTunnel != "" {
		return "connect", r.DefaultTunnel
	}

	return "none", ""
}
