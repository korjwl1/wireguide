package config

import (
	"strings"
	"testing"
)

const validConf = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParseValidConfig(t *testing.T) {
	cfg, err := Parse(validConf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Interface.PrivateKey != "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=" {
		t.Errorf("PrivateKey mismatch: %s", cfg.Interface.PrivateKey)
	}
	if len(cfg.Interface.Address) != 1 || cfg.Interface.Address[0] != "10.0.0.2/24" {
		t.Errorf("Address mismatch: %v", cfg.Interface.Address)
	}
	if len(cfg.Interface.DNS) != 2 {
		t.Errorf("expected 2 DNS servers, got %d", len(cfg.Interface.DNS))
	}
	if cfg.Interface.MTU != 1420 {
		t.Errorf("MTU mismatch: %d", cfg.Interface.MTU)
	}

	if len(cfg.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
	}
	peer := cfg.Peers[0]
	if peer.PublicKey != "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=" {
		t.Errorf("PublicKey mismatch: %s", peer.PublicKey)
	}
	if peer.Endpoint != "vpn.example.com:51820" {
		t.Errorf("Endpoint mismatch: %s", peer.Endpoint)
	}
	if len(peer.AllowedIPs) != 2 {
		t.Errorf("expected 2 AllowedIPs, got %d", len(peer.AllowedIPs))
	}
	if peer.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive mismatch: %d", peer.PersistentKeepalive)
	}
}

func TestParseMultiplePeers(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2piVFBs2LPqG08=
Endpoint = 192.168.1.1:51820
AllowedIPs = 192.168.1.0/24
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(cfg.Peers))
	}
	if cfg.Peers[1].Endpoint != "192.168.1.1:51820" {
		t.Errorf("second peer endpoint mismatch: %s", cfg.Peers[1].Endpoint)
	}
}

func TestParseWithScripts(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PreDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.HasScripts() {
		t.Error("expected HasScripts() to return true")
	}
	scripts := cfg.Scripts()
	if len(scripts) != 2 {
		t.Fatalf("expected 2 scripts, got %d", len(scripts))
	}
	if scripts[0].Hook != "PostUp" {
		t.Errorf("expected PostUp, got %s", scripts[0].Hook)
	}
	if scripts[1].Hook != "PreDown" {
		t.Errorf("expected PreDown, got %s", scripts[1].Hook)
	}
}

func TestParseInvalidSyntax(t *testing.T) {
	_, err := Parse("not a valid config")
	if err == nil {
		t.Error("expected error for invalid syntax")
	}
}

func TestParseEmptyContent(t *testing.T) {
	cfg, err := Parse("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Peers) != 0 {
		t.Error("expected no peers for empty config")
	}
}

func TestParseCommentsAndEmptyLines(t *testing.T) {
	conf := `# This is a comment
; This is also a comment

[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

# Peer section
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
	}
}

// --- Validation tests ---

func TestValidateValidConfig(t *testing.T) {
	cfg, _ := Parse(validConf)
	result := Validate(cfg)
	if !result.IsValid() {
		t.Errorf("expected valid config, got errors: %v", result.ErrorMessages())
	}
}

func TestValidateMissingPrivateKey(t *testing.T) {
	conf := `[Interface]
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	if result.IsValid() {
		t.Error("expected validation error for missing PrivateKey")
	}
	found := false
	for _, e := range result.Errors {
		if e.Field == "Interface.PrivateKey" {
			found = true
		}
	}
	if !found {
		t.Error("expected error on Interface.PrivateKey field")
	}
}

func TestValidateMissingAddress(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	hasAddrError := false
	for _, e := range result.Errors {
		if e.Field == "Interface.Address" {
			hasAddrError = true
		}
	}
	if !hasAddrError {
		t.Error("expected validation error for missing Address")
	}
}

func TestValidateInvalidKey(t *testing.T) {
	conf := `[Interface]
PrivateKey = not-a-valid-base64-key!!!
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	hasKeyError := false
	for _, e := range result.Errors {
		if e.Field == "Interface.PrivateKey" && strings.Contains(e.Message, "invalid key") {
			hasKeyError = true
		}
	}
	if !hasKeyError {
		t.Error("expected validation error for invalid PrivateKey format")
	}
}

func TestValidateInvalidCIDR(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	hasCIDRError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "invalid CIDR") {
			hasCIDRError = true
		}
	}
	if !hasCIDRError {
		t.Error("expected validation error for invalid CIDR format")
	}
}

func TestValidateInvalidEndpoint(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = invalid-endpoint
AllowedIPs = 0.0.0.0/0
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	hasEndpointError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Field, "Endpoint") {
			hasEndpointError = true
		}
	}
	if !hasEndpointError {
		t.Error("expected validation error for invalid endpoint")
	}
}

func TestValidateNoPeers(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	hasPeerError := false
	for _, e := range result.Errors {
		if e.Field == "Peer" {
			hasPeerError = true
		}
	}
	if !hasPeerError {
		t.Error("expected validation error for missing peers")
	}
}

func TestValidateMissingPeerPublicKey(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
AllowedIPs = 0.0.0.0/0
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	hasPKError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Field, "PublicKey") {
			hasPKError = true
		}
	}
	if !hasPKError {
		t.Error("expected validation error for missing PublicKey")
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	conf := `[Interface]
Address = bad-cidr

[Peer]
Endpoint = no-port
AllowedIPs = also-bad
`
	cfg, _ := Parse(conf)
	result := Validate(cfg)
	if len(result.Errors) < 3 {
		t.Errorf("expected at least 3 errors, got %d: %v", len(result.Errors), result.ErrorMessages())
	}
}

// --- Serialization tests ---

func TestSerializeRoundTrip(t *testing.T) {
	cfg, err := Parse(validConf)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	serialized := Serialize(cfg)
	cfg2, err := Parse(serialized)
	if err != nil {
		t.Fatalf("re-parse error: %v", err)
	}

	if cfg2.Interface.PrivateKey != cfg.Interface.PrivateKey {
		t.Error("PrivateKey mismatch after round-trip")
	}
	if len(cfg2.Peers) != len(cfg.Peers) {
		t.Error("peer count mismatch after round-trip")
	}
	if cfg2.Peers[0].Endpoint != cfg.Peers[0].Endpoint {
		t.Error("endpoint mismatch after round-trip")
	}
}

// --- Helper tests ---

func TestIsFullTunnel(t *testing.T) {
	cfg, _ := Parse(validConf)
	if !cfg.IsFullTunnel() {
		t.Error("expected IsFullTunnel() to be true for 0.0.0.0/0")
	}

	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.0.0.0/24
`
	cfg2, _ := Parse(conf)
	if cfg2.IsFullTunnel() {
		t.Error("expected IsFullTunnel() to be false for 10.0.0.0/24")
	}
}

func TestHasScriptsNoScripts(t *testing.T) {
	cfg, _ := Parse(validConf)
	if cfg.HasScripts() {
		t.Error("expected HasScripts() to be false for config without scripts")
	}
}
