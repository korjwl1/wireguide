package cli

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/automation"
)

func TestParseCondition(t *testing.T) {
	cases := []struct {
		spec    string
		want    automation.Condition
		wantErr bool
	}{
		{spec: "ssid:Home", want: automation.Condition{Type: automation.CondSSID, SSID: "Home"}},
		{spec: "ssid: Home  ", want: automation.Condition{Type: automation.CondSSID, SSID: "Home"}},
		{spec: "not-ssid:Home WiFi", want: automation.Condition{Type: automation.CondSSID, Negate: true, SSID: "Home WiFi"}},
		{spec: "not-ssid:  HomeWiFi ", want: automation.Condition{Type: automation.CondSSID, Negate: true, SSID: "HomeWiFi"}},
		{spec: "ssid:cafe:5G", want: automation.Condition{Type: automation.CondSSID, SSID: "cafe:5G"}},
		{spec: "subnet:10.0.0.0/24", want: automation.Condition{Type: automation.CondSubnet, Subnet: "10.0.0.0/24"}},
		{spec: "not-subnet:10.0.0.0/24", want: automation.Condition{Type: automation.CondSubnet, Negate: true, Subnet: "10.0.0.0/24"}},
		{spec: "mac:B0:38:6C:54:8B:AB", want: automation.Condition{Type: automation.CondNetwork, GatewayMAC: "b0:38:6c:54:8b:ab"}},
		{spec: "not-mac:B0:38:6C:54:8B:AB", want: automation.Condition{Type: automation.CondNetwork, Negate: true, GatewayMAC: "b0:38:6c:54:8b:ab"}},
		{spec: "else", want: automation.Condition{Type: automation.CondNoneMatch}},
		{spec: "not-else", wantErr: true},
		{spec: "not-ssid:", wantErr: true},
		{spec: "not-ssid:   ", wantErr: true},
		{spec: "not-subnet:nope", wantErr: true},
		{spec: "not-mac:zz", wantErr: true},
		{spec: "not-bogus:x", wantErr: true},
		{spec: "ssid", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parseCondition(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got %+v", tc.spec, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.spec, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %+v want %+v", tc.spec, got, tc.want)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("%q: parsed condition fails Validate: %v", tc.spec, err)
		}
	}
}

func TestFormatCondition(t *testing.T) {
	cases := []struct {
		c    automation.Condition
		want string
	}{
		{automation.Condition{Type: automation.CondSSID, SSID: "A"}, "ssid=A"},
		{automation.Condition{Type: automation.CondSSID, Negate: true, SSID: "A"}, "ssid!=A"},
		{automation.Condition{Type: automation.CondSubnet, Subnet: "10.0.0.0/8"}, "subnet=10.0.0.0/8"},
		{automation.Condition{Type: automation.CondSubnet, Negate: true, Subnet: "10.0.0.0/8"}, "subnet!=10.0.0.0/8"},
		{automation.Condition{Type: automation.CondNetwork, GatewayMAC: "aa:bb:cc:dd:ee:ff"}, "network(mac)=aa:bb:cc:dd:ee:ff"},
		{automation.Condition{Type: automation.CondNetwork, Negate: true, GatewayMAC: "aa:bb:cc:dd:ee:ff"}, "network(mac)!=aa:bb:cc:dd:ee:ff"},
		{automation.Condition{Type: automation.CondNoneMatch}, "otherwise"},
	}
	for _, tc := range cases {
		if got := formatCondition(tc.c); got != tc.want {
			t.Errorf("%+v: got %q want %q", tc.c, got, tc.want)
		}
	}
}
