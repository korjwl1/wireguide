package cli

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/wifi"
)

func TestParseCondition(t *testing.T) {
	cases := []struct {
		spec    string
		want    wifi.Condition
		wantErr bool
	}{
		{spec: "ssid:Home", want: wifi.Condition{Type: wifi.CondSSID, SSID: "Home"}},
		{spec: "ssid: Home  ", want: wifi.Condition{Type: wifi.CondSSID, SSID: "Home"}},
		{spec: "not-ssid:Home WiFi", want: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "Home WiFi"}},
		{spec: "not-ssid:  HomeWiFi ", want: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "HomeWiFi"}},
		{spec: "ssid:cafe:5G", want: wifi.Condition{Type: wifi.CondSSID, SSID: "cafe:5G"}},
		{spec: "subnet:10.0.0.0/24", want: wifi.Condition{Type: wifi.CondSubnet, Subnet: "10.0.0.0/24"}},
		{spec: "not-subnet:10.0.0.0/24", want: wifi.Condition{Type: wifi.CondSubnet, Negate: true, Subnet: "10.0.0.0/24"}},
		{spec: "mac:B0:38:6C:54:8B:AB", want: wifi.Condition{Type: wifi.CondNetwork, GatewayMAC: "b0:38:6c:54:8b:ab"}},
		{spec: "not-mac:B0:38:6C:54:8B:AB", want: wifi.Condition{Type: wifi.CondNetwork, Negate: true, GatewayMAC: "b0:38:6c:54:8b:ab"}},
		{spec: "else", want: wifi.Condition{Type: wifi.CondNoneMatch}},
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
		c    wifi.Condition
		want string
	}{
		{wifi.Condition{Type: wifi.CondSSID, SSID: "A"}, "ssid=A"},
		{wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "A"}, "ssid!=A"},
		{wifi.Condition{Type: wifi.CondSubnet, Subnet: "10.0.0.0/8"}, "subnet=10.0.0.0/8"},
		{wifi.Condition{Type: wifi.CondSubnet, Negate: true, Subnet: "10.0.0.0/8"}, "subnet!=10.0.0.0/8"},
		{wifi.Condition{Type: wifi.CondNetwork, GatewayMAC: "aa:bb:cc:dd:ee:ff"}, "network(mac)=aa:bb:cc:dd:ee:ff"},
		{wifi.Condition{Type: wifi.CondNetwork, Negate: true, GatewayMAC: "aa:bb:cc:dd:ee:ff"}, "network(mac)!=aa:bb:cc:dd:ee:ff"},
		{wifi.Condition{Type: wifi.CondNoneMatch}, "otherwise"},
	}
	for _, tc := range cases {
		if got := formatCondition(tc.c); got != tc.want {
			t.Errorf("%+v: got %q want %q", tc.c, got, tc.want)
		}
	}
}
