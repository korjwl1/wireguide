package reconnect

import "testing"

func TestOnlineFromPrimaries(t *testing.T) {
	cases := []struct {
		name       string
		v4, v6     string
		ok6        bool
		wantOnline bool
	}{
		{"ipv4 only", "en0", "", true, true},
		{"ipv6 only", "", "en0", true, true},
		{"dual stack", "en0", "en0", true, true},
		{"neither key", "", "", true, false},
		{"ipv6 read failed, no ipv4", "", "", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := onlineFromPrimaries(c.v4, c.v6, c.ok6); got != c.wantOnline {
				t.Fatalf("onlineFromPrimaries(%q, %q, %v) = %v, want %v", c.v4, c.v6, c.ok6, got, c.wantOnline)
			}
		})
	}
}
