package diag

import "testing"

func TestDNSModeOf(t *testing.T) {
	cases := []struct {
		in     []string
		mode   string
		status string
	}{
		{[]string{"1.1.1.1"}, DNSModeGlobal, "global"},
		{[]string{"192.168.1.1", "~intranet.example", "~corp.lan"}, DNSModeSplit, "split(intranet.example,corp.lan)"},
		{nil, DNSModeNone, "none"},
		{[]string{"example.com"}, DNSModeSearch, "search"},
	}
	for _, c := range cases {
		m := DNSModeOf(c.in)
		if m.Mode != c.mode || m.StatusString() != c.status {
			t.Errorf("%v -> %+v %q", c.in, m, m.StatusString())
		}
	}
}
