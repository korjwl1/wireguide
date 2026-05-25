//go:build darwin

package tunnel

import "testing"

func TestParseNetstatIB(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		iface     string
		wantIn    uint64
		wantOut   uint64
		wantOK    bool
	}{
		{
			name: "single interface, single row",
			output: `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
utun4      1380  <Link#27>                            123     0       4567       89     0       1234     0
`,
			iface:   "utun4",
			wantIn:  4567,
			wantOut: 1234,
			wantOK:  true,
		},
		{
			name: "multi-row interface (Link#, then per-address aliases) — picks Link# (first)",
			output: `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0        1500  <Link#11>     56:95:26:8e:95:57    1732438     0 1858822057   680956     0  668485696     0
en0        1500  fe80::1c01:   fe80:b::1c01:bc4:    1732438     - 1858822057   680956     -  668485696     -
en0        1500  192.168.1     192.168.1.65          1732438     - 1858822057   680956     -  668485696     -
`,
			iface:   "en0",
			wantIn:  1858822057,
			wantOut: 668485696,
			wantOK:  true,
		},
		{
			name: "with trailing Drop column (newer macOS)",
			output: `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll Drop
utun4      1380  <Link#27>                            10      0        100       20     0        200     0    0
`,
			iface:   "utun4",
			wantIn:  100,
			wantOut: 200,
			wantOK:  true,
		},
		{
			name:   "empty output",
			output: ``,
			iface:  "utun4",
			wantOK: false,
		},
		{
			name: "header without Ibytes/Obytes columns (corrupted layout)",
			output: `Name       Mtu   Network       Address            Ipkts Ierrs     Opkts Oerrs Coll
utun4      1380  <Link#27>                            10    0           20     0    0
`,
			iface:  "utun4",
			wantOK: false,
		},
		{
			name: "interface name doesn't match — should not return another iface's data",
			output: `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0        1500  <Link#11>     56:95:26:8e:95:57    1732438     0 1858822057   680956     0  668485696     0
`,
			iface:  "utun4",
			wantOK: false,
		},
		{
			name: "non-numeric bytes (kernel didn't fill row) — skipped",
			output: `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
utun4      1380  <Link#27>                            -       -          -        -     -          -     -
`,
			iface:  "utun4",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotIn, gotOut, gotOK := parseNetstatIB([]byte(tc.output), tc.iface)
			if gotOK != tc.wantOK {
				t.Fatalf("ok: got %v, want %v", gotOK, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if gotIn != tc.wantIn {
				t.Errorf("in: got %d, want %d", gotIn, tc.wantIn)
			}
			if gotOut != tc.wantOut {
				t.Errorf("out: got %d, want %d", gotOut, tc.wantOut)
			}
		})
	}
}
