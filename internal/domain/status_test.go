package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestConnectionStatusJSONHidesInternalFields ensures the time.Time fields
// used internally by the reconnect monitor are never serialized to the wire
// (they'd serialize verbosely and confuse the frontend). The frontend should
// only ever see the human-readable `last_handshake` string.
func TestConnectionStatusJSONHidesInternalFields(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cs := ConnectionStatus{
		State:             StateConnected,
		TunnelName:        "test",
		InterfaceName:     "utun5",
		ConnectedAt:       now,
		LastHandshakeTime: now,
		LastHandshake:     "5s",
		Duration:          "1m 0s",
		RxBytes:           1024,
		TxBytes:           2048,
	}

	data, err := json.Marshal(&cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)

	// Wire-safe fields are present.
	for _, want := range []string{
		`"state":"connected"`,
		`"tunnel_name":"test"`,
		`"interface_name":"utun5"`,
		`"last_handshake":"5s"`,
		`"duration":"1m 0s"`,
		`"rx_bytes":1024`,
		`"tx_bytes":2048`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing wire field %q in %s", want, s)
		}
	}

	// Internal time.Time fields are NOT serialized.
	for _, unwanted := range []string{
		"connected_at",
		"last_handshake_time",
		"2025-01-01",
	} {
		if strings.Contains(s, unwanted) {
			t.Errorf("unexpected internal field %q in %s", unwanted, s)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m 30s"},
		{2*time.Hour + 3*time.Minute + 4*time.Second, "2h 3m 4s"},
		{0, "0s"},
	}
	for _, tc := range cases {
		got := FormatDuration(tc.d)
		if got != tc.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
