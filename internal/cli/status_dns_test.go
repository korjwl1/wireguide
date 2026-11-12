package cli

import (
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestFormatStatusRowDNS(t *testing.T) {
	r := domain.ConnectionStatus{TunnelName: "office-vpn", Duration: "1m", LastHandshake: "3s"}
	if got := formatStatusRow(r, "split(corp.example)"); !strings.HasSuffix(got, "  dns=split(corp.example)") {
		t.Errorf("split: %q", got)
	}
	if got := formatStatusRow(r, ""); strings.Contains(got, "dns=") {
		t.Errorf("unreadable config must omit dns=: %q", got)
	}
}
