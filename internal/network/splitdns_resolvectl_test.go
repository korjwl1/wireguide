package network

import (
	"reflect"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestResolvectlSplitCommands(t *testing.T) {
	p := domain.ParseDNSEntries([]string{"192.168.1.1", "~intranet.example", "~1.168.192.in-addr.arpa", "corp.example"})
	got := resolvectlSplitCommands("wg0", p)
	want := [][]string{
		{"dns", "wg0", "192.168.1.1"},
		{"domain", "wg0", "~intranet.example", "~1.168.192.in-addr.arpa", "corp.example"},
		{"default-route", "wg0", "no"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	for _, c := range got {
		if strings.Contains(strings.Join(c, " "), "~.") {
			t.Fatalf("catch-all routing domain must not be used in split mode: %v", c)
		}
	}
}
