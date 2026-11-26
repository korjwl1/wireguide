package cli

import (
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/diag"
)

func TestFormatDomainCheck(t *testing.T) {
	got := []string{
		formatDomainCheck(diag.DomainCheck{Domain: "corp.example", Resolver: "10.66.66.1", Registered: true}),
		formatDomainCheck(diag.DomainCheck{Domain: "corp.example", Resolver: "192.168.50.1"}),
		formatDomainCheck(diag.DomainCheck{Domain: "lan.example", Search: true}),
	}
	want := []string{
		"domain ~corp.example -> 10.66.66.1",
		"domain ~corp.example -> 192.168.50.1 (not this tunnel's DNS server)",
		"domain lan.example: no supplemental resolver",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
}
