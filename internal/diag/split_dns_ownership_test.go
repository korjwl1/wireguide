package diag

import (
	"github.com/korjwl1/wireguide/internal/domain"
	"testing"
)

func TestSplitDNSDiagnosticPreservesDomainOwnership(t *testing.T) {
	plans := []domain.DNSEntries{
		domain.ParseDNSEntries([]string{"10.1.0.53", "~a.example"}),
		domain.ParseDNSEntries([]string{"10.2.0.53", "~b.example"}),
	}
	actual := []scutilResolver{{Domain: "a.example", Nameservers: []string{"10.2.0.53"}}, {Domain: "b.example", Nameservers: []string{"10.2.0.53"}}}
	missing := evaluateSplitDNSPlans(actual, plans)
	if len(missing) != 1 || missing[0] != "a.example" {
		t.Fatalf("wrong ownership accepted: %v", missing)
	}
	actual[0].Nameservers = []string{"10.1.0.53", "10.2.0.53"}
	if len(evaluateSplitDNSPlans(actual, plans)) != 1 {
		t.Fatal("unexpected extra resolver accepted")
	}
	actual[0].Nameservers = []string{"10.1.0.53"}
	if len(evaluateSplitDNSPlans(actual, plans)) != 0 {
		t.Fatal("valid independent split resolvers rejected")
	}
}
