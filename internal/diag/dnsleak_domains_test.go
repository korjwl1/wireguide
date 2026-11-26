package diag

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestSplitDomainChecks(t *testing.T) {
	plans := []domain.DNSEntries{domain.ParseDNSEntries([]string{"192.168.1.1", "~intranet.example", "~absent.lan"})}
	rows := splitDomainChecks(parseScutilDNS(scutilSample), plans)
	if len(rows) != 2 || rows[0].Domain != "absent.lan" || rows[0].Registered ||
		rows[1].Domain != "intranet.example" || !rows[1].Registered || rows[1].Resolver != "192.168.1.1" {
		t.Fatalf("%+v", rows)
	}
	// The leak test's missing list is derived from the same rows.
	if got := evaluateSplitDNSPlans(parseScutilDNS(scutilSample), plans); len(got) != 1 || got[0] != "absent.lan" {
		t.Fatalf("missing = %v", got)
	}
	// Wrong owner: the domain has a resolver, just not this tunnel's.
	rows = splitDomainChecks(parseScutilDNS(scutilSample), []domain.DNSEntries{domain.ParseDNSEntries([]string{"10.0.0.53", "~intranet.example", "lan"})})
	if rows[0].Domain != "intranet.example" || rows[0].Registered || rows[0].Resolver != "192.168.1.1" || rows[0].Search {
		t.Fatalf("mismatch: %+v", rows)
	}
	if rows[1].Domain != "lan" || !rows[1].Search || rows[1].Registered {
		t.Fatalf("search: %+v", rows)
	}
}

func TestEvaluateSplitDNSResultFillsDomains(t *testing.T) {
	plans := []domain.DNSEntries{domain.ParseDNSEntries([]string{"192.168.1.1", "~intranet.example", "~absent.lan"})}
	r := evaluateSplitDNSResult(&DNSLeakResult{SplitMode: true}, plans, parseScutilDNS(scutilSample))
	if len(r.Domains) != 2 || len(r.MissingMatchDomains) != 1 || r.MissingMatchDomains[0] != "absent.lan" {
		t.Fatalf("%+v", r)
	}
}
