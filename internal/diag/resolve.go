package diag

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// ProbeTimeout bounds every Resolve probe. It runs on user request and must
// never hang the caller.
const ProbeTimeout = 3 * time.Second

// ResolveResult is the outcome of resolving one name through the system
// resolver path (getaddrinfo), i.e. the same path browsers and most apps
// use. Unlike dig / nslookup / the pure-Go resolver, that path honours
// macOS supplemental ("~domain") resolvers.
type ResolveResult struct {
	Name        string   `json:"name"`
	Addrs       []string `json:"addrs,omitempty"`
	Resolver    string   `json:"resolver,omitempty"`     // nameserver IP chosen by the system, when known
	MatchDomain string   `json:"match_domain,omitempty"` // supplemental resolver domain that matched, if any
	NXDomain    bool     `json:"nxdomain,omitempty"`
	TimedOut    bool     `json:"timed_out,omitempty"`
	DurationMs  float64  `json:"duration_ms"`
	Error       string   `json:"error,omitempty"`
	ErrorCode   string   `json:"error_code,omitempty"` // stable id ("invalid_name") for localised text
}

// resolveDeps are the seams for tests.
type resolveDeps struct {
	lookup func(ctx context.Context, name string) ([]string, error)
	scutil func(ctx context.Context) (string, error)
}

func defaultResolveDeps() resolveDeps {
	return resolveDeps{
		// PreferGo=false selects the platform resolver (getaddrinfo via
		// cgo on macOS), the only Go path that sees supplemental resolvers.
		lookup: func(ctx context.Context, name string) ([]string, error) {
			r := &net.Resolver{PreferGo: false}
			return r.LookupHost(ctx, name)
		},
		scutil: func(ctx context.Context) (string, error) {
			if runtime.GOOS != "darwin" {
				return "", errors.New("scutil unavailable")
			}
			cmd := exec.CommandContext(ctx, "scutil", "--dns")
			sysexec.Hide(cmd)
			out, err := cmd.Output()
			return string(out), err
		},
	}
}

// Resolve resolves name via the system resolver with a ProbeTimeout budget
// and, where the platform allows (macOS), reports which resolver the system
// would use for that name.
func Resolve(ctx context.Context, name string) *ResolveResult {
	return resolveWith(ctx, defaultResolveDeps(), name)
}

func validHostname(name string) bool {
	if name == "" || len(name) > 253 || strings.ContainsAny(name, " \t\r\n/\\") {
		return false
	}
	return !strings.HasPrefix(name, "-")
}

func resolveWith(ctx context.Context, d resolveDeps, name string) *ResolveResult {
	name = strings.TrimSpace(name)
	res := &ResolveResult{Name: name}
	if !validHostname(name) {
		res.Error = "invalid host name"
		res.ErrorCode = "invalid_name"
		return res
	}
	lctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	start := time.Now()
	addrs, err := d.lookup(lctx, name)
	res.DurationMs = float64(time.Since(start).Microseconds()) / 1000
	cancel()
	if err != nil {
		var dnsErr *net.DNSError
		switch {
		case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			res.NXDomain = true
			res.Error = "NXDOMAIN"
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &dnsErr) && dnsErr.IsTimeout):
			res.TimedOut = true
			res.Error = fmt.Sprintf("no answer within %ds", int(ProbeTimeout/time.Second))
		default:
			res.Error = err.Error()
		}
	} else {
		res.Addrs = addrs
	}
	sctx, scancel := context.WithTimeout(ctx, 2*time.Second)
	defer scancel()
	if out, serr := d.scutil(sctx); serr == nil {
		if b, ok := pickResolver(parseScutilDNS(out), name); ok && len(b.Nameservers) > 0 {
			res.Resolver = b.Nameservers[0]
			res.MatchDomain = b.Domain
		}
	}
	return res
}

// pickResolver mirrors how the macOS resolver chooses a nameserver set for a
// name: the unscoped resolver with the longest matching domain, else the
// first domain-less (default) resolver. Pure.
func pickResolver(blocks []scutilResolver, name string) (scutilResolver, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	var best scutilResolver
	found := false
	for _, b := range blocks {
		if b.Scoped || b.Domain == "" || len(b.Nameservers) == 0 {
			continue
		}
		if name == b.Domain || strings.HasSuffix(name, "."+b.Domain) {
			if !found || len(b.Domain) > len(best.Domain) {
				best, found = b, true
			}
		}
	}
	if found {
		return best, true
	}
	for _, b := range blocks {
		if !b.Scoped && b.Domain == "" && len(b.Nameservers) > 0 {
			return b, true
		}
	}
	return scutilResolver{}, false
}
