package diag

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"
)

type resolvedLink struct {
	Servers      []string
	Domains      []string
	DefaultRoute bool
}

type resolvedSnapshot struct {
	Global        []string
	GlobalDomains []string
	Fallback      []string
	Links         []resolvedLink
}

// Read the routing policy, not /run/systemd/resolve/resolv.conf's flattened
// list: domain-only VPN resolvers do not handle arbitrary global names.
func (s resolvedSnapshot) defaultResolvers() []string {
	root := len(s.Global) > 0 && slices.Contains(s.GlobalDomains, ".")
	for _, link := range s.Links {
		root = root || (len(link.Servers) > 0 && slices.Contains(link.Domains, "."))
	}
	var out []string
	if !root || slices.Contains(s.GlobalDomains, ".") {
		out = append(out, s.Global...)
	}
	configured := len(s.Global)
	for _, link := range s.Links {
		configured += len(link.Servers)
		if (root && slices.Contains(link.Domains, ".")) || (!root && link.DefaultRoute) {
			out = append(out, link.Servers...)
		}
	}
	if configured == 0 {
		out = append(out, s.Fallback...)
	}
	return uniqueResolvers(out)
}

func uniqueResolvers(servers []string) []string {
	seen := make(map[string]bool, len(servers))
	out := make([]string, 0, len(servers))
	for _, server := range servers {
		if !seen[server] {
			seen[server] = true
			out = append(out, server)
		}
	}
	return out
}

func linuxResolverUpstreams(r io.Reader, readResolved func() (resolvedSnapshot, error)) ([]string, error) {
	servers, err := parseResolvConf(bufio.NewScanner(r))
	if err != nil {
		return nil, err
	}
	var out []string
	resolved := false
	for _, server := range servers {
		ip := net.ParseIP(server)
		if ip == nil {
			return nil, fmt.Errorf("invalid system DNS address %q", server)
		}
		if !ip.IsLoopback() {
			out = append(out, server)
			continue
		}
		if server != "127.0.0.53" && server != "127.0.0.54" {
			return nil, fmt.Errorf("cannot attribute upstream DNS behind local resolver %s", server)
		}
		if resolved {
			continue
		}
		snapshot, err := readResolved()
		if err != nil {
			return nil, fmt.Errorf("cannot inspect systemd-resolved upstream DNS: %w", err)
		}
		upstreams := snapshot.defaultResolvers()
		if len(upstreams) == 0 {
			return nil, fmt.Errorf("no default upstream DNS found behind systemd-resolved")
		}
		out = append(out, upstreams...)
		resolved = true
	}
	return uniqueResolvers(out), nil
}

type resolvedDNSAddress struct {
	Index   int32
	Family  int32
	Address []byte
}

type resolvedLinkAddress struct {
	Family  int32
	Address []byte
}

type resolvedDomain struct {
	Name        string
	RoutingOnly bool
}

type resolvedGlobalDomain struct {
	Index       int32
	Name        string
	RoutingOnly bool
}

const resolvedService = "org.freedesktop.resolve1"

func readResolvedSnapshot() (resolvedSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return resolvedSnapshot{}, err
	}
	defer conn.Close()
	return resolvedSnapshotFromBus(ctx, conn)
}

func resolvedProperties(ctx context.Context, conn *dbus.Conn, path dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	var props map[string]dbus.Variant
	err := conn.Object(resolvedService, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, iface).Store(&props)
	return props, err
}

func resolvedProperty(props map[string]dbus.Variant, name string, value any) error {
	v, ok := props[name]
	if !ok {
		return fmt.Errorf("systemd-resolved omitted %s", name)
	}
	return dbus.Store([]any{v.Value()}, value)
}

func resolvedAddress(family int32, address []byte, zone string) (string, error) {
	if (family != 2 || len(address) != 4) && (family != 10 || len(address) != 16) {
		return "", fmt.Errorf("invalid resolved DNS address family=%d length=%d", family, len(address))
	}
	ip := net.IP(address)
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return "", fmt.Errorf("cannot attribute upstream DNS behind %s", ip)
	}
	if ip.IsLinkLocalUnicast() && ip.To4() == nil {
		if zone == "" {
			return "", fmt.Errorf("resolved link-local DNS lacks an interface")
		}
		return ip.String() + "%" + zone, nil
	}
	return ip.String(), nil
}

func resolvedSnapshotFromBus(ctx context.Context, conn *dbus.Conn) (resolvedSnapshot, error) {
	var snapshot resolvedSnapshot
	linkIndices := make(map[int32]bool)
	manager := dbus.ObjectPath("/org/freedesktop/resolve1")
	props, err := resolvedProperties(ctx, conn, manager, resolvedService+".Manager")
	if err != nil {
		return snapshot, err
	}
	for _, item := range []struct {
		name string
		dest *[]string
	}{{"DNS", &snapshot.Global}, {"FallbackDNS", &snapshot.Fallback}} {
		var entries []resolvedDNSAddress
		if err := resolvedProperty(props, item.name, &entries); err != nil {
			return snapshot, err
		}
		for _, entry := range entries {
			if entry.Index != 0 {
				if item.name == "DNS" {
					linkIndices[entry.Index] = true
				}
				continue
			}
			ip, err := resolvedAddress(entry.Family, entry.Address, "")
			if err != nil {
				return snapshot, err
			}
			*item.dest = append(*item.dest, ip)
		}
	}
	var domains []resolvedGlobalDomain
	if err := resolvedProperty(props, "Domains", &domains); err != nil {
		return snapshot, err
	}
	for _, d := range domains {
		if d.Index == 0 {
			snapshot.GlobalDomains = append(snapshot.GlobalDomains, d.Name)
		}
	}
	indices := make([]int, 0, len(linkIndices))
	for index := range linkIndices {
		indices = append(indices, int(index))
	}
	sort.Ints(indices)
	for _, index := range indices {
		var path dbus.ObjectPath
		if err := conn.Object(resolvedService, manager).CallWithContext(ctx, resolvedService+".Manager.GetLink", 0, int32(index)).Store(&path); err != nil {
			return snapshot, err
		}
		props, err := resolvedProperties(ctx, conn, path, resolvedService+".Link")
		if err != nil {
			return snapshot, err
		}
		var addresses []resolvedLinkAddress
		var domains []resolvedDomain
		var current resolvedLink
		if err := resolvedProperty(props, "DNS", &addresses); err != nil {
			return snapshot, err
		}
		if err := resolvedProperty(props, "Domains", &domains); err != nil {
			return snapshot, err
		}
		if err := resolvedProperty(props, "DefaultRoute", &current.DefaultRoute); err != nil {
			return snapshot, err
		}
		for _, entry := range addresses {
			ip, err := resolvedAddress(entry.Family, entry.Address, strconv.Itoa(index))
			if err != nil {
				return snapshot, err
			}
			current.Servers = append(current.Servers, ip)
		}
		for _, d := range domains {
			current.Domains = append(current.Domains, d.Name)
		}
		snapshot.Links = append(snapshot.Links, current)
	}
	return snapshot, nil
}
