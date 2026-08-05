//go:build linux

package network

import (
	"reflect"
	"testing"
)

func TestSplitRouteDeleteArgsSelectsAddressFamilyAndTable(t *testing.T) {
	tests := []struct {
		name, cidr, table string
		want              []string
	}{
		{"ipv4 main", "10.0.0.0/24", "", []string{"route", "delete", "10.0.0.0/24", "dev", "wg0"}},
		{"ipv6 main", "fd00::/64", "", []string{"-6", "route", "delete", "fd00::/64", "dev", "wg0"}},
		{"ipv6 custom table", "2001:db8::/32", "51821", []string{"-6", "route", "delete", "2001:db8::/32", "dev", "wg0", "table", "51821"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitRouteDeleteArgs("wg0", tt.cidr, tt.table); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("splitRouteDeleteArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTableOffPersistsAcrossRemovalAndCrashRecovery(t *testing.T) {
	mgr := &LinuxManager{}
	if err := mgr.AddRoutes("not-a-real-interface", []string{"10.255.254.99/32"}, false, nil, "off", ""); err != nil {
		t.Fatalf("AddRoutes(Table=off): %v", err)
	}
	if !mgr.tableSet || mgr.table != -1 {
		t.Fatalf("Table=off state = tableSet:%v table:%d", mgr.tableSet, mgr.table)
	}
	// This would invoke `ip route delete` and merely log the resulting error
	// if the disabled state were forgotten.
	if err := mgr.RemoveRoutes("not-a-real-interface", []string{"10.255.254.99/32"}, false); err != nil {
		t.Fatalf("RemoveRoutes(Table=off): %v", err)
	}

	recovered := &LinuxManager{}
	recovered.RestoreRoutingState("off", "")
	if !recovered.tableSet || recovered.table != -1 {
		t.Fatalf("restored Table=off state = tableSet:%v table:%d", recovered.tableSet, recovered.table)
	}
}

func TestEndpointThrowRouteDeleteArgs(t *testing.T) {
	tests := []struct {
		host, table string
		want        []string
	}{
		{"203.0.113.7/32", "51888", []string{"route", "delete", "throw", "203.0.113.7/32", "table", "51888"}},
		{"2001:db8::7/128", "51889", []string{"-6", "route", "delete", "throw", "2001:db8::7/128", "table", "51889"}},
	}
	for _, tt := range tests {
		if got := endpointThrowRouteDeleteArgs(tt.host, tt.table); !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("endpointThrowRouteDeleteArgs(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}

	mgr := &LinuxManager{endpointThrowRoutes: []string{"203.0.113.7/32"}}
	got := mgr.InstalledEndpointRoutes()
	got[0] = "mutated"
	if mgr.endpointThrowRoutes[0] != "203.0.113.7/32" {
		t.Fatal("InstalledEndpointRoutes returned aliased storage")
	}
}
