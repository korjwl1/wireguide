package app

import "testing"

func TestResolveHostRejectsInvalidName(t *testing.T) {
	r := (&TunnelService{}).ResolveHost("bad name")
	if r.ErrorCode != "invalid_name" || r.Error == "" {
		t.Fatalf("%+v", r)
	}
}
