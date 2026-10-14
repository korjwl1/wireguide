package wifi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNegationDowngradeCannotRunInverseOrFallback(t *testing.T) {
	a := Automation{PerTunnel: map[string][]Rule{
		"new": {{When: Condition{Type: CondSSID, SSID: "Home", Negate: true}, Do: ActionConnect}, {When: Condition{Type: CondNoneMatch}, Do: ActionDisconnect}},
		"old": {{When: Condition{Type: CondSSID, SSID: "Home"}, Do: ActionDisconnect}},
	}}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	// Same shape as the old engine; unknown JSON fields are ignored.
	var old struct {
		PerTunnel map[string][]Rule `json:"per_tunnel_rules"`
	}
	if err := json.Unmarshal(b, &old); err != nil {
		t.Fatal(err)
	}
	if _, ok := old.PerTunnel["new"]; ok {
		t.Fatal("old engine must not see any part of a negated rule list")
	}
	if len(old.PerTunnel["old"]) != 1 {
		t.Fatal("positive rules lost compatibility")
	}
	var roundtrip Automation
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, roundtrip) {
		t.Fatalf("roundtrip: %+v", roundtrip)
	}
}
