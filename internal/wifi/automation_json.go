package wifi

import "encoding/json"

// MarshalJSON isolates entire rule lists containing negation from old readers.
// Older engines ignore negate fields, which would reverse a condition. Keeping
// even the fallback rules out of their map also prevents fallthrough actions.
func (a Automation) MarshalJSON() ([]byte, error) {
	legacy := make(map[string][]Rule)
	extended := make(map[string][]Rule)
	for name, rules := range a.PerTunnel {
		if HasNegated(rules) {
			extended[name] = rules
		} else {
			legacy[name] = rules
		}
	}
	return json.Marshal(struct {
		Legacy   map[string][]Rule `json:"per_tunnel_rules"`
		Extended map[string][]Rule `json:"per_tunnel_rules_v2,omitempty"`
	}{legacy, extended})
}

func (a *Automation) UnmarshalJSON(data []byte) error {
	var wire struct {
		Legacy   map[string][]Rule `json:"per_tunnel_rules"`
		Extended map[string][]Rule `json:"per_tunnel_rules_v2"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	a.PerTunnel = wire.Legacy
	if a.PerTunnel == nil {
		a.PerTunnel = make(map[string][]Rule)
	}
	for name, rules := range wire.Extended {
		a.PerTunnel[name] = rules
	}
	return nil
}
