//go:build darwin

package network

// SubscribeNetworkChange registers cb to fire on physical network
// changes (route table / interface changes), reusing the same
// `route -n monitor` subprocess the tunnel route-reapply path uses.
// Keyed so a later Unsubscribe removes exactly this subscriber. The
// helper uses this to re-evaluate subnet-based Automation rules the
// instant the underlay changes — zero added runtime cost over the
// monitor that already runs.
func SubscribeNetworkChange(key string, cb func()) {
	rmMgr.Subscribe(key, cb)
}

// UnsubscribeNetworkChange removes a subscriber registered via
// SubscribeNetworkChange.
func UnsubscribeNetworkChange(key string) {
	rmMgr.Unsubscribe(key)
}
