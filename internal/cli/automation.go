package cli

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func cmdAutomation(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "rules", "list":
			return automationRules(args[1:])
		case "add":
			return automationAdd(args[1:])
		case "rm", "remove", "delete":
			return automationRm(args[1:])
		case "show", "status":
			// fall through to the live preview below
		default:
			fmt.Fprintf(os.Stderr, "unknown automation subcommand %q (try: rules, add, rm)\n", args[0])
			return 2
		}
	}
	return automationPreview()
}

func automationPreview() int {
	c, err := dialHelper()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	var resp ipc.AutomationPreviewResponse
	if err := c.Call(ipc.MethodAutomationPreview, nil, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	ssid := resp.SSID
	if ssid == "" {
		ssid = "(none)"
	}
	gwMAC := resp.GatewayMAC
	if gwMAC == "" {
		gwMAC = "(unknown)"
	}
	fmt.Printf("network context: ssid=%s  gateway-mac=%s  physical-ips=%v\n", ssid, gwMAC, resp.PhysicalIPs)
	iface := resp.PrimaryIface
	if iface == "" {
		iface = "(unknown)"
	}
	settle := "settled"
	if !resp.Settled {
		settle = fmt.Sprintf("settling, %ds left (negated rules hold)", resp.SettleRemainingSec)
	}
	fmt.Printf("                 primary=%s wifi=%v online=%v  %s\n", iface, resp.PrimaryIsWiFi, resp.Online, settle)
	if len(resp.Tunnels) == 0 {
		fmt.Println("no tunnels have automation rules")
		return 0
	}
	for _, tdec := range resp.Tunnels {
		state := "down"
		if tdec.Active {
			state = "up"
		}
		note := ""
		switch {
		case tdec.Latched:
			note = "  (manual override: automation paused until the network changes)"
		case tdec.Held:
			note = "  (a negated rule can't be decided yet; leaving the tunnel alone)"
		}
		fmt.Printf("  %-28s rules=%d  currently=%s  decision=%s%s\n",
			tdec.Name, tdec.RuleCount, state, tdec.Decision, note)
	}
	return 0
}

func settingsStore() (*storage.SettingsStore, error) {
	paths, err := userPaths()
	if err != nil {
		return nil, err
	}
	if err := paths.EnsureDirs(); err != nil {
		return nil, err
	}
	return storage.NewSettingsStore(paths.ConfigDir), nil
}

// loadSettingsWithAutomation loads settings and ensures Automation is
// populated (migrating legacy rules once) so edits build on the current
// effective rule set.
func loadSettingsWithAutomation() (*storage.SettingsStore, *storage.Settings, error) {
	ss, err := settingsStore()
	if err != nil {
		return nil, nil, err
	}
	s, err := ss.Load()
	if err != nil {
		return nil, nil, err
	}
	s.EnsureAutomation()
	if s.Automation.PerTunnel == nil {
		s.Automation.PerTunnel = map[string][]automation.Rule{}
	}
	return ss, s, nil
}

func formatCondition(c automation.Condition) string {
	op := "="
	if c.Negate {
		op = "!="
	}
	switch c.Type {
	case automation.CondSSID:
		return "ssid" + op + c.SSID
	case automation.CondSubnet:
		return "subnet" + op + c.Subnet
	case automation.CondNetwork:
		return "network(mac)" + op + c.GatewayMAC
	case automation.CondNoneMatch:
		return "otherwise"
	}
	return c.Type
}

func automationRules(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl automation rules <tunnel>")
		return 2
	}
	name := args[0]
	_, s, err := loadSettingsWithAutomation()
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	rules := s.Automation.PerTunnel[name]
	if len(rules) == 0 {
		fmt.Printf("%s has no automation rules\n", name)
		return 0
	}
	fmt.Printf("%s (top rule wins on conflict):\n", name)
	for i, r := range rules {
		fmt.Printf("  %d. %-10s when %s\n", i+1, r.Do, formatCondition(r.When))
	}
	return 0
}

// parseCondition turns "ssid:home" / "subnet:10.0.0.0/24" / "mac:.." /
// "else" into a automation.Condition. A "not-" prefix on ssid/subnet/mac
// ("not-ssid:home") negates it: it matches only when the value is known
// and different (a blank SSID mid-roam holds instead of matching).
// "not-else" is rejected. Returns an error for malformed values.
func parseCondition(spec string) (automation.Condition, error) {
	spec = strings.TrimSpace(spec)
	if spec == "else" || spec == "otherwise" || spec == "none" {
		return automation.Condition{Type: automation.CondNoneMatch}, nil
	}
	if spec == "not-else" || spec == "not-otherwise" || spec == "not-none" {
		return automation.Condition{}, fmt.Errorf("'else' cannot be negated")
	}
	kind, val, ok := strings.Cut(spec, ":")
	if !ok || strings.TrimSpace(val) == "" {
		return automation.Condition{}, fmt.Errorf("condition %q must be ssid:<name>, subnet:<CIDR>, mac:<MAC> or else (prefix not- to negate)", spec)
	}
	negate := false
	if rest, found := strings.CutPrefix(kind, "not-"); found {
		negate = true
		kind = rest
	}
	val = strings.TrimSpace(val)
	switch kind {
	case "ssid":
		return automation.Condition{Type: automation.CondSSID, Negate: negate, SSID: val}, nil
	case "subnet":
		if _, _, err := net.ParseCIDR(val); err != nil {
			return automation.Condition{}, fmt.Errorf("subnet %q is not a valid CIDR (e.g. 192.168.0.0/24)", val)
		}
		return automation.Condition{Type: automation.CondSubnet, Negate: negate, Subnet: val}, nil
	case "mac":
		hex := strings.Map(func(r rune) rune {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				return r
			}
			return -1
		}, val)
		if len(hex) != 12 {
			return automation.Condition{}, fmt.Errorf("mac %q is not a valid MAC address", val)
		}
		return automation.Condition{Type: automation.CondNetwork, Negate: negate, GatewayMAC: strings.ToLower(val)}, nil
	default:
		return automation.Condition{}, fmt.Errorf("unknown condition kind %q (use ssid/subnet/mac/else, or not-ssid/not-subnet/not-mac)", kind)
	}
}

func automationAdd(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl automation add <tunnel> <connect|disconnect> <cond>")
		return 2
	}
	name, action, spec := args[0], args[1], args[2]
	if action != "connect" && action != "disconnect" {
		fmt.Fprintf(os.Stderr, "action must be 'connect' or 'disconnect', got %q\n", action)
		return 2
	}
	cond, err := parseCondition(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 2
	}
	store, err := tunnelStore()
	if err == nil && !store.Exists(name) {
		fmt.Fprintf(os.Stderr, "warning: no tunnel named %q — the rule is saved but won't do anything until it exists\n", name)
	}
	ss, err := settingsStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	ruleNum := 0
	err = ss.Update(func(s *storage.Settings) error {
		s.EnsureAutomation()
		if s.Automation.PerTunnel == nil {
			s.Automation.PerTunnel = map[string][]automation.Rule{}
		}
		s.Automation.PerTunnel[name] = append(s.Automation.PerTunnel[name], automation.Rule{When: cond, Do: automation.Action(action)})
		ruleNum = len(s.Automation.PerTunnel[name])
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation: save failed:", err)
		return 1
	}
	fmt.Printf("added rule %d for %s: %s when %s\n", ruleNum, name, action, formatCondition(cond))
	return 0
}

func automationRm(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl automation rm <tunnel> <rule-number>")
		return 2
	}
	name := args[0]
	idx, err := strconv.Atoi(args[1])
	if err != nil || idx < 1 {
		fmt.Fprintf(os.Stderr, "rule number must be a positive integer (see 'automation rules %s')\n", name)
		return 2
	}
	ss, err := settingsStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation:", err)
		return 1
	}
	var removed automation.Rule
	tooFew := -1 // set to the actual rule count if idx is out of range
	err = ss.Update(func(s *storage.Settings) error {
		s.EnsureAutomation()
		rules := s.Automation.PerTunnel[name]
		if idx > len(rules) {
			tooFew = len(rules)
			return fmt.Errorf("rule number out of range")
		}
		removed = rules[idx-1]
		s.Automation.PerTunnel[name] = append(rules[:idx-1:idx-1], rules[idx:]...)
		if len(s.Automation.PerTunnel[name]) == 0 {
			delete(s.Automation.PerTunnel, name)
		}
		return nil
	})
	if tooFew >= 0 {
		fmt.Fprintf(os.Stderr, "%s has only %d rule(s)\n", name, tooFew)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "automation: save failed:", err)
		return 1
	}
	fmt.Printf("removed rule %d for %s: %s when %s\n", idx, name, removed.Do, formatCondition(removed.When))
	return 0
}
