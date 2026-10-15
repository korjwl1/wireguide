package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func parseOnOff(v string) (bool, bool) {
	switch strings.ToLower(v) {
	case "on", "true", "1", "yes", "enable", "enabled":
		return true, true
	case "off", "false", "0", "no", "disable", "disabled":
		return false, true
	}
	return false, false
}

func cmdSet(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wireguide ctl set <killswitch|dns-protection|healthcheck|pin-interface|loglevel> <value>")
		return 2
	}
	setting, value := strings.ToLower(args[0]), args[1]

	ss, err := settingsStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "set:", err)
		return 1
	}

	// applyIPC persists-then-applies: the setting is already saved to
	// config.json, so a helper that isn't running just means "applies on
	// next launch" (exit 0 — nothing is live to be wrong). But if the
	// helper IS running and the live apply fails, we return nonzero: the
	// value is on disk yet NOT actually in effect, and a script that just
	// ran `set killswitch on` must not believe traffic is being blocked
	// when it isn't (issue #10).
	liveRC := 0
	applyIPC := func(method string, params interface{}) int {
		c, derr := dialHelper()
		if derr != nil {
			fmt.Println("(helper not running — saved; will take effect when the app starts)")
			return 0
		}
		defer c.Close()
		if err := c.Call(method, params, nil); err != nil {
			fmt.Fprintln(os.Stderr, "error: saved to config but live apply failed:", err)
			return 1
		}
		return 0
	}

	switch setting {
	case "killswitch", "kill-switch", "kill_switch":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.KillSwitch = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: v})
	case "dns-protection", "dnsprotection", "dns_protection":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.DNSProtection = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		// The helper derives the servers from every connected tunnel (#48).
		liveRC = applyIPC(ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{Enabled: v})
	case "healthcheck", "health-check", "health_check":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.HealthCheck = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetHealthCheck, ipc.SetHealthCheckRequest{Enabled: v})
	case "pin-interface", "pininterface", "pin_interface":
		v, ok := parseOnOff(value)
		if !ok {
			fmt.Fprintln(os.Stderr, "value must be on/off")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.PinInterface = v; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetPinInterface, ipc.SetPinInterfaceRequest{Enabled: v})
	case "loglevel", "log-level", "log_level":
		lvl := strings.ToLower(value)
		switch lvl {
		case "debug", "info", "warn", "error":
		default:
			fmt.Fprintln(os.Stderr, "loglevel must be one of: debug, info, warn, error")
			return 2
		}
		if err := ss.Update(func(s *storage.Settings) error { s.LogLevel = lvl; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		liveRC = applyIPC(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: lvl})
	default:
		fmt.Fprintf(os.Stderr, "unknown setting %q (killswitch, dns-protection, healthcheck, pin-interface, loglevel)\n", setting)
		return 2
	}
	if liveRC != 0 {
		// Persisted, but the running helper rejected the live apply — the
		// value is NOT in effect right now. Exit nonzero so scripts notice.
		return liveRC
	}
	fmt.Printf("%s = %s\n", setting, value)
	return 0
}
