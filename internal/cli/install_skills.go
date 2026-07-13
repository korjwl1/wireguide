package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// skillFrontmatter + skillBody make up the agent-facing reference for
// `wireguide ctl`. Claude Code gets it as a SKILL.md (frontmatter + body);
// AGENTS.md-based agents (Codex, OpenCode) get the body inside a managed
// block so re-running install-skills updates in place without touching the
// user's other instructions.
const skillFrontmatter = `---
name: wireguide-ctl
description: Control the WireGuide VPN client from the command line (the ` + "`wireguide ctl`" + ` command) — connect/disconnect WireGuard tunnels, edit per-tunnel Automation rules (connect/disconnect by Wi-Fi SSID, subnet, or gateway MAC), toggle kill switch / DNS protection, and run diagnostics. Use when the user wants to script WireGuide, manage tunnels from a terminal, or set up network-based auto-connect/disconnect.
---
`

const skillBody = "# Using `wireguide ctl`\n" + `
` + "`wireguide ctl`" + ` is the command-line interface to the WireGuide VPN client. It
talks to the already-running, already-elevated helper over a local socket
(like ` + "`tailscale`/`tailscaled`" + `), so it needs no per-command sudo and works the
same on macOS/Windows/Linux.

If ` + "`wireguide`" + ` is not on PATH, invoke the binary directly (on macOS a
Homebrew/manual install lives at
` + "`/Applications/WireGuide.app/Contents/MacOS/wireguide`" + `).

## Tunnels
` + "```" + `
wireguide ctl status                 # connection status
wireguide ctl list                   # list tunnels (● = connected)
wireguide ctl connect <name>         # connect a tunnel (warns on route conflicts)
wireguide ctl disconnect [name]      # disconnect one (or all)
wireguide ctl import <file> [name]   # import a .conf
wireguide ctl rename <old> <new>
wireguide ctl delete <name>          # disconnects first if active
` + "```" + `

## Automation — per-tunnel connect/disconnect rules
Rules are evaluated top to bottom; the FIRST matching rule wins (order is
priority). A rule can connect OR disconnect its tunnel based on the network
you're on. A tunnel with no rules is never auto-managed.
` + "```" + `
wireguide ctl automation                 # what the engine decides right now
wireguide ctl automation rules <name>    # list a tunnel's rules, in priority order
wireguide ctl automation add <name> <connect|disconnect> <cond>
    #   cond = ssid:<wifi-name>   subnet:<CIDR>   mac:<gateway-MAC>   else
wireguide ctl automation rm <name> <n>   # remove rule number <n> (from 'rules')
` + "```" + `
` + "`mac:`" + ` fingerprints a specific router (precise, works on Wi-Fi and Ethernet,
and tells apart two networks sharing a subnet like 192.168.0.0/24); separator
and case don't matter. Example — office VPN off on the office network, on
everywhere else:
` + "```" + `
wireguide ctl automation add work disconnect mac:b0:38:6c:54:8b:ab
wireguide ctl automation add work connect else
` + "```" + `

## Settings & diagnostics
` + "```" + `
wireguide ctl set killswitch <on|off>       # block non-VPN traffic if the tunnel drops
wireguide ctl set dns-protection <on|off>   # pin DNS to the tunnel
wireguide ctl set healthcheck <on|off>
wireguide ctl set pin-interface <on|off>
wireguide ctl set loglevel <debug|info|warn|error>
wireguide ctl dnsleak                        # check whether DNS leaks outside the tunnel
wireguide ctl routes                         # OS routing table
` + "```" + `
Every command exits non-zero on failure and prints a one-line error to stderr,
so it composes in scripts. ` + "`connect`/`disconnect`/`status`/`set`" + ` need the app
(or its helper) running; ` + "`list`/`import`/`rename`/`delete`" + ` and automation edits
work directly against the local files.
`

const (
	skillBeginMarker = "<!-- BEGIN wireguide ctl (managed by `wireguide ctl install-skills`) -->"
	skillEndMarker   = "<!-- END wireguide ctl -->"
)

type skillTarget struct {
	name string
	// detected reports whether this agent looks installed on the machine.
	detected func() bool
	// install writes the skill for this agent and returns the path written.
	install func() (string, error)
}

func home() string {
	h, _ := os.UserHomeDir()
	return h
}

func binOrDir(bin string, dirs ...string) func() bool {
	return func() bool {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
		for _, d := range dirs {
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				return true
			}
		}
		return false
	}
}

// writeClaudeSkill writes the proper Claude Code skill layout:
// ~/.claude/skills/wireguide-ctl/SKILL.md (frontmatter + body).
func writeClaudeSkill() (string, error) {
	dir := filepath.Join(home(), ".claude", "skills", "wireguide-ctl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(path, []byte(skillFrontmatter+skillBody), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// mergeAgentsFile inserts/updates the managed skill block in an AGENTS.md
// at path, leaving the user's other content untouched.
func mergeAgentsFile(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	block := skillBeginMarker + "\n" + skillBody + "\n" + skillEndMarker + "\n"

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	content := string(existing)
	if b := strings.Index(content, skillBeginMarker); b >= 0 {
		if e := strings.Index(content, skillEndMarker); e > b {
			// Replace the existing managed block in place.
			content = content[:b] + strings.TrimRight(block, "\n") + content[e+len(skillEndMarker):]
		} else {
			content += "\n" + block
		}
	} else {
		if content != "" && !strings.HasSuffix(content, "\n\n") {
			content = strings.TrimRight(content, "\n") + "\n\n"
		}
		content += block
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func skillTargets() []skillTarget {
	return []skillTarget{
		{
			name:     "claude",
			detected: binOrDir("claude", filepath.Join(home(), ".claude")),
			install:  writeClaudeSkill,
		},
		{
			name:     "codex",
			detected: binOrDir("codex", filepath.Join(home(), ".codex")),
			install:  func() (string, error) { return mergeAgentsFile(filepath.Join(home(), ".codex", "AGENTS.md")) },
		},
		{
			name:     "opencode",
			detected: binOrDir("opencode", filepath.Join(home(), ".config", "opencode")),
			install:  func() (string, error) { return mergeAgentsFile(filepath.Join(home(), ".config", "opencode", "AGENTS.md")) },
		},
		{
			name:     "hermes",
			detected: binOrDir("hermes", filepath.Join(home(), ".hermes")),
			install:  func() (string, error) { return mergeAgentsFile(filepath.Join(home(), ".hermes", "AGENTS.md")) },
		},
	}
}

// cmdInstallSkills installs the `wireguide ctl` usage skill into coding
// agents. By default it installs into every detected agent; `--target
// a,b` restricts to (and forces) the named ones.
func cmdInstallSkills(args []string) int {
	var only map[string]bool
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--target" && i+1 < len(args):
			only = map[string]bool{}
			for _, t := range strings.Split(args[i+1], ",") {
				only[strings.ToLower(strings.TrimSpace(t))] = true
			}
			i++
		case strings.HasPrefix(args[i], "--target="):
			only = map[string]bool{}
			for _, t := range strings.Split(strings.TrimPrefix(args[i], "--target="), ",") {
				only[strings.ToLower(strings.TrimSpace(t))] = true
			}
		default:
			fmt.Fprintf(os.Stderr, "install-skills: unexpected argument %q\n", args[i])
			fmt.Fprintln(os.Stderr, "usage: wireguide ctl install-skills [--target claude,codex,opencode,hermes]")
			return 2
		}
	}

	targets := skillTargets()
	// Validate --target names up front.
	if only != nil {
		known := map[string]bool{}
		for _, t := range targets {
			known[t.name] = true
		}
		for name := range only {
			if !known[name] {
				fmt.Fprintf(os.Stderr, "install-skills: unknown target %q (known: claude, codex, opencode, hermes)\n", name)
				return 2
			}
		}
	}

	installed, skipped := 0, 0
	for _, t := range targets {
		selected := false
		if only != nil {
			selected = only[t.name] // --target forces install even if not detected
		} else {
			selected = t.detected()
		}
		if !selected {
			continue
		}
		path, err := t.install()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-9s FAILED: %v\n", t.name, err)
			skipped++
			continue
		}
		fmt.Printf("  %-9s %s\n", t.name, path)
		installed++
	}

	if installed == 0 && skipped == 0 {
		fmt.Println("no coding agents detected (claude, codex, opencode, hermes).")
		fmt.Println("install one, or force with: wireguide ctl install-skills --target <name>")
		return 0
	}
	fmt.Printf("installed the `wireguide ctl` skill for %d agent(s).\n", installed)
	if skipped > 0 {
		return 1
	}
	return 0
}
