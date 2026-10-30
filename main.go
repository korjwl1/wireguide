// WireGuide — single-binary WireGuard client.
//
// The same binary runs in two modes:
//   - default:  GUI mode, runs as the current user (Wails window + tray).
//   - --helper: privileged helper mode, runs as root/admin via IPC socket.
//
// main.go is intentionally tiny: flag dispatch only. GUI bootstrap lives in
// internal/gui, helper bootstrap lives in internal/helper.
package main

import (
	"embed"
	"flag"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/korjwl1/wireguide/internal/cli"
	"github.com/korjwl1/wireguide/internal/gui"
	"github.com/korjwl1/wireguide/internal/helper"
	"github.com/korjwl1/wireguide/internal/logrotate"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

// trayIconBytes is the source PNG we hand to the GUI for the system-tray
// icon. macOS keeps using the white-W template (the existing buildTrayOn/
// OffIcon path), but on Windows the white-on-transparent template
// disappeared against light system-tray backgrounds and Wails composited
// the full app icon's transparent corners onto a white square. Sending
// the rounded red app icon directly — pre-resized with alpha intact —
// gives the menu-bar look the user expected.
//
//go:embed build/appicon.png
var trayIconBytes []byte

func main() {
	// `wireguide ctl …` is the command-line control interface (issue #10).
	// Dispatched before flag parsing because it has its own positional
	// sub-commands rather than the helper/GUI flag set.
	if len(os.Args) > 1 && os.Args[1] == "ctl" {
		os.Exit(cli.Run(os.Args[2:]))
	}

	helperMode := flag.Bool("helper", false, "run as privileged helper")
	socketPath := flag.String("socket", "", "socket path for IPC")
	socketUID := flag.Int("uid", -1, "socket owner UID (Unix only)")
	ownerSID := flag.String("owner-sid", "", "socket owner SID (Windows only)")
	dataDir := flag.String("data-dir", "", "data directory for crash recovery")
	restoreDesired := flag.Bool("restore-desired", false, "restore tunnels a crashed helper had up (GUI respawn after a mid-session crash)")
	flag.Parse()

	if *helperMode {
		if *socketPath == "" {
			log.Fatal("--socket required in helper mode")
		}
		if *dataDir == "" {
			*dataDir = systemDataDir()
		}
		// Optional: capture helper stderr (runtime fatal errors, panics) under
		// dataDir when WIREGUIDE_HELPER_STDERR=1. The helper is spawned by
		// `Start-Process -Verb RunAs -WindowStyle Hidden` on Windows, launchd
		// on macOS and pkexec on Linux, all of which detach stderr from any
		// console the user can read, so without this hook a crash leaves zero
		// forensic trail. Append mode, so a crash + relaunch accumulates both
		// runs in one place. On Windows slog output is written separately to
		// a size-rotated helper-stderr.log (see internal/helper), so stderr
		// goes to helper-stderr.panic.log, trimmed at startup when oversized;
		// elsewhere stderr keeps going to helper-stderr.log. Off by default:
		// a privileged process writing to a known path on every install is a
		// bigger surface than most users want without opting in. Failure to
		// open a file is silent and the helper proceeds with the default
		// (detached) stderr.
		if os.Getenv("WIREGUIDE_HELPER_STDERR") == "1" {
			_ = os.MkdirAll(*dataDir, 0755)
			stderrLog := filepath.Join(*dataDir, "helper-stderr.log")
			if runtime.GOOS == "windows" {
				stderrLog = filepath.Join(*dataDir, logrotate.WindowsPanicLogName)
				if fi, err := os.Stat(stderrLog); err == nil && fi.Size() > logrotate.HelperLogMaxBytes {
					_ = os.Remove(stderrLog + ".1")
					_ = os.Rename(stderrLog, stderrLog+".1")
				}
			}
			if f, err := os.OpenFile(stderrLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				redirectStderrToFile(f)
			}
		}
		log.Println("WireGuide helper starting...")
		if err := helper.Run(*socketPath, *socketUID, *ownerSID, *dataDir, *restoreDesired); err != nil {
			log.Fatal("helper error:", err)
		}
		return
	}

	// GUI mode
	gui.SetTrayIconPNG(trayIconBytes)
	if err := gui.Run(application.AssetFileServerFS(assets), systemDataDir()); err != nil {
		gui.ShowStartupError(err)
		log.Fatal(err)
	}
}

// systemDataDir returns the system-level data directory for helper state.
// Duplicated in cmd/gui / cmd/helper as needed if we ever split binaries.
func systemDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/wireguide"
	case "linux":
		return "/var/lib/wireguide"
	case "windows":
		if pd := os.Getenv("PROGRAMDATA"); pd != "" {
			return pd + `\wireguide`
		}
		return `C:\ProgramData\wireguide`
	}
	return "/tmp/wireguide"
}
