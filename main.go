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
	dataDir := flag.String("data-dir", "", "data directory for crash recovery")
	flag.Parse()

	if *helperMode {
		if *socketPath == "" {
			log.Fatal("--socket required in helper mode")
		}
		if *dataDir == "" {
			*dataDir = systemDataDir()
		}
		// Best-effort stderr capture to a file under dataDir/helper-stderr.log.
		// The helper is spawned by powershell `Start-Process -Verb RunAs
		// -WindowStyle Hidden`, which means the elevated process has no
		// inherited console — every write to os.Stderr (slog text handler,
		// wintun.dll log callback, runtime panic traceback) goes to a
		// detached handle that the spawning process can't read. Without
		// this redirect, a helper that dies mid-run leaves zero forensic
		// trace; with it, the next time the helper restarts we have the
		// previous crash's full panic + stack trace on disk. Append mode
		// so the file accumulates across crashes within one helper PID
		// generation; the GUI's spawn flow truncates between sessions if
		// it cares to. Failure to open the log file is silent and the
		// helper proceeds with the default (detached) stderr.
		// Optional: capture helper stderr (slog text + runtime fatal
		// throws) to <dataDir>/helper-stderr.log when WIREGUIDE_HELPER_STDERR=1.
		// Helper is spawned by `Start-Process -Verb RunAs -WindowStyle Hidden`
		// on Windows / launchd on macOS / systemd on Linux, all of which
		// detach stderr from any console the user can read, so without this
		// hook a crash leaves zero forensic trail. The file mode is append
		// so a crash + relaunch cycle accumulates both runs in one place.
		// Off by default — having a privileged process write to a known
		// path on every install is a bigger surface than most users want
		// without opting in.
		if os.Getenv("WIREGUIDE_HELPER_STDERR") == "1" {
			_ = os.MkdirAll(*dataDir, 0755)
			if f, err := os.OpenFile(filepath.Join(*dataDir, "helper-stderr.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				redirectStderrToFile(f)
			}
		}
		log.Println("WireGuide helper starting...")
		if err := helper.Run(*socketPath, *socketUID, *dataDir); err != nil {
			log.Fatal("helper error:", err)
		}
		return
	}

	// GUI mode
	gui.SetTrayIconPNG(trayIconBytes)
	if err := gui.Run(application.AssetFileServerFS(assets), systemDataDir()); err != nil {
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
