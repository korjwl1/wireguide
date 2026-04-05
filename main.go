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
	"runtime"

	"github.com/korjwl1/wireguide/internal/gui"
	"github.com/korjwl1/wireguide/internal/helper"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
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
		log.Println("WireGuide helper starting...")
		if err := helper.Run(*socketPath, *socketUID, *dataDir); err != nil {
			log.Fatal("helper error:", err)
		}
		return
	}

	// GUI mode
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
