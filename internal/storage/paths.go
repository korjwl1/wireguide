package storage

import (
	"os"
	"path/filepath"
	"runtime"
)

const appName = "wireguide"

// Paths holds all OS-specific directory paths for the application.
type Paths struct {
	ConfigDir  string // App settings (config.json)
	TunnelsDir string // .conf files
	LogsDir    string // Log files
	DataDir    string // Daemon state / recovery journal (system-level)
}

// GetPaths returns OS-specific paths for the application.
func GetPaths() (*Paths, error) {
	var p Paths

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		appSupport := filepath.Join(home, "Library", "Application Support", appName)
		p.ConfigDir = appSupport
		p.TunnelsDir = filepath.Join(appSupport, "tunnels")
		p.LogsDir = filepath.Join(home, "Library", "Logs", appName)
		p.DataDir = filepath.Join("/Library", "Application Support", appName)

	case "linux":
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			configHome = filepath.Join(home, ".config")
		}
		p.ConfigDir = filepath.Join(configHome, appName)
		p.TunnelsDir = filepath.Join(configHome, appName, "tunnels")

		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			dataHome = filepath.Join(home, ".local", "share")
		}
		p.LogsDir = filepath.Join(dataHome, appName, "logs")
		p.DataDir = filepath.Join("/var", "lib", appName)

	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		p.ConfigDir = filepath.Join(appData, appName)
		p.TunnelsDir = filepath.Join(appData, appName, "tunnels")
		p.LogsDir = filepath.Join(appData, appName, "logs")

		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		p.DataDir = filepath.Join(programData, appName)
	}

	return &p, nil
}

// EnsureDirs creates all necessary directories if they don't exist.
func (p *Paths) EnsureDirs() error {
	dirs := []string{p.ConfigDir, p.TunnelsDir, p.LogsDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}
