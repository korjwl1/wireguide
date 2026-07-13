package gui

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// startConfigWatcher polls the data files the CLI (or any external
// process) can change and notifies the frontend so a running GUI reflects
// them immediately, without going through the helper:
//
//   - config.json → "config_changed" (settings incl. automation rules)
//   - the tunnels dir listing → "tunnels_changed" (import / delete / rename)
//
// A 1 s mtime/listing poll is used (fsnotify isn't a dependency); the
// latency is imperceptible for these and the cost is a couple of stat
// calls per second. Reacting to the GUI's own writes is harmless — the
// frontend re-reads and re-applies the same values idempotently.
func startConfigWatcher(app *application.App, configPath, tunnelsDir string, done <-chan struct{}, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		fileMtime := func(p string) time.Time {
			fi, err := os.Stat(p)
			if err != nil {
				return time.Time{}
			}
			return fi.ModTime()
		}
		// Signature of the tunnel set: sorted list of .conf base names.
		// Catches add/delete/rename regardless of directory-mtime quirks.
		tunnelSig := func(dir string) string {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return ""
			}
			var names []string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
					names = append(names, e.Name())
				}
			}
			sort.Strings(names)
			return strings.Join(names, "\n")
		}

		lastCfg := fileMtime(configPath)
		lastTun := tunnelSig(tunnelsDir)

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			if m := fileMtime(configPath); !m.Equal(lastCfg) {
				lastCfg = m
				app.Event.Emit("config_changed", struct{}{})
			}
			if sig := tunnelSig(tunnelsDir); sig != lastTun {
				lastTun = sig
				app.Event.Emit("tunnels_changed", struct{}{})
			}
		}
	}()
}

// configFilePath returns the config.json path inside a config dir.
func configFilePath(configDir string) string {
	return filepath.Join(configDir, "config.json")
}
