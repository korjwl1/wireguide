package gui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type tunnelFileStamp struct {
	name     string
	size     int64
	modified int64
}

// tunnelFilesSnapshot includes config edits and metadata, not just filenames.
// Atomic-write temporary files are excluded. Read errors leave the watcher's
// previous snapshot intact rather than reporting a spurious deletion.
func tunnelFilesSnapshot(dir string) ([]tunnelFileStamp, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var stamps []tunnelFileStamp
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".meta.json") {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			continue
		}
		stamps = append(stamps, tunnelFileStamp{name, info.Size(), info.ModTime().UnixNano()})
	}
	return stamps, nil // os.ReadDir already sorts by filename.
}

// startConfigWatcher reflects CLI and external edits in the GUI using a 3 s
// metadata poll. It runs while the window is hidden and stops on GUI shutdown.
func startConfigWatcher(app *application.App, configPath, tunnelsDir string, done <-chan struct{}, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		fileMtime := func() (time.Time, error) {
			fi, err := os.Stat(configPath)
			if os.IsNotExist(err) {
				return time.Time{}, nil
			}
			if err != nil {
				return time.Time{}, err
			}
			return fi.ModTime(), nil
		}
		lastCfg, _ := fileMtime()
		lastTun, _ := tunnelFilesSnapshot(tunnelsDir)
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			if m, err := fileMtime(); err == nil && !m.Equal(lastCfg) {
				lastCfg = m
				app.Event.Emit("config_changed", struct{}{})
			}
			if snapshot, err := tunnelFilesSnapshot(tunnelsDir); err == nil && !slices.Equal(snapshot, lastTun) {
				lastTun = snapshot
				app.Event.Emit("tunnels_changed", struct{}{})
			}
		}
	}()
}

func configFilePath(configDir string) string {
	return filepath.Join(configDir, "config.json")
}
