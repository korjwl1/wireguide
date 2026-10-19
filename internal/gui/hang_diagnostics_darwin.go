package gui

/*
#cgo LDFLAGS: -framework Cocoa
#include "mainthread_probe_darwin.h"
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

func startGUIHangMonitor(logsDir string, done <-chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-done:
				cancel()
			case <-ctx.Done():
			}
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var watch mainThreadWatch
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if appQuitting.Load() {
					continue
				}
				ping, stalled := watch.tick(now, uint64(C.wgMainThreadAck()), 10*time.Second)
				if ping > 0 {
					C.wgMainThreadPing(C.uint64_t(ping))
				}
				if stalled {
					if err := captureGUIHang(ctx, logsDir); err != nil {
						slog.Warn("GUI hang capture failed", "error", err)
					}
				}
			}
		}
	}()
}

// Keep Go and native stacks together: Apple's stackshots omit the Go frames
// that are needed to distinguish an RPC wait from a main-queue deadlock.
func captureGUIHang(ctx context.Context, logsDir string) error {
	dir := filepath.Join(logsDir, "hang-diagnostics")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	stem := filepath.Join(dir, "hang-"+time.Now().Format("20060102T150405.000000000"))
	buffer := make([]byte, 4<<20)
	n := runtime.Stack(buffer, true)
	if err := os.WriteFile(stem+"-go.txt", buffer[:n], 0600); err != nil {
		return err
	}
	nativePath := stem + "-native.txt"
	if err := os.WriteFile(nativePath, nil, 0600); err != nil {
		return err
	}
	sampleCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(sampleCtx, "/usr/bin/sample", strconv.Itoa(os.Getpid()), "1", "-file", nativePath).CombinedOutput()
	files, _ := filepath.Glob(filepath.Join(dir, "hang-*.txt"))
	sort.Strings(files)
	for len(files) > 6 {
		_ = os.Remove(files[0])
		files = files[1:]
	}
	slog.Warn("GUI main thread stalled; local diagnostic stacks saved", "directory", dir)
	if err != nil {
		return fmt.Errorf("native sample: %w (%s)", err, out)
	}
	return nil
}
