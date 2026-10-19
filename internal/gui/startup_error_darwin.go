package gui

import (
	"context"
	"os/exec"
	"strconv"
	"time"
)

// ShowStartupError works before Wails owns an application or tray.
func ShowStartupError(err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	script := "display alert \"WireGuide\" message " + strconv.Quote(err.Error()) + " as critical"
	_ = exec.CommandContext(ctx, "osascript", "-e", script).Run()
}
