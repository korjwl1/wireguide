package gui

import (
	"context"
	"os/exec"
	"time"
)

func ShowStartupError(err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if path, e := exec.LookPath("zenity"); e == nil {
		_ = exec.CommandContext(ctx, path, "--error", "--title=WireGuide", "--text="+err.Error(), "--no-markup").Run()
	} else if path, e := exec.LookPath("kdialog"); e == nil {
		_ = exec.CommandContext(ctx, path, "--title", "WireGuide", "--error", err.Error()).Run()
	}
}
