//go:build !darwin

package gui

import "github.com/wailsapp/wails/v3/pkg/application"

var dockWindow *application.WebviewWindow

func showDock() {}
func hideDock() {}
