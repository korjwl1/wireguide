//go:build !darwin

package gui

// watchMenuBarAppearance is only meaningful on macOS; other platforms
// never reach the appearance-dependent icon paths.
func watchMenuBarAppearance(func(dark bool)) {}
