//go:build !darwin

package gui

func createNativeTray([]byte, func(string)) {}
func setNativeTrayIcon([]byte)              {}
func setNativeTrayMenu([]nativeTrayItem)    {}
func setNativeTrayTooltip(string)           {}
func destroyNativeTray()                    {}
