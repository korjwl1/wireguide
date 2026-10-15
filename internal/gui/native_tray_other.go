//go:build !darwin

package gui

func createNativeTray([]byte, func(string)) {}
func setNativeTrayMenu([]nativeTrayItem)    {}
func setNativeTrayTooltip(string)           {}
func destroyNativeTray()                    {}
func setNativeTrayConnected(bool)           {}
