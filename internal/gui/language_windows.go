package gui

import "golang.org/x/sys/windows"

func preferredGUILanguage() string {
	language, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage").Call()
	switch language & 0x3ff {
	case 0x12:
		return "ko"
	case 0x11:
		return "ja"
	default:
		return "en"
	}
}
