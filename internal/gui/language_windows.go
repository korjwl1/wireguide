package gui

import "golang.org/x/sys/windows"

func preferredGUILanguage() string {
	language, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage").Call()
	switch language & 0x3ff {
	case 0x12:
		return "ko"
	case 0x11:
		return "ja"
	case 0x04:
		return "zh"
	case 0x0a:
		return "es"
	default:
		return "en"
	}
}
