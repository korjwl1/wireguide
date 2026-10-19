package gui

import "os"

func preferredGUILanguage() string {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if language := os.Getenv(key); language != "" {
			return language
		}
	}
	return "en"
}
