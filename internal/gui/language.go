package gui

import "strings"

type trayLabels struct{ show, quit string }

func labelsForLanguage(language string) trayLabels {
	primary := strings.FieldsFunc(strings.ToLower(language), func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	if len(primary) > 0 {
		switch primary[0] {
		case "ko":
			return trayLabels{show: "창 열기", quit: "종료"}
		case "ja":
			return trayLabels{show: "ウィンドウを表示", quit: "終了"}
		}
	}
	return trayLabels{show: "Show Window", quit: "Quit"}
}

func (t *trayManager) labels() trayLabels {
	language := ""
	if settings, err := t.svc.GetSettings(); err == nil && settings != nil {
		language = settings.Language
	}
	if language == "" || language == "auto" {
		language = preferredGUILanguage()
	}
	return labelsForLanguage(language)
}
