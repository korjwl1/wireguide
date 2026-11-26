package gui

import (
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/storage"
)

func TestNotifyTextLanguages(t *testing.T) {
	for _, lang := range []string{"en", "ko", "ja", "zh"} {
		for _, k := range []msgKind{msgUp, msgDown, msgAuto, msgForced, msgCritical} {
			title, body := notifyText(lang, k, "Home")
			if title != "WireGuide" || !strings.Contains(body, "Home") || strings.Contains(body, "%!") {
				t.Errorf("%s/%d: %q %q", lang, k, title, body)
			}
		}
	}
	_, fb := notifyText("fr", msgAuto, "X")
	if !strings.HasPrefix(fb, "Automation") {
		t.Errorf("unknown language must fall back to English, got %q", fb)
	}
	// A localized table must not silently fall through to English.
	for _, lang := range []string{"ko", "ja", "zh"} {
		_, en := notifyText("en", msgDown, "Home")
		_, loc := notifyText(lang, msgDown, "Home")
		if loc == en {
			t.Errorf("%s: down message is not localized", lang)
		}
	}
}

func TestPickLanguage(t *testing.T) {
	cases := map[string]string{
		"ko":                                  "ko",
		"zh":                                  "zh",
		"zh-Hans-CN":                          "zh",
		"ja-JP":                               "ja",
		"ja_JP.UTF-8":                         "ja",
		"zh_CN.UTF-8":                         "zh",
		"en-US":                               "en",
		"de_DE.UTF-8":                         "en",
		"auto":                                "en",
		"":                                    "en",
		"(\n    \"ko-KR\",\n    \"en-US\"\n)": "ko",
		"(\n    \"en-US\",\n    \"ja-JP\"\n)": "en",
	}
	for in, want := range cases {
		if got := pickLanguage(in); got != want {
			t.Errorf("pickLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAppleScriptEscape(t *testing.T) {
	got := appleScriptEscape("a\"b\\c\nd")
	if got != `a\"b\\c d` {
		t.Errorf("got %q", got)
	}
}

// The Settings language wins; "auto" (or no stored value) follows the OS.
func TestNotifierLanguage(t *testing.T) {
	store := storage.NewSettingsStore(t.TempDir())
	n := newNotifier(store, nil)
	n.systemLanguage = func() string { return "ko-KR" }
	if got := n.language(); got != "ko" {
		t.Errorf("default auto should follow the system language, got %q", got)
	}
	for _, lang := range []string{"en", "ja", "zh"} {
		if err := store.Update(func(s *storage.Settings) error { s.Language = lang; return nil }); err != nil {
			t.Fatal(err)
		}
		if got := n.language(); got != lang {
			t.Errorf("explicit %q: got %q", lang, got)
		}
	}
	if err := store.Update(func(s *storage.Settings) error { s.Language = "auto"; return nil }); err != nil {
		t.Fatal(err)
	}
	n.systemLanguage = func() string { return "zh-Hans-CN" }
	if got := n.language(); got != "zh" {
		t.Errorf("auto with a Chinese system: got %q", got)
	}
	nilSettings := newNotifier(nil, nil)
	nilSettings.systemLanguage = func() string { return "ja-JP" }
	if got := nilSettings.language(); got != "ja" {
		t.Errorf("nil settings should follow the system language, got %q", got)
	}
}
