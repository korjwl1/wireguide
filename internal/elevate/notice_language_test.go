package elevate

import "testing"

func TestNormalizeNoticeLanguage(t *testing.T) {
	for in, want := range map[string]string{
		"ko": "ko", "ko-KR": "ko", "ja_JP": "ja", "zh-Hans-CN": "zh", "ZH": "zh",
		"en-US": "en", "fr-FR": "en", "": "en", "auto": "en",
	} {
		if got := normalizeNoticeLanguage(in); got != want {
			t.Errorf("normalizeNoticeLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetNoticeLanguage(t *testing.T) {
	t.Cleanup(func() { SetNoticeLanguage(nil) })
	if got := currentNoticeLanguage(); got != "en" {
		t.Fatalf("unset resolver = %q, want en", got)
	}
	lang := "ja-JP"
	SetNoticeLanguage(func() string { return lang })
	if got := currentNoticeLanguage(); got != "ja" {
		t.Fatalf("got %q, want ja", got)
	}
	lang = "zh-CN" // resolved on every call, so a Settings change applies live
	if got := currentNoticeLanguage(); got != "zh" {
		t.Fatalf("got %q, want zh", got)
	}
}
