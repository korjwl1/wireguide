package elevate

import (
	"strings"
	"sync/atomic"
)

// noticeLanguage resolves the language of the explanation dialog shown before
// the administrator prompt. internal/elevate cannot import internal/gui (which
// owns the user's Settings language and the system-language lookup), so the
// GUI registers a resolver here at startup.
var noticeLanguage atomic.Pointer[func() string]

// SetNoticeLanguage registers a function returning the language to show the
// pre-authorization dialog in: the user's Settings language, or the system
// GUI language when Settings is "auto". Any BCP-47-ish tag is accepted ("ko",
// "ja-JP", "zh_CN"); unsupported languages fall back to English. The resolver
// runs each time the dialog is shown, so a language change takes effect
// without a restart.
func SetNoticeLanguage(resolve func() string) {
	if resolve == nil {
		noticeLanguage.Store(nil)
		return
	}
	noticeLanguage.Store(&resolve)
}

// normalizeNoticeLanguage reduces a language tag to one of "en", "ko", "ja",
// "zh". Anything else is English.
func normalizeNoticeLanguage(tag string) string {
	parts := strings.FieldsFunc(strings.ToLower(tag), func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	if len(parts) > 0 {
		switch parts[0] {
		case "ko", "ja", "zh":
			return parts[0]
		}
	}
	return "en"
}

// currentNoticeLanguage returns the normalized language for the dialog.
func currentNoticeLanguage() string {
	if p := noticeLanguage.Load(); p != nil {
		return normalizeNoticeLanguage((*p)())
	}
	return "en"
}
