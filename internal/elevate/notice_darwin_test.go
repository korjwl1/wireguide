//go:build darwin

package elevate

import (
	"errors"
	"strings"
	"testing"
)

func TestAuthNoticesCompleteAndSafeForAppleScript(t *testing.T) {
	for _, lang := range []string{"en", "ko", "ja", "zh"} {
		n, ok := authNotices[lang]
		if !ok {
			t.Fatalf("missing %s notice", lang)
		}
		for name, v := range map[string]string{"title": n.Title, "message": n.Message, "cancel": n.Cancel, "go": n.Go, "prompt": n.Prompt} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s %s is empty", lang, name)
			}
			if strings.ContainsAny(v, "\"\n") {
				t.Errorf("%s %s contains a raw quote or newline that would break the AppleScript literal", lang, name)
			}
		}
	}
	// The English text must say why, and must not claim the password is only
	// needed once per update: first installs and repairs prompt too.
	en := authNotices["en"].Message
	for _, want := range []string{"install or repair", "password", "first time", "updates"} {
		if !strings.Contains(en, want) {
			t.Errorf("en notice missing %q: %q", want, en)
		}
	}
	if strings.Contains(en, "once per") {
		t.Errorf("en notice must not promise a once-per-update cadence: %q", en)
	}
	if !strings.Contains(authNoticeScript(authNotices["en"]), `cancel button "Cancel"`) {
		t.Error("dialog needs a cancel button so declining is possible")
	}
}

func TestCurrentAuthNoticeFollowsResolver(t *testing.T) {
	t.Cleanup(func() { SetNoticeLanguage(nil) })
	for lang, want := range map[string]string{"ko-KR": "ko", "ja": "ja", "zh_CN": "zh", "de": "en"} {
		SetNoticeLanguage(func() string { return lang })
		if got := currentAuthNotice(); got != authNotices[want] {
			t.Errorf("language %q: got %q notice, want %q", lang, got.Cancel, authNotices[want].Cancel)
		}
	}
}

func TestShowAuthorizationNoticeMapsCancel(t *testing.T) {
	old := runNoticeScript
	t.Cleanup(func() { runNoticeScript = old })

	var script string
	runNoticeScript = func(s string) ([]byte, error) {
		script = s
		return []byte("execution error: User canceled. (-128)"), errors.New("exit status 1")
	}
	if err := showAuthorizationNotice(); !errors.Is(err, ErrAuthorizationCanceled) {
		t.Fatalf("declined dialog err = %v, want ErrAuthorizationCanceled", err)
	}
	if !strings.Contains(script, "display dialog") {
		t.Fatalf("unexpected script: %s", script)
	}

	runNoticeScript = func(string) ([]byte, error) { return nil, nil }
	if err := showAuthorizationNotice(); err != nil {
		t.Fatalf("accepted dialog err = %v", err)
	}

	// A dialog that cannot be shown must not block the install.
	runNoticeScript = func(string) ([]byte, error) { return []byte("no window server"), errors.New("exit status 1") }
	if err := showAuthorizationNotice(); err != nil {
		t.Fatalf("unshowable dialog err = %v, want nil", err)
	}
}

func TestDeclinedNoticeStopsBeforePasswordPrompt(t *testing.T) {
	oldNotice, oldRun := showAuthorizationNotice, runAuthorizationScript
	t.Cleanup(func() { showAuthorizationNotice, runAuthorizationScript = oldNotice, oldRun })
	showAuthorizationNotice = func() error { return ErrAuthorizationCanceled }
	runAuthorizationScript = func(string) ([]byte, error) {
		t.Fatal("password prompt reached after the notice was declined")
		return nil, nil
	}
	// runDaemonAuthorization must stop at the notice, before any osascript
	// password prompt could run.
	if err := runDaemonAuthorization("true"); !errors.Is(err, ErrAuthorizationCanceled) {
		t.Fatalf("err = %v, want ErrAuthorizationCanceled", err)
	}
}
