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
	if shown, err := showAuthorizationNotice(); !shown || !errors.Is(err, ErrAuthorizationCanceled) {
		t.Fatalf("declined dialog shown=%v err=%v, want shown + ErrAuthorizationCanceled", shown, err)
	}
	if !strings.Contains(script, "display dialog") {
		t.Fatalf("unexpected script: %s", script)
	}

	runNoticeScript = func(string) ([]byte, error) { return nil, nil }
	if shown, err := showAuthorizationNotice(); !shown || err != nil {
		t.Fatalf("accepted dialog shown=%v err=%v", shown, err)
	}

	// A dialog that cannot be shown must not block the install.
	runNoticeScript = func(string) ([]byte, error) { return []byte("no window server"), errors.New("exit status 1") }
	if shown, err := showAuthorizationNotice(); shown || err != nil {
		t.Fatalf("unshowable dialog shown=%v err=%v, want not shown and nil", shown, err)
	}
}

// resetAuthNoticeShown clears the once-per-process gate now and again when the
// test ends, so tests that reach runDaemonAuthorization pass in any order and
// under -count=N.
func resetAuthNoticeShown(t *testing.T) {
	t.Helper()
	authNoticeShown.Store(false)
	t.Cleanup(func() { authNoticeShown.Store(false) })
}

func TestDeclinedNoticeStopsBeforePasswordPrompt(t *testing.T) {
	resetAuthNoticeShown(t)
	oldNotice, oldRun := showAuthorizationNotice, runAuthorizationScript
	t.Cleanup(func() { showAuthorizationNotice, runAuthorizationScript = oldNotice, oldRun })
	showAuthorizationNotice = func() (bool, error) { return true, ErrAuthorizationCanceled }
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

// stubAuthScripts replaces both osascript seams with counters.
func stubAuthScripts(t *testing.T, notice func() ([]byte, error)) (noticeRuns, authRuns *int) {
	t.Helper()
	oldNotice, oldAuth := runNoticeScript, runAuthorizationScript
	t.Cleanup(func() { runNoticeScript, runAuthorizationScript = oldNotice, oldAuth })
	noticeRuns, authRuns = new(int), new(int)
	runNoticeScript = func(string) ([]byte, error) {
		*noticeRuns++
		return notice()
	}
	runAuthorizationScript = func(string) ([]byte, error) {
		*authRuns++
		return nil, nil
	}
	return noticeRuns, authRuns
}

func TestNoticeShownOncePerProcess(t *testing.T) {
	resetAuthNoticeShown(t)
	noticeRuns, authRuns := stubAuthScripts(t, func() ([]byte, error) { return nil, nil })
	for i := 0; i < 2; i++ {
		if err := runDaemonAuthorization("true"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if *noticeRuns != 1 || *authRuns != 2 {
		t.Fatalf("notice ran %d times, authorization %d times; want 1 and 2", *noticeRuns, *authRuns)
	}
}

func TestDeclinedNoticeIsNotShownAgain(t *testing.T) {
	resetAuthNoticeShown(t)
	noticeRuns, authRuns := stubAuthScripts(t, func() ([]byte, error) {
		return []byte("execution error: User canceled. (-128)"), errors.New("exit status 1")
	})
	if err := runDaemonAuthorization("true"); !errors.Is(err, ErrAuthorizationCanceled) {
		t.Fatalf("first call err = %v, want ErrAuthorizationCanceled", err)
	}
	if *authRuns != 0 {
		t.Fatalf("password prompt ran %d times after a declined notice", *authRuns)
	}
	if err := runDaemonAuthorization("true"); err != nil {
		t.Fatalf("second call err = %v", err)
	}
	if *noticeRuns != 1 || *authRuns != 1 {
		t.Fatalf("notice ran %d times, authorization %d times; want 1 and 1", *noticeRuns, *authRuns)
	}
}

func TestUnshowableNoticeIsRetried(t *testing.T) {
	resetAuthNoticeShown(t)
	noticeRuns, authRuns := stubAuthScripts(t, func() ([]byte, error) {
		return []byte("no window server"), errors.New("exit status 1")
	})
	for i := 0; i < 2; i++ {
		if err := runDaemonAuthorization("true"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if *noticeRuns != 2 || *authRuns != 2 {
		t.Fatalf("notice ran %d times, authorization %d times; want 2 and 2", *noticeRuns, *authRuns)
	}
}
