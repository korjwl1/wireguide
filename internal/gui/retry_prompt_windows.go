//go:build windows

package gui

import (
	"strings"

	"golang.org/x/sys/windows"
)

// askHelperRetry shows a native Retry/Cancel message box when the helper
// connection fails — typically because the UAC consent prompt sat
// unanswered past ensureHelper's timeout (common at login autostart).
// The Wails app isn't running yet, so this must be a raw user32 call.
// Returns true if the user chose Retry.
//
// The previous code ran osascript here, which doesn't exist on Windows,
// so every helper timeout was silently treated as "user cancelled" and
// the GUI exited before the tray icon was ever created — while the
// still-pending UAC prompt could go on to spawn an orphaned helper.
// detail is the underlying error, appended so a persistent failure is
// diagnosable from the dialog instead of retrying blind.
func askHelperRetry(cause error) bool {
	detail := cause.Error()
	const idRetry = 4 // IDRETRY — not exported by x/sys/windows
	const style = windows.MB_RETRYCANCEL | windows.MB_ICONWARNING |
		windows.MB_SETFOREGROUND | windows.MB_TOPMOST
	msg := "The VPN service could not be started.\n\nAllow administrator access when prompted, then select Retry."
	detailsLabel := "Details: "
	switch preferredGUILanguage() {
	case "ko":
		msg = "VPN 서비스를 시작하지 못했습니다.\n\n관리자 권한 요청을 허용한 뒤 ‘다시 시도’를 선택하세요."
		detailsLabel = "세부 정보: "
	case "ja":
		msg = "VPN サービスを起動できませんでした。\n\n管理者権限を許可してから「再試行」を選択してください。"
		detailsLabel = "詳細: "
	case "zh":
		msg = "VPN 服务无法启动。\n\n请在出现提示时授予管理员权限，然后选择“重试”。"
		detailsLabel = "详情："
	}
	if d := strings.TrimSpace(detail); d != "" {
		if r := []rune(d); len(r) > 400 {
			d = "…" + string(r[len(r)-400:])
		}
		msg += "\n\n" + detailsLabel + d
	}
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return false
	}
	caption, err := windows.UTF16PtrFromString("WireGuide")
	if err != nil {
		return false
	}
	ret, _ := windows.MessageBox(0, text, caption, style)
	return ret == idRetry
}
