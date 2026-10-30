//go:build darwin

package elevate

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// authNotice is the text of the explanation shown immediately before the
// administrator password prompt. The app's own i18n tables are not reachable
// here (this runs before the Wails app exists and from the repair path), so
// the supported languages are carried locally and picked through the resolver
// the GUI registers with SetNoticeLanguage.
type authNotice struct {
	Title   string
	Message string // AppleScript string literal body: "\n" escapes allowed, no double quotes
	Cancel  string
	Go      string
	Prompt  string // text of the macOS password prompt itself
}

var authNotices = map[string]authNotice{
	"en": {
		Title:   "WireGuide",
		Message: `WireGuide needs administrator access to install or repair its background VPN helper.\n\nThe helper is what lets WireGuide manage VPN connections, DNS and the firewall without running the whole app as an administrator. It is installed the first time you use WireGuide and is reinstalled or repaired after app updates or if it stops working.\n\nmacOS will ask for your password next. You do not need to enter it every time you connect.`,
		Cancel:  "Cancel",
		Go:      "Continue",
		Prompt:  "WireGuide needs administrator access to start or repair its VPN helper service.",
	},
	"ko": {
		Title:   "WireGuide",
		Message: `WireGuide가 백그라운드 VPN 도우미를 설치하거나 복구하려면 관리자 권한이 필요합니다.\n\n이 도우미 덕분에 앱 전체를 관리자 권한으로 실행하지 않고도 VPN 연결, DNS, 방화벽을 관리할 수 있습니다. 도우미는 WireGuide를 처음 사용할 때 설치되며, 앱을 업데이트하거나 도우미가 작동하지 않을 때 다시 설치되거나 복구됩니다.\n\n다음으로 macOS가 암호를 요청합니다. 연결할 때마다 입력할 필요는 없습니다.`,
		Cancel:  "취소",
		Go:      "계속",
		Prompt:  "WireGuide의 VPN 도우미 서비스를 시작하거나 복구하려면 관리자 권한이 필요합니다.",
	},
	"ja": {
		Title:   "WireGuide",
		Message: `WireGuide がバックグラウンドの VPN ヘルパーをインストールまたは修復するには、管理者権限が必要です。\n\nこのヘルパーにより、アプリ全体を管理者として実行しなくても、VPN 接続、DNS、ファイアウォールを管理できます。ヘルパーは WireGuide を初めて使うときにインストールされ、アプリの更新時や動作しなくなったときに再インストールまたは修復されます。\n\n次に macOS がパスワードを求めます。接続のたびに入力する必要はありません。`,
		Cancel:  "キャンセル",
		Go:      "続ける",
		Prompt:  "WireGuide の VPN ヘルパーサービスを起動または修復するには、管理者権限が必要です。",
	},
	"zh": {
		Title:   "WireGuide",
		Message: `WireGuide 需要管理员权限来安装或修复其后台 VPN 辅助程序。\n\n借助该辅助程序，WireGuide 无需以管理员身份运行整个应用，即可管理 VPN 连接、DNS 和防火墙。辅助程序会在首次使用 WireGuide 时安装，并在应用更新或其停止工作时重新安装或修复。\n\n接下来 macOS 会要求输入密码。每次连接时无需输入。`,
		Cancel:  "取消",
		Go:      "继续",
		Prompt:  "WireGuide 需要管理员权限才能启动或修复其 VPN 辅助服务。",
	},
}

func currentAuthNotice() authNotice {
	if n, ok := authNotices[currentNoticeLanguage()]; ok {
		return n
	}
	return authNotices["en"]
}

// authNoticeScript builds the AppleScript for the explanation dialog.
func authNoticeScript(n authNotice) string {
	return fmt.Sprintf(`display dialog "%s" buttons {"%s", "%s"} default button "%s" cancel button "%s" with title "%s" with icon note`,
		n.Message, n.Cancel, n.Go, n.Go, n.Cancel, n.Title)
}

// runNoticeScript runs the dialog's AppleScript; a seam for tests.
var runNoticeScript = func(script string) ([]byte, error) {
	return exec.Command("osascript", "-e", script).CombinedOutput()
}

// showAuthorizationNotice tells the user why a password is about to be asked
// for. It returns ErrAuthorizationCanceled when they decline, so the existing
// retry flow handles it like a cancelled password prompt. A dialog that cannot
// be shown at all (no osascript, no window server) never blocks the install:
// the password prompt that follows carries its own explanation.
var showAuthorizationNotice = func() error {
	out, err := runNoticeScript(authNoticeScript(currentAuthNotice()))
	if err == nil {
		return nil
	}
	if strings.Contains(string(out), "(-128)") {
		return fmt.Errorf("%w: declined in the explanation dialog", ErrAuthorizationCanceled)
	}
	slog.Warn("authorization explanation dialog could not be shown; continuing", "error", err)
	return nil
}
