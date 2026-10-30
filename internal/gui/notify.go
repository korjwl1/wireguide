package gui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/storage"
)

// pendingDelay holds back a "changed outside the app" notification so the
// helper's more specific event (auto_connected, forced_disconnect) can claim
// the same change first and we don't notify twice. The status stream and the
// event stream are independent, so either may arrive first.
const pendingDelay = 1500 * time.Millisecond

// downPendingDelay is the longer hold-back for a "disconnected outside the
// app" message. A helper-driven reconnect (wake, network change, health
// check) tears the tunnel down and rebuilds it, and the tunnel is absent from
// the connected set while it is connecting, which usually outlasts
// pendingDelay (endpoint resolution, routes, DNS). Holding the down message
// back this long lets the matching up cancel both; a tunnel that stays down
// is announced, just later.
const downPendingDelay = 10 * time.Second

// claimTTL is how long an auto_connected / forced_disconnect event claims
// its tunnel: a status-diff notification for the same change inside this
// window is skipped, whichever of the status tick and the event arrived
// first.
const claimTTL = 10 * time.Second

// execTimeout bounds the osascript fallback child process.
const execTimeout = 4 * time.Second

// notificationBackend is the platform notification service. Implemented
// over the Wails notifications service on macOS and Linux
// (notify_service_desktop.go); Windows has no backend (notify_service_other.go)
// because the service's startup writes per-user registry keys, which is out
// of scope for this feature.
type notificationBackend interface {
	start() error
	requestAuth() (bool, error)
	// checkAuth reports whether notifications are currently authorized,
	// without prompting.
	checkAuth() (bool, error)
	send(id, title, body string) error
}

// notifier turns helper-driven tunnel changes into native notifications.
//
// It deliberately never fires for something the user did in this GUI
// process (window or tray — both go through TunnelService, which records
// them in UserActions). Changes made by the CLI or the helper itself
// (automation, wake, health check) are "outside the app" and do notify.
//
// The Wails notifications service is used directly rather than registered
// in application.Options.Services: its Startup fails on an unbundled build
// (go run / dev), and a failing service startup would abort the whole app.
// Starting it lazily here keeps that failure local — delivery then falls
// back to osascript on macOS and to a no-op elsewhere.
//
// Nothing here blocks the caller: every delivery runs on its own goroutine,
// so the event bridge goroutine and the main thread never wait on the OS.
type notifier struct {
	settings *storage.SettingsStore
	actions  *wgapp.UserActions
	differ   wgapp.StatusDiffer

	mu       sync.Mutex
	pending  map[string]*time.Timer // "up|name" / "down|name" -> hold-back timer
	claimed  map[string]time.Time   // "up|name" / "down|name" -> when an event claimed it
	quitting bool
	// pendingDelay and downPendingDelay override the package defaults
	// (tests). A zero downPendingDelay falls back to pendingDelay when that
	// is set, so one override covers both directions.
	pendingDelay     time.Duration
	downPendingDelay time.Duration

	// post delivers one notification; deliver in production, a stub in tests.
	post func(title, body string)
	// systemLanguage reports the OS UI language; preferredGUILanguage in
	// production, a stub in tests.
	systemLanguage func() string
	// newBackend creates the platform notification service (stubbed in
	// tests).
	newBackend func() notificationBackend
	// fallback posts without the service when it cannot be used; nil where
	// no fallback exists. osascriptNotify on macOS.
	fallback func(title, body string) error

	svcMu       sync.Mutex // guards the fields below; never held across a blocking call
	svc         notificationBackend
	svcStarted  bool
	svcUsable   bool
	authAsked   bool
	authPending bool
	authDenied  bool
	// authTimedOut: the authorization request timed out unanswered, so the
	// service stays usable but the user's choice is unknown. Each later
	// send re-checks without prompting.
	authTimedOut bool
}

func newNotifier(settings *storage.SettingsStore, actions *wgapp.UserActions) *notifier {
	n := &notifier{
		settings:       settings,
		actions:        actions,
		pending:        map[string]*time.Timer{},
		claimed:        map[string]time.Time{},
		systemLanguage: preferredGUILanguage,
		newBackend:     newNotificationBackend,
	}
	if runtime.GOOS == "darwin" {
		n.fallback = osascriptNotify
	}
	n.post = n.deliver
	return n
}

func changeKey(name string, up bool) string {
	if up {
		return "up|" + name
	}
	return "down|" + name
}

// stop silences the notifier for the rest of the session (app quit): the
// helper tearing tunnels down must not read as "outside the app".
func (n *notifier) stop() {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.quitting = true
	n.cancelAllLocked()
	n.mu.Unlock()
}

func (n *notifier) cancelAllLocked() {
	for key, t := range n.pending {
		t.Stop()
		delete(n.pending, key)
	}
}

// reset forgets the status baseline (helper restart) and any pending
// notifications.
func (n *notifier) reset() {
	if n == nil {
		return
	}
	n.differ.Reset()
	n.mu.Lock()
	n.cancelAllLocked()
	n.mu.Unlock()
}

func (n *notifier) enabled() bool {
	if n.settings == nil {
		return true
	}
	s, err := n.settings.Load()
	if err != nil || s == nil {
		return true // unreadable settings: default is on
	}
	return s.NotifyAutoChanges
}

// claimedLocked reports whether an event recently named the change. Caller
// holds n.mu.
func (n *notifier) claimedLocked(key string, now time.Time) bool {
	t, ok := n.claimed[key]
	if ok && now.Sub(t) >= claimTTL {
		delete(n.claimed, key)
		return false
	}
	return ok
}

// claim records that a helper event named the change at now (suppressing
// the generic status-diff message for it) and drops any message already
// held back for it.
func (n *notifier) claim(key string, now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, t := range n.claimed { // prune
		if now.Sub(t) >= claimTTL {
			delete(n.claimed, k)
		}
	}
	n.claimed[key] = now
	if t, ok := n.pending[key]; ok {
		t.Stop()
		delete(n.pending, key)
	}
}

// onStatus is called for every status event with the connected tunnel set.
func (n *notifier) onStatus(connected []string) {
	if n == nil {
		return
	}
	events := n.differ.Observe(connected)
	if len(events) == 0 {
		return
	}
	enabled := n.enabled()
	now := time.Now()
	for _, ev := range events {
		up := ev.Kind == wgapp.NotifyTunnelUp
		// A change reversed inside the hold-back window (a wake or
		// health-check reconnect tears the tunnel down and brings it
		// back) is no change at all: drop the held-back message and
		// announce nothing.
		if n.cancelPending(changeKey(ev.Tunnel, !up)) {
			continue
		}
		if !wgapp.ShouldNotify(enabled, ev, n.actions, now) {
			continue
		}
		kind := msgDown
		if up {
			kind = msgUp
		}
		n.schedule(changeKey(ev.Tunnel, up), kind, ev.Tunnel)
	}
}

// schedule holds a status-diff notification back (pendingDelay for up,
// downPendingDelay for down) so a helper event can claim the change first and
// a reconnect can cancel it.
func (n *notifier) schedule(key string, kind msgKind, tunnel string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.quitting || n.claimedLocked(key, time.Now()) {
		return // a helper event already announced (or will, via the claim)
	}
	if old, ok := n.pending[key]; ok {
		old.Stop()
	}
	n.pending[key] = time.AfterFunc(n.delay(kind), func() {
		n.mu.Lock()
		delete(n.pending, key)
		skip := n.quitting || n.claimedLocked(key, time.Now())
		n.mu.Unlock()
		if skip {
			return
		}
		n.send(kind, tunnel)
	})
}

func (n *notifier) delay(kind msgKind) time.Duration {
	if kind == msgDown {
		if n.downPendingDelay > 0 {
			return n.downPendingDelay
		}
		if n.pendingDelay > 0 {
			return n.pendingDelay
		}
		return downPendingDelay
	}
	if n.pendingDelay > 0 {
		return n.pendingDelay
	}
	return pendingDelay
}

// cancelPending drops the message held back under key and reports whether
// it was stopped before delivery. false means nothing was pending or its
// timer had already fired, so that message goes out.
func (n *notifier) cancelPending(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	t, ok := n.pending[key]
	if !ok {
		return false
	}
	delete(n.pending, key)
	return t.Stop()
}

// onAutoConnected handles the helper's auto_connected event: it names the
// tunnel and claims the matching status-diff "up" so only one message shows.
func (n *notifier) onAutoConnected(name string) {
	if n == nil || name == "" {
		return
	}
	n.claim(changeKey(name, true), time.Now())
	if wgapp.ShouldNotify(n.enabled(), wgapp.NotifyEvent{Kind: wgapp.NotifyAutoConnected, Tunnel: name}, n.actions, time.Now()) {
		n.send(msgAuto, name)
	}
}

// onForcedDisconnect handles the helper's forced_disconnect event (loop
// watchdog) and claims the matching status-diff "down".
func (n *notifier) onForcedDisconnect(name string) {
	if n == nil || name == "" {
		return
	}
	n.claim(changeKey(name, false), time.Now())
	if wgapp.ShouldNotify(n.enabled(), wgapp.NotifyEvent{Kind: wgapp.NotifyForcedDisconnect, Tunnel: name}, n.actions, time.Now()) {
		n.send(msgForced, name)
	}
}

// onCriticalError handles the helper's critical_error event.
func (n *notifier) onCriticalError(where string) {
	if n == nil {
		return
	}
	if wgapp.ShouldNotify(n.enabled(), wgapp.NotifyEvent{Kind: wgapp.NotifyCriticalError}, n.actions, time.Now()) {
		n.send(msgCritical, where)
	}
}

// send localises and delivers one message off the caller's goroutine.
func (n *notifier) send(kind msgKind, arg string) {
	n.mu.Lock()
	q := n.quitting
	n.mu.Unlock()
	if q {
		return
	}
	go func() {
		title, body := notifyText(n.language(), kind, arg)
		n.post(title, body)
	}()
}

// language resolves the notification language: the Settings language, or
// the OS UI language when it is "auto" (or unreadable).
func (n *notifier) language() string {
	lang := "auto"
	if n.settings != nil {
		if s, err := n.settings.Load(); err == nil && s != nil && s.Language != "" {
			lang = s.Language
		}
	}
	if lang == "auto" {
		lang = n.systemLanguage()
	}
	return pickLanguage(lang)
}

// serviceResult is the outcome of one delivery attempt through the
// notifications service.
type serviceResult int

const (
	// serviceDelivered: the service posted the notification.
	serviceDelivered serviceResult = iota
	// serviceDrop: the user has not allowed notifications (denied, or the
	// authorization prompt is still unanswered); the notification is
	// dropped so the user's choice is respected.
	serviceDrop
	// serviceFailed: the service could not start, or authorization (other
	// than a timeout) or delivery returned an error; the fallback may post
	// instead.
	serviceFailed
)

// deliver posts through the Wails notifications service, requesting
// authorization lazily on first use. The osascript fallback (macOS) is used
// only when the service fails; a denied or still-pending authorization
// drops the notification instead of routing around the user's choice.
func (n *notifier) deliver(title, body string) {
	if n.sendViaService(title, body) != serviceFailed || n.fallback == nil {
		return
	}
	if err := n.fallback(title, body); err != nil {
		slog.Warn("notification fallback failed", "error", err)
	}
}

// sendViaService attempts one delivery through the service. svcMu is only
// held for state changes, never across the authorization wait (which can
// block until the user answers the macOS prompt). Notifications arriving
// while the prompt is open are dropped. A denial holds for the rest of the
// session: allowing notifications later in System Settings takes effect
// after a restart.
//
// An authorization request the user leaves unanswered times out with
// context.DeadlineExceeded. That says nothing about the user's choice, so
// the service stays usable and the notification is dropped; later sends
// re-check the authorization without prompting and post only once it is
// granted. Only a start failure or another error sends delivery around the
// service.
func (n *notifier) sendViaService(title, body string) serviceResult {
	n.svcMu.Lock()
	if !n.svcStarted {
		n.svcStarted = true
		n.svc = n.newBackend()
		if err := n.svc.start(); err != nil {
			slog.Info("notifications service unavailable, using fallback", "error", err)
		} else {
			n.svcUsable = true
		}
	}
	if !n.svcUsable {
		n.svcMu.Unlock()
		return serviceFailed
	}
	if n.authPending || n.authDenied {
		n.svcMu.Unlock()
		return serviceDrop
	}
	svc := n.svc
	if n.authTimedOut {
		n.svcMu.Unlock()
		// The check cannot tell "denied" from "not decided yet": both
		// report not authorized, so neither is latched and a grant made
		// later is still honoured.
		ok, err := svc.checkAuth()
		if err != nil || !ok {
			if err != nil {
				slog.Info("notification authorization check failed; dropping", "error", err)
			}
			return serviceDrop
		}
		n.svcMu.Lock()
		n.authTimedOut = false
		n.svcMu.Unlock()
	} else if !n.authAsked {
		n.authPending = true
		n.svcMu.Unlock()
		ok, err := svc.requestAuth()
		n.svcMu.Lock()
		n.authPending = false
		n.authAsked = true // ask at most once per session, even on error/timeout
		if errors.Is(err, context.DeadlineExceeded) {
			slog.Info("notification authorization request timed out; dropping until it is granted", "error", err)
			n.authTimedOut = true
			n.svcMu.Unlock()
			return serviceDrop
		}
		if err != nil {
			slog.Info("notification authorization failed, using fallback", "error", err)
			n.svcUsable = false
			n.svcMu.Unlock()
			return serviceFailed
		}
		if !ok {
			slog.Info("notifications not allowed by the user; dropping them")
			n.authDenied = true
			n.svcMu.Unlock()
			return serviceDrop
		}
		n.svcMu.Unlock()
	} else {
		n.svcMu.Unlock()
	}
	if err := svc.send(fmt.Sprintf("wireguide-%d", time.Now().UnixNano()), title, body); err != nil {
		slog.Info("notification delivery failed, using fallback", "error", err)
		return serviceFailed
	}
	return serviceDelivered
}

// osascriptNotify posts a notification through AppleScript, which needs no
// bundle identifier or authorization of our own.
func osascriptNotify(title, body string) error {
	script := fmt.Sprintf(`display notification "%s" with title "%s"`, appleScriptEscape(body), appleScriptEscape(title))
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "osascript", "-e", script).Run()
}

func appleScriptEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// --- localisation -------------------------------------------------------

type msgKind int

const (
	msgUp msgKind = iota
	msgDown
	msgAuto
	msgForced
	msgCritical
)

var notifyStrings = map[string]map[msgKind]string{
	"en": {
		msgUp:       "“%s” connected outside the app.",
		msgDown:     "“%s” disconnected outside the app.",
		msgAuto:     "Automation connected “%s”.",
		msgForced:   "“%s” was disconnected to stop a routing loop. Connect it again manually.",
		msgCritical: "Helper problem (%s). Restart WireGuide to recover.",
	},
	"ko": {
		msgUp:       "“%s” 터널이 앱 밖에서 연결되었습니다.",
		msgDown:     "“%s” 터널이 앱 밖에서 연결 해제되었습니다.",
		msgAuto:     "자동화가 “%s” 터널을 연결했습니다.",
		msgForced:   "라우팅 루프를 막기 위해 “%s” 터널의 연결을 해제했습니다. 직접 다시 연결하세요.",
		msgCritical: "헬퍼 문제 (%s). 복구하려면 WireGuide를 다시 시작하세요.",
	},
	"ja": {
		msgUp:       "“%s” がアプリ外で接続されました。",
		msgDown:     "“%s” がアプリ外で切断されました。",
		msgAuto:     "自動化が “%s” を接続しました。",
		msgForced:   "ルーティングループを防ぐため “%s” を切断しました。手動で再接続してください。",
		msgCritical: "ヘルパーの問題 (%s)。復旧するには WireGuide を再起動してください。",
	},
	"zh": {
		msgUp:       "“%s”已在应用之外连接。",
		msgDown:     "“%s”已在应用之外断开。",
		msgAuto:     "自动化已连接“%s”。",
		msgForced:   "为避免路由环路，已断开“%s”。请手动重新连接。",
		msgCritical: "辅助程序出现问题（%s）。请重启 WireGuide 以恢复。",
	},
}

// notifyText returns the notification title and body for lang (falling
// back to English). arg is the tunnel name, or the failing subsystem for
// critical errors.
func notifyText(lang string, kind msgKind, arg string) (title, body string) {
	table, ok := notifyStrings[lang]
	if !ok {
		table = notifyStrings["en"]
	}
	return "WireGuide", fmt.Sprintf(table[kind], arg)
}

// pickLanguage maps the FIRST language in raw (a Settings value like "ko",
// a macOS preferred-language tag like "zh-Hans-CN" or a LANG value like
// "ja_JP.UTF-8") to en/ko/ja/zh, English otherwise. Only the primary
// language counts, matching labelsForLanguage and the frontend's
// detectLanguage.
func pickLanguage(raw string) string {
	tokens := strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool { return r < 'a' || r > 'z' })
	if len(tokens) > 0 {
		switch tokens[0] {
		case "ko", "ja", "zh":
			return tokens[0]
		}
	}
	return "en"
}
