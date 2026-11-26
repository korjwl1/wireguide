//go:build darwin || linux

package gui

import (
	"context"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

type wailsNotifications struct {
	svc *notifications.NotificationService
}

func newNotificationBackend() notificationBackend {
	return &wailsNotifications{svc: notifications.New()}
}

// start runs the service's own startup (macOS: bundle identifier check and
// UNUserNotificationCenter delegate; Linux: session D-Bus connection).
func (w *wailsNotifications) start() error {
	return w.svc.ServiceStartup(context.Background(), application.ServiceOptions{})
}

func (w *wailsNotifications) requestAuth() (bool, error) {
	return w.svc.RequestNotificationAuthorization()
}

func (w *wailsNotifications) checkAuth() (bool, error) {
	return w.svc.CheckNotificationAuthorization()
}

func (w *wailsNotifications) send(id, title, body string) error {
	return w.svc.SendNotification(notifications.NotificationOptions{ID: id, Title: title, Body: body})
}
