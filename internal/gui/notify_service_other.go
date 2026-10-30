//go:build !darwin && !linux

package gui

import "errors"

type noNotifications struct{}

func newNotificationBackend() notificationBackend { return noNotifications{} }

func (noNotifications) start() error {
	return errors.New("native notifications not supported on this platform")
}
func (noNotifications) requestAuth() (bool, error)        { return false, nil }
func (noNotifications) checkAuth() (bool, error)          { return false, nil }
func (noNotifications) send(string, string, string) error { return nil }
