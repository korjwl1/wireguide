//go:build !(darwin && cgo)

package launchd

import "net"

// Listeners is only implemented on darwin with cgo. Everywhere else the
// process is never launchd-socket-activated.
func Listeners() ([]net.Listener, error) {
	return nil, ErrNotManaged
}
