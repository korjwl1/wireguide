//go:build darwin

package tunnel

import "golang.zx2c4.com/wireguard/conn"

func newPlatformBind(_ string) (conn.Bind, error) {
	return &routeGuardBind{Bind: conn.NewDefaultBind(), allowed: true}, nil
}
