//go:build !darwin && !windows

package tunnel

import "golang.zx2c4.com/wireguard/conn"

func newPlatformBind(_ string) (conn.Bind, error) { return conn.NewDefaultBind(), nil }
