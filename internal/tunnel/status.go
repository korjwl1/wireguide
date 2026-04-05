package tunnel

import (
	"fmt"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Re-export the canonical connection status + state types from the domain
// package so existing callers (`tunnel.ConnectionStatus`, `tunnel.StateConnected`)
// keep compiling. There is a single underlying type — methods defined on the
// domain type work transparently through these aliases.
type (
	ConnectionStatus = domain.ConnectionStatus
	State            = domain.State
)

const (
	StateDisconnected = domain.StateDisconnected
	StateConnecting   = domain.StateConnecting
	StateConnected    = domain.StateConnected
	StateError        = domain.StateError
)

// GetStatus queries the current status of a WireGuard interface.
func GetStatus(ifaceName string, tunnelName string, connectedAt time.Time) (*ConnectionStatus, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("creating wgctrl client: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("querying device %s: %w", ifaceName, err)
	}

	status := &ConnectionStatus{
		State:         StateConnected,
		TunnelName:    tunnelName,
		InterfaceName: ifaceName,
		ConnectedAt:   connectedAt,
		Duration:      domain.FormatDuration(time.Since(connectedAt)),
	}

	// Aggregate stats from all peers
	for _, peer := range dev.Peers {
		status.RxBytes += peer.ReceiveBytes
		status.TxBytes += peer.TransmitBytes

		if !peer.LastHandshakeTime.IsZero() {
			if status.LastHandshakeTime.IsZero() || peer.LastHandshakeTime.After(status.LastHandshakeTime) {
				status.LastHandshakeTime = peer.LastHandshakeTime
			}
		}

		if peer.Endpoint != nil {
			status.Endpoint = peer.Endpoint.String()
		}
	}

	if !status.LastHandshakeTime.IsZero() {
		status.LastHandshake = domain.FormatDuration(time.Since(status.LastHandshakeTime))
	}

	return status, nil
}
