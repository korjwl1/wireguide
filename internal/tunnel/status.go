package tunnel

import (
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// ConnectionStatus represents the current state of a tunnel connection.
type ConnectionStatus struct {
	State            State     `json:"state"`
	TunnelName       string    `json:"tunnel_name"`
	InterfaceName    string    `json:"interface_name"`
	ConnectedAt      time.Time `json:"connected_at"`
	Duration         string    `json:"duration"`
	RxBytes          int64     `json:"rx_bytes"`
	TxBytes          int64     `json:"tx_bytes"`
	LastHandshake    time.Time `json:"last_handshake"`
	HandshakeAge     string    `json:"handshake_age"`
	Endpoint         string    `json:"endpoint"`
}

// State represents the tunnel connection state.
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateError        State = "error"
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
		Duration:      formatDuration(time.Since(connectedAt)),
	}

	// Aggregate stats from all peers
	for _, peer := range dev.Peers {
		status.RxBytes += peer.ReceiveBytes
		status.TxBytes += peer.TransmitBytes

		if !peer.LastHandshakeTime.IsZero() {
			if status.LastHandshake.IsZero() || peer.LastHandshakeTime.After(status.LastHandshake) {
				status.LastHandshake = peer.LastHandshakeTime
			}
		}

		if peer.Endpoint != nil {
			status.Endpoint = peer.Endpoint.String()
		}
	}

	if !status.LastHandshake.IsZero() {
		status.HandshakeAge = formatDuration(time.Since(status.LastHandshake))
	}

	return status, nil
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
