package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/korjwl1/wireguide/internal/daemon"
	pb "github.com/korjwl1/wireguide/internal/ipc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client wraps the gRPC client for communicating with the daemon.
type Client struct {
	conn    *grpc.ClientConn
	service pb.WireGuideServiceClient
}

// NewClient connects to the daemon via Unix socket.
func NewClient() (*Client, error) {
	sockPath := daemon.SocketPath()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "unix:"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", sockPath, 5*time.Second)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to daemon at %s: %w", sockPath, err)
	}

	return &Client{
		conn:    conn,
		service: pb.NewWireGuideServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Ping checks if the daemon is running.
func (c *Client) Ping(ctx context.Context) (*pb.PingResponse, error) {
	return c.service.Ping(ctx, &pb.PingRequest{})
}

// Connect requests the daemon to connect a tunnel.
func (c *Client) Connect(ctx context.Context, name string, scriptsAllowed bool) error {
	_, err := c.service.Connect(ctx, &pb.ConnectRequest{
		TunnelName:     name,
		ScriptsAllowed: scriptsAllowed,
	})
	return err
}

// Disconnect requests the daemon to disconnect.
func (c *Client) Disconnect(ctx context.Context) error {
	_, err := c.service.Disconnect(ctx, &pb.DisconnectRequest{})
	return err
}

// ListTunnels returns all tunnels.
func (c *Client) ListTunnels(ctx context.Context) ([]*pb.TunnelInfo, error) {
	resp, err := c.service.ListTunnels(ctx, &pb.ListTunnelsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Tunnels, nil
}

// GetTunnelDetail returns full detail for a tunnel.
func (c *Client) GetTunnelDetail(ctx context.Context, name string) (*pb.TunnelDetail, error) {
	return c.service.GetTunnelDetail(ctx, &pb.GetTunnelDetailRequest{Name: name})
}

// StreamStatus opens a streaming connection for real-time status.
func (c *Client) StreamStatus(ctx context.Context) (pb.WireGuideService_StreamStatusClient, error) {
	return c.service.StreamStatus(ctx, &pb.StreamStatusRequest{})
}

// ImportConfig imports a .conf from content.
func (c *Client) ImportConfig(ctx context.Context, name, content string) (*pb.TunnelInfo, error) {
	resp, err := c.service.ImportConfig(ctx, &pb.ImportConfigRequest{Name: name, Content: content})
	if err != nil {
		return nil, err
	}
	return resp.Tunnel, nil
}

// ValidateConfig validates .conf content.
func (c *Client) ValidateConfig(ctx context.Context, content string) ([]string, error) {
	resp, err := c.service.ValidateConfig(ctx, &pb.ValidateConfigRequest{Content: content})
	if err != nil {
		return nil, err
	}
	return resp.Errors, nil
}

// GetConfigText returns raw .conf text.
func (c *Client) GetConfigText(ctx context.Context, name string) (string, error) {
	resp, err := c.service.GetConfigText(ctx, &pb.GetConfigTextRequest{Name: name})
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// UpdateConfig updates a tunnel's config.
func (c *Client) UpdateConfig(ctx context.Context, name, content string) error {
	_, err := c.service.UpdateConfig(ctx, &pb.UpdateConfigRequest{Name: name, Content: content})
	return err
}

// DeleteTunnel removes a tunnel.
func (c *Client) DeleteTunnel(ctx context.Context, name string) error {
	_, err := c.service.DeleteTunnel(ctx, &pb.DeleteTunnelRequest{Name: name})
	return err
}

// ExportConfig returns .conf text for export.
func (c *Client) ExportConfig(ctx context.Context, name string) (string, error) {
	resp, err := c.service.ExportConfig(ctx, &pb.ExportConfigRequest{Name: name})
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// TunnelExists checks if a tunnel exists.
func (c *Client) TunnelExists(ctx context.Context, name string) (bool, error) {
	resp, err := c.service.TunnelExists(ctx, &pb.TunnelExistsRequest{Name: name})
	if err != nil {
		return false, err
	}
	return resp.Exists, nil
}

// GetSettings returns app settings.
func (c *Client) GetSettings(ctx context.Context) (*pb.Settings, error) {
	return c.service.GetSettings(ctx, &pb.GetSettingsRequest{})
}

// SaveSettings saves app settings.
func (c *Client) SaveSettings(ctx context.Context, settings *pb.Settings) error {
	_, err := c.service.SaveSettings(ctx, settings)
	return err
}
