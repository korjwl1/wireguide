package daemon

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	pb "github.com/korjwl1/wireguide/internal/ipc/proto"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"google.golang.org/grpc"
)

const socketDir = "/var/run/wireguide"
const socketName = "wireguide.sock"

// SocketPath returns the IPC socket path for the current OS.
func SocketPath() string {
	switch runtime.GOOS {
	case "windows":
		return `\\.\pipe\wireguide`
	default:
		return filepath.Join(socketDir, socketName)
	}
}

// Run starts the daemon with gRPC server.
func Run() error {
	// Initialize storage
	paths, err := storage.GetPaths()
	if err != nil {
		return fmt.Errorf("getting paths: %w", err)
	}
	if err := paths.EnsureDirs(); err != nil {
		return fmt.Errorf("creating dirs: %w", err)
	}

	tunnelStore := storage.NewTunnelStore(paths.TunnelsDir)
	settingsStore := storage.NewSettingsStore(paths.ConfigDir)
	manager := tunnel.NewManager(paths.DataDir)

	// Crash recovery
	if recovered := tunnel.RecoverFromCrash(paths.DataDir); recovered != "" {
		slog.Warn("recovered from previous crash", "tunnel", recovered)
	}

	// Create Unix socket
	sockPath := SocketPath()
	if runtime.GOOS != "windows" {
		os.MkdirAll(socketDir, 0755)
		os.Remove(sockPath) // remove stale socket
	}

	listener, err := net.Listen(socketNetwork(), sockPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", sockPath, err)
	}
	defer listener.Close()

	if runtime.GOOS != "windows" {
		os.Chmod(sockPath, 0660)
	}

	slog.Info("daemon listening", "socket", sockPath)

	// Create gRPC server
	grpcServer := grpc.NewServer()
	service := NewService(tunnelStore, settingsStore, manager)
	pb.RegisterWireGuideServiceServer(grpcServer, service)

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down daemon")
		// Cleanup firewall rules
		service.firewall.Cleanup()
		if manager.IsConnected() {
			manager.Disconnect()
		}
		grpcServer.GracefulStop()
	}()

	return grpcServer.Serve(listener)
}

func socketNetwork() string {
	if runtime.GOOS == "windows" {
		return "pipe" // placeholder — Windows named pipe needs a different approach
	}
	return "unix"
}
