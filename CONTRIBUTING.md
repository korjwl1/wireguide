# Contributing to WireGuide

Thanks for your interest in contributing!

## Development Setup

### Prerequisites

- Go 1.26+
- Node.js 20+
- [Wails v3](https://v3alpha.wails.io/) (`go install github.com/wailsapp/wails/v3/cmd/wails3@latest`)
- macOS with Apple Silicon (for now)

### Build & Run

```bash
# Install frontend dependencies
cd frontend && npm install && cd ..

# Development mode (hot reload)
wails3 task dev

# Production build
wails3 task package
```

### Project Structure

- `internal/helper/` — Privileged daemon (runs as root)
- `internal/tunnel/` — WireGuard engine and connection phases
- `internal/gui/` — Wails app, tray, event bridge
- `internal/network/` — Platform-specific network config
- `internal/firewall/` — Kill switch (pf on macOS)
- `internal/ipc/` — JSON-RPC 2.0 transport
- `frontend/` — Svelte UI

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Test on macOS Apple Silicon
4. Open a PR with a clear description of what and why

Keep PRs focused — one fix or feature per PR.

## Issues

Found a bug? Have a feature idea? Open an issue using the templates provided.

## Code Style

- Follow existing patterns in the codebase
- `go vet` and `go build` must pass with no errors
- Frontend: follow existing Svelte conventions
