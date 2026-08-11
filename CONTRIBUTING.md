# Contributing to WireGuide

Thanks for your interest in contributing!

## Development Setup

### Prerequisites

- Go 1.25+
- Node.js 20+
- [Task](https://taskfile.dev/) (`go install github.com/go-task/task/v3/cmd/task@v3.45.4`)
- [Wails v3](https://v3alpha.wails.io/) (`go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-alpha.74`)
- macOS (Apple Silicon), Windows 11, or Linux — all three are supported build/dev hosts

### Build & Run

```bash
# Install frontend dependencies
cd frontend && npm ci && cd ..

# Development mode (hot reload)
task dev

# Production build
task build
```

### Project Structure

- `internal/helper/` — Privileged daemon (runs as root), Automation evaluation
- `internal/tunnel/` — WireGuard engine and connection phases
- `internal/gui/` — Wails app, tray, event bridge
- `internal/app/` — GUI-side services bound to the frontend
- `internal/network/` — Platform-specific network config
- `internal/firewall/` — Kill switch (macOS `pf` / Linux `nftables` / Windows WFP)
- `internal/wifi/` — Automation rule model, network fingerprinting
- `internal/ipc/` — JSON-RPC 2.0 transport (Unix socket / named pipe)
- `internal/cli/` — `wireguide ctl` command-line interface
- `internal/update/` — Update checker and Ed25519 release verification
- `frontend/` — Svelte UI

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `go vet ./...` and `go test ./...` locally (CI runs the same on a Linux/macOS/Windows matrix for every PR)
4. Open a PR with a clear description of what and why

Keep PRs focused — one fix or feature per PR.

## Issues

Found a bug? Have a feature idea? Open an issue using the templates provided.

## Code Style

- Follow existing patterns in the codebase
- `go vet` and `go build` must pass with no errors
- Frontend: follow existing Svelte conventions
