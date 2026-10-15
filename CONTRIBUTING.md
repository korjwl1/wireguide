# Contributing to WireGuide

Thanks for your interest in contributing!

## Development Setup

### Prerequisites

- Go 1.26.9+
- Node.js 20+
- [Task](https://taskfile.dev/) (`go install github.com/go-task/task/v3/cmd/task@v3.45.4`)
- [Wails v3](https://v3alpha.wails.io/) (`go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-alpha.74`)
- macOS 12+ (Apple Silicon), Windows 11, or Linux — all three are supported build/dev hosts

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
- `internal/domain/` — Shared configuration/status types; no GUI or OS implementation dependencies
- `internal/tunnel/` — WireGuard engine and connection phases
- `internal/gui/` — Wails app, tray, event bridge
- `internal/app/` — GUI-side services bound to the frontend
- `internal/network/` — Platform-specific network config
- `internal/firewall/` — Kill switch (macOS `pf` / Linux `nftables` / Windows WFP)
- `internal/wifi/` — Automation rule model, network fingerprinting
- `internal/ipc/` — JSON-RPC 2.0 transport (Unix socket / named pipe)
- `internal/cli/` — `wireguide ctl` command-line interface
- `internal/update/` — Update checker and Ed25519 release verification
- `internal/storage/` — User settings, tunnel configs/metadata, connection history
- `internal/atomicfile/` — Shared file snapshot replacement; callers own directories and locks
- `internal/reconnect/`, `internal/healthcheck/` — Reconnect coordination and bounded tunnel probes
- `internal/guiinstance/` — Single GUI instance and activation transport
- `frontend/` — Svelte UI

### Package boundaries

`gui` assembles the Wails application; `app` is its frontend-facing adapter.
`cli` and `app` request privileged work over `ipc`. `helper` coordinates
`tunnel`, `network`, `firewall` and automation. It also reads the owning user's
storage for automation and crash recovery, under the lifecycle locks.
`tunnel` is a runtime engine, not the domain model; shared data belongs in
`domain`. Neither `domain` nor the OS adapters should import `gui` or `app`.

Keep cohesive responsibilities in one package and split files when their reasons
to change differ. For example, helper lifetime/reconnect/firewall suspension,
macOS routes/DNS/recovery, CLI command families and update download/signature
verification have separate files. Platform files retain their `_darwin.go`,
`_linux.go` or `_windows.go` suffix and build constraints. Avoid a new package or
interface just to wrap an existing function; introduce a narrow interface at a
consumer when it actually separates a dependency or enables a meaningful test.
See the Go team's [module layout guide](https://go.dev/doc/modules/layout) and
[code review comments](https://go.dev/wiki/CodeReviewComments).

Svelte components keep their scoped styles together. Shared import conversion
and event subscription ownership live in `frontend/src/lib`; persistent shared
state lives in `frontend/src/stores`. Register listeners before awaiting startup
RPCs and release listeners, timers and observers on component teardown.

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run frontend `npm test` and `npm run build`, then `go vet ./...` and `go test -race ./...` (Windows CI runs without `-race`)
4. Open a PR with a clear description of what and why

Keep PRs focused — one fix or feature per PR.

## Issues

Found a bug? Have a feature idea? Open an issue using the templates provided.

## Code Style

- Follow existing patterns in the codebase
- `go vet` and `go build` must pass with no errors
- Frontend: follow existing Svelte conventions
- Keep comments about contracts, lock ownership and platform constraints; remove obsolete implementation histories
- Bound external input before allocating it; use `atomicfile.WriteFile` for complete private file snapshots
- For security reviews, run `govulncheck ./...` with the project's actual Go toolchain and `npm audit --omit=dev`
