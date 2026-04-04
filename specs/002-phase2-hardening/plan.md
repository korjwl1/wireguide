# Implementation Plan: WireGuide Phase 2 — Hardening & UX

**Branch**: `002-phase2-hardening` | **Date**: 2026-04-05 | **Spec**: [spec.md](./spec.md)

## Clarification Decisions

| # | 질문 | 결정 |
|---|------|------|
| 1 | IPC 프로토콜 | **gRPC over Unix Socket** (macOS/Linux) / Named Pipe (Windows) |
| 2 | 킬 스위치 기본값 | **OFF** |
| 3 | Config 에디터 | **CodeMirror 6 풀 통합** |

## Summary

Phase 2는 WireGuide를 "작동하는 프로토타입"에서 "배포 가능한 앱"으로 전환한다.
핵심은 권한 분리(GUI ↔ 데몬), 보안 강화(킬 스위치, DNS 보호), 안정성(자동 재연결, sleep/wake), UX 개선(CodeMirror, 테마, 자동 시작, 로그, 알림).

## Technical Context

**IPC**: gRPC over Unix Socket (macOS/Linux), Named Pipe (Windows)
- `google.golang.org/grpc` + `protobuf`
- 서버 스트리밍으로 실시간 상태 push (폴링 제거)

**Firewall (Kill Switch + DNS Protection)**:
- macOS: `pfctl` (pf)
- Linux: `nftables`
- Windows: WFP (Windows Filtering Platform) — 동적 세션 (프로세스 종료 시 자동 해제)

**CodeMirror 6**: `@codemirror/view`, `@codemirror/lang-*`, 커스텀 WireGuard language mode

**Sleep/Wake Detection**:
- macOS: `NSWorkspace` willSleep/didWake (via cgo 또는 subprocess)
- Linux: systemd `sleep.target`
- Windows: `WM_POWERBROADCAST`

## Project Structure (추가/변경 파일)

```text
/
├── proto/
│   └── wireguide.proto          # gRPC 서비스 정의
│
├── internal/
│   ├── daemon/
│   │   ├── daemon.go            # 데몬 메인 (gRPC 서버 + 터널 관리)
│   │   ├── service.go           # gRPC 서비스 구현
│   │   └── install.go           # OS별 데몬 설치 (LaunchDaemon/systemd/SCM)
│   │
│   ├── ipc/
│   │   ├── client.go            # gRPC 클라이언트 (GUI → 데몬)
│   │   └── proto/               # protobuf 생성 코드
│   │
│   ├── firewall/
│   │   ├── interface.go         # Firewall 인터페이스
│   │   ├── darwin.go            # macOS pf
│   │   ├── linux.go             # Linux nftables
│   │   └── windows.go           # Windows WFP
│   │
│   ├── reconnect/
│   │   ├── monitor.go           # 핸드셰이크 모니터 + 자동 재연결
│   │   └── sleep.go             # sleep/wake 감지 (OS별)
│   │
│   ├── app/
│   │   └── app.go               # 변경: gRPC 클라이언트 사용으로 전환
│   │
│   └── tunnel/
│       └── manager.go           # 변경: 데몬 내부에서만 실행
│
├── cmd/
│   ├── wireguide/main.go        # GUI 앱 (비특권)
│   └── wireguided/main.go       # 데몬 (특권)
│
├── frontend/
│   ├── src/
│   │   ├── lib/
│   │   │   ├── ConfigEditor.svelte  # CodeMirror 6 에디터
│   │   │   ├── LogViewer.svelte     # 로그 뷰어
│   │   │   └── Settings.svelte      # 설정 화면 (테마, 자동시작 등)
│   │   └── stores/
│   │       └── tunnels.js           # 변경: gRPC 스트리밍 기반
```

## Phases (5 phases, Normal Mode)

### Phase 1: Daemon + gRPC IPC
데몬 프로세스 분리 + gRPC 서비스 정의 + GUI를 gRPC 클라이언트로 전환.
모든 터널 작업이 데몬을 통해 동작.

### Phase 2: Kill Switch + DNS Protection
OS별 방화벽으로 킬 스위치 + DNS 누출 방지 구현.
데몬에서 방화벽 규칙 관리.

### Phase 3: Auto-reconnect + Sleep/Wake
핸드셰이크 모니터링, 지수 백오프 재연결, OS sleep/wake 감지.

### Phase 4: CodeMirror 6 + Dark/Light Mode + Auto-start
에디터 업그레이드, 시스템 테마 감지, OS 부팅 시 자동 시작.

### Phase 5: Log Viewer + OS Notifications + Polish
로그 뷰어, OS 알림, 전체 통합 테스트.
