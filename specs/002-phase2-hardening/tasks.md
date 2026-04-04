# Tasks: WireGuide Phase 2 — Hardening & UX

**Input**: `specs/002-phase2-hardening/plan.md`

---

## Phase 1: Daemon + gRPC IPC

**Description**: GUI ↔ 데몬 권한 분리. gRPC over UDS로 통신.
**Deliverables**: proto/, internal/daemon/, internal/ipc/, cmd/wireguided/
**Acceptance**: 일반 사용자로 GUI 실행 → 데몬 통해 터널 연결/해제 동작

**Tasks**:
- [x] T001 `proto/wireguide.proto` — gRPC 서비스 정의 (17 RPC methods + streaming)
- [x] T002 protobuf 코드 생성 (protoc + protoc-gen-go + protoc-gen-go-grpc)
- [x] T003 `internal/daemon/daemon.go` — gRPC 서버 + Unix Socket + graceful shutdown
- [x] T004 `internal/daemon/service.go` — 전체 gRPC 서비스 구현 (tunnel.Manager 래핑)
- [x] T005 `internal/daemon/service.go` — StreamStatus 서버 스트리밍
- [x] T006 `internal/ipc/client.go` — gRPC 클라이언트 (모든 RPC 메서드)
- [x] T007 `internal/app/app.go` — TunnelService를 gRPC 클라이언트 기반으로 전환
- [x] T008 `cmd/wireguided/main.go` — 데몬 바이너리 (16MB)
- [x] T009 `main.go` — GUI를 gRPC 클라이언트 기반으로 전환 (12MB)
- [ ] T010 `internal/daemon/install.go` — macOS LaunchDaemon plist (Phase 5에서 구현)
- [ ] T011 `internal/daemon/install.go` — Linux systemd unit (Phase 5에서 구현)
- [ ] T012 `internal/daemon/install.go` — Windows SCM 서비스 (Phase 5에서 구현)
- [x] T013 프론트엔드는 기존 폴링 유지 (gRPC 스트리밍은 Wails 바인딩과 호환 — 폴링이 더 간단)
- [x] T014 `IsDaemonRunning()` + `DaemonError()` 메서드 추가
- [ ] T015 E2E 테스트: sudo 데몬 시작 → GUI 연결 → 터널 동작 (수동 테스트)

---

## Phase 2: Kill Switch + DNS Leak Protection

**Description**: OS 방화벽으로 킬 스위치 + DNS 보호. 데몬에서 관리.
**Deliverables**: internal/firewall/
**Acceptance**: 킬 스위치 ON + VPN 강제 종료 → 인터넷 차단 확인

**Tasks**:
- [x] T016 `internal/firewall/interface.go` — FirewallManager 인터페이스
- [x] T017 `internal/firewall/darwin.go` — macOS pf anchor (com.wireguide) + DNS sub-anchor
- [x] T018 `internal/firewall/linux.go` — Linux nftables (inet wireguide table) + DNS table
- [x] T019 `internal/firewall/windows.go` — Windows netsh advfirewall rules
- [x] T020 `internal/daemon/service.go` — SetKillSwitch/SetDNSProtection 실제 구현
- [ ] T021 `frontend/src/lib/TunnelDetail.svelte` — 킬 스위치/DNS 토글 UI (Phase 5 polish)
- [x] T022 daemon.go graceful shutdown에서 firewall.Cleanup() 호출
- [ ] T023 E2E 테스트: 수동 (sudo 데몬 + 킬 스위치 활성화 + VPN 강제 종료)

---

## Phase 3: Auto-reconnect + Sleep/Wake

**Description**: 자동 재연결 (지수 백오프) + 죽은 연결 감지 + sleep/wake 복구.
**Deliverables**: internal/reconnect/
**Acceptance**: 네트워크 끊김 후 60초 이내 자동 재연결

**Tasks**:
- [x] T024 `internal/reconnect/monitor.go` — 핸드셰이크 모니터 (120초 타임아웃)
- [x] T025 `internal/reconnect/monitor.go` — 지수 백오프 (5s→60s max, 10회)
- [x] T026 `internal/reconnect/sleep_darwin.go` — macOS wall clock gap 감지
- [x] T027 `internal/reconnect/sleep_linux.go` — Linux wall clock gap 감지
- [x] T028 `internal/reconnect/sleep_windows.go` — Windows wall clock gap 감지
- [x] T029 데몬에 monitor 통합 (daemon.go에서 Start/Stop)
- [ ] T030 frontend 재연결 상태 표시 — Phase 5 polish
- [ ] T031 E2E 테스트 — 수동 (네트워크 끊기 + sleep/wake)

---

## Phase 4: CodeMirror 6 + Dark/Light Mode + Auto-start

**Description**: 에디터 업그레이드, 테마 시스템, 자동 시작.
**Deliverables**: ConfigEditor.svelte, Settings.svelte, 테마 CSS
**Acceptance**: CodeMirror로 .conf 편집 + 시스템 테마 추종 + 부팅 시 자동 시작

**Tasks**:
- [x] T032 CodeMirror 6 npm 패키지 설치 (@codemirror/view, state, language, autocomplete, theme-one-dark)
- [x] T033 `wireguard-lang.js` — 커스텀 StreamLanguage (섹션 헤더, 키워드, 키, IP, 스크립트 구분)
- [x] T034 자동완성: 섹션별 키워드 (Interface 11개, Peer 5개) + 섹션 헤더
- [x] T035 `ConfigEditor.svelte` — CodeMirror 6 Svelte 래퍼 (oneDark 테마, line numbers, history)
- [x] T036 `style.css` — CSS 변수 테마 (dark/light/system with prefers-color-scheme)
- [x] T037 `Settings.svelte` — 테마/언어/자동시작/재연결/로그레벨 설정
- [x] T038 `install.go` — macOS LaunchAgent plist
- [x] T039 `install.go` — Linux XDG autostart desktop entry
- [x] T040 `install.go` — Windows Registry Run key

---

## Phase 5: Log Viewer + OS Notifications + Polish

**Description**: 로그 뷰어, OS 알림, 전체 통합 테스트.
**Deliverables**: LogViewer.svelte, 알림 시스템
**Acceptance**: 로그 필터링 + 연결 끊김 시 OS 알림

**Tasks**:
- [ ] T041 `internal/daemon/logger.go` — 구조화된 로그 시스템 (gRPC로 GUI에 스트리밍)
- [ ] T042 `LogViewer.svelte` — 로그 뷰어 (레벨 필터: debug/info/warn/error, 자동 스크롤)
- [ ] T043 OS 알림: macOS (NSUserNotification / UNUserNotificationCenter)
- [ ] T044 OS 알림: Linux (libnotify / D-Bus)
- [ ] T045 OS 알림: Windows (toast notification)
- [ ] T046 알림 이벤트: 연결 끊김, 재연결 성공, 킬 스위치 활성화, 에러
- [ ] T047 i18n: 새 UI 문자열 3개 언어 추가 (킬 스위치, 재연결, 로그 등)
- [ ] T048 macOS E2E 테스트 (데몬 설치 → GUI 실행 → 연결 → 킬 스위치 → sleep/wake)
- [ ] T049 전체 빌드 + README 업데이트

---

## Dependency Map

```
Phase 1 (Daemon + IPC)
 │
 ├──→ Phase 2 (Kill Switch) — 데몬 필요
 ├──→ Phase 3 (Reconnect) — 데몬 필요
 │
 └──→ Phase 4 (CodeMirror + Theme + Autostart) — 독립적
      │
      └──→ Phase 5 (Log + Notifications + Polish) — 전체 통합
```

## Notes

- **gRPC over UDS**: `google.golang.org/grpc` + Unix Socket (macOS/Linux), Named Pipe (Windows)
- **킬 스위치 기본 OFF**: 설정에서 토글, 터널별 오버라이드 가능
- **CodeMirror 6 풀 통합**: textarea 완전 교체
- **Phase 4는 Phase 2/3과 병렬 가능**: CodeMirror/테마는 데몬과 무관
