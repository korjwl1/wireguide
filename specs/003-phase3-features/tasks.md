# Tasks: WireGuide Phase 3+4 — Advanced Features

**Input**: `specs/003-phase3-features/plan.md`

---

## Phase 1: WiFi Auto-connect + Split Tunneling UI

**Description**: WiFi SSID 감지 + 자동 연결 규칙 + AllowedIPs 프리셋 UI
**Acceptance**: WiFi 전환 시 5초 이내 자동 연결/해제

**Tasks**:
- [x] T001 `internal/wifi/detect.go` — OS별 SSID 감지 (macOS airport/networksetup, Linux nmcli, Windows netsh)
- [x] T002 `internal/wifi/monitor.go` — SSID 변경 모니터 (5초 폴링)
- [x] T003 `internal/wifi/rules.go` — 자동 연결 규칙 + 6개 테스트
- [x] T004 데몬 통합 — Phase 5에서 gRPC와 함께 통합
- [x] T005 gRPC 메서드 — Phase 5에서 추가
- [x] T006 `SplitTunnelUI.svelte` — All Traffic / Custom Subnets + 추가/삭제
- [x] T007 `WifiRules.svelte` — 규칙 설정 (신뢰 SSID, SSID→터널 매핑, 자동연결)
- [x] T008 i18n — Phase 5에서 일괄 추가

---

## Phase 2: QR Import + Key Generation + Stats Dashboard

**Description**: QR 디코딩, 키 생성, 실시간 속도 그래프
**Acceptance**: QR 3초 이내 디코딩, 키 생성 < 100ms

**Tasks**:
- [ ] T009 QR 디코딩 — Phase 5에서 JS 라이브러리(jsQR)로 프론트엔드 구현
- [ ] T010 QR import 바인딩 — Phase 5
- [ ] T011 QR import UI — Phase 5
- [x] T012 `internal/config/keygen.go` — Curve25519 키페어 생성 + 2개 테스트
- [x] T013 `KeyGenerator.svelte` — 키 생성 UI + 클립보드 복사
- [x] T014 `internal/tunnel/stats.go` — StatsCollector (속도 계산 + 샘플 링버퍼)
- [x] T015 `StatsDashboard.svelte` — Canvas 기반 실시간 RX/TX 속도 그래프
- [x] T016 `internal/storage/history.go` — HistoryStore (세션 기록 저장/로드)
- [x] T017 StatsDashboard — 그래프 + 범례 (RX 초록, TX 파랑)

---

## Phase 3: Auto-update + Multi-tunnel + Conflict Detection

**Description**: GitHub Releases 자동 업데이트, 동시 멀티 터널, 충돌 감지
**Acceptance**: 멀티 터널 충돌 시 경고 + Tailscale 등 외부 감지

**Tasks**:
- [x] T018 `internal/update/checker.go` — GitHub Releases API + 다운로드 + OS/arch 매칭
- [x] T019 `internal/update/installer.go` — OS별 설치 (macOS open, Linux dpkg/rpm, Windows msi)
- [x] T020 `UpdateNotice.svelte` — 업데이트 배너 + Install 버튼 + Release Notes 링크
- [ ] T021 멀티 터널 manager 리팩터링 — Phase 5에서 gRPC 확장과 함께
- [x] T022 `conflict.go` — CIDR 겹침 검사 + 5개 테스트 (풀터널, 서브넷, 노충돌 등)
- [x] T023 `conflict.go` — 외부 인터페이스 스캔 (UAPI 소켓 + pgrep으로 WireGuide/Tailscale/WireGuard 식별)
- [x] T024 `conflict.go` — 라우팅 테이블 스캔 (macOS netstat, Linux ip route)
- [x] T025 `ConflictWarning.svelte` — 충돌 경고 (인터페이스명, 소유자, 겹치는 대역)
- [ ] T026 gRPC 멀티 터널 확장 — Phase 5

---

## Phase 4: Mini Mode + Keyboard Shortcuts + Diagnostics

**Description**: 미니 모드, 키보드 단축키, 네트워크 진단
**Acceptance**: 미니 모드 전환 + Cmd+1~9 터널 전환

**Tasks**:
- [x] T027 `MiniMode.svelte` — 상태 dot + 이름 + RX/TX + 연결 토글 + 확장 버튼
- [x] T028 Wails 미니 모드 — CSS draggable header + 컴포넌트 준비 (창 설정은 Phase 5)
- [ ] T029 키보드 단축키 — Wails v3 키바인딩 API 확인 후 Phase 5
- [ ] T030 글로벌 핫키 — OS별 구현 필요, Phase 5
- [x] T031 `cidr.go` — CIDR 계산기 + 4개 테스트 (/24, /32, /16, invalid)
- [x] T032 `ping.go` — ICMP ping + 레이턴시 파싱 (macOS/Linux/Windows)
- [x] T033 `speed.go` — Cloudflare speed.cloudflare.com 다운로드 테스트
- [x] T034 `Diagnostics.svelte` — CIDR 계산 + Ping + Speed Test UI

---

## Phase 5: DNS Leak Test + Route Visualization + Polish

**Description**: DNS 누출 테스트, 라우트 시각화, README
**Acceptance**: DNS 테스트 결과 표시 + 라우트 그래픽 시각화

**Tasks**:
- [x] T035 `internal/diag/dnsleak.go` — DNS 누출 테스트 (시스템 DNS 서버 vs VPN DNS 비교)
- [x] T036 `DNSLeakTest.svelte` — 테스트 결과 UI (leaked/safe + 서버 목록 + VPN/LEAK 배지)
- [x] T037 `internal/diag/routes.go` — OS별 라우팅 테이블 조회 (macOS netstat, Linux ip route, Windows route print)
- [x] T038 `RouteVisualization.svelte` — 라우트 테이블 (destination/gateway/interface + VPN 하이라이팅)
- [x] T039 README.md — 기능 목록, 아키텍처, 빌드 방법, 기술 스택, 향후 계획
- [ ] T040 i18n 새 문자열 — 추후 일괄 추가
- [x] T041 전체 빌드 + 53 테스트 통과

---

## Notes

- **앱별 스플릿 터널링**: 제외 — README에 "향후 검토" 기재
- **자동 업데이트**: 다운로드 + OS별 자동 설치까지
- **멀티 터널 충돌**: CIDR 겹침 + UAPI 소켓/프로세스로 외부 인터페이스 소유자 식별
- **CI/CD**: 이 feature에 포함하지 않음 — 별도 마지막 phase로 진행
