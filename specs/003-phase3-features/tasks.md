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
- [ ] T009 QR 디코딩 라이브러리 추가 (Go: `makiuchi-d/gozxing` 또는 JS: `jsQR`)
- [ ] T010 `internal/app/app.go` — ImportFromQR 바인딩 (이미지 파일 → QR 디코딩 → .conf 파싱)
- [ ] T011 `frontend/src/lib/ImportDialog.svelte` — QR import 버튼 + 이미지 파일 선택
- [ ] T012 `internal/config/keygen.go` — WireGuard 키페어 생성 (Curve25519)
- [ ] T013 `frontend/src/lib/KeyGenerator.svelte` — 키 생성 UI + PublicKey 클립보드 복사
- [ ] T014 `internal/tunnel/stats.go` — 속도 히스토리 저장 (최근 60초 RX/TX 샘플)
- [ ] T015 `frontend/src/lib/StatsDashboard.svelte` — 실시간 속도 그래프 (Canvas/SVG)
- [ ] T016 `internal/storage/history.go` — 연결 이력 저장 (시작/종료 시간, 전송량)
- [ ] T017 `frontend/src/lib/StatsDashboard.svelte` — 연결 이력 탭

---

## Phase 3: Auto-update + Multi-tunnel + Conflict Detection

**Description**: GitHub Releases 자동 업데이트, 동시 멀티 터널, 충돌 감지
**Acceptance**: 멀티 터널 충돌 시 경고 + Tailscale 등 외부 감지

**Tasks**:
- [ ] T018 `internal/update/checker.go` — GitHub Releases API 버전 확인 + 다운로드
- [ ] T019 `internal/update/installer.go` — OS별 자동 설치 (macOS: DMG mount, Linux: dpkg/rpm, Windows: MSI)
- [ ] T020 `frontend/src/lib/UpdateNotice.svelte` — 업데이트 알림 + 설치 버튼
- [ ] T021 `internal/tunnel/manager.go` — 멀티 터널 지원 (단일 activeCfg → map[string]*Engine)
- [ ] T022 `internal/tunnel/conflict.go` — CIDR 겹침 검사 (새 AllowedIPs vs 기존 터널)
- [ ] T023 `internal/tunnel/conflict.go` — 외부 인터페이스 스캔 (utun/wg 인터페이스 목록 + UAPI 소켓 경로로 소유자 식별)
- [ ] T024 `internal/tunnel/conflict.go` — 라우팅 테이블 스캔 fallback (UAPI 없는 경우)
- [ ] T025 `frontend/src/lib/ConflictWarning.svelte` — 충돌 경고 다이얼로그 (어떤 인터페이스, 누구 소유, 어떤 대역 충돌)
- [ ] T026 gRPC: 멀티 터널 지원으로 Connect/Disconnect/Status 확장

---

## Phase 4: Mini Mode + Keyboard Shortcuts + Diagnostics

**Description**: 미니 모드, 키보드 단축키, 네트워크 진단
**Acceptance**: 미니 모드 전환 + Cmd+1~9 터널 전환

**Tasks**:
- [ ] T027 `frontend/src/lib/MiniMode.svelte` — 작은 플로팅 위젯 (상태 + 연결/해제 토글)
- [ ] T028 Wails v3 미니 모드 창 설정 (작은 크기, 항상 위, 드래그 가능)
- [ ] T029 키보드 단축키: Cmd/Ctrl+1~9 터널 선택 + 연결
- [ ] T030 글로벌 VPN 토글 핫키 등록
- [ ] T031 `internal/diag/cidr.go` — CIDR 계산기 (네트워크/브로드캐스트/호스트 범위)
- [ ] T032 `internal/diag/ping.go` — 엔드포인트 도달 테스트 (ICMP ping)
- [ ] T033 `internal/diag/speed.go` — 속도 테스트 (HTTP 다운로드 측정)
- [ ] T034 `frontend/src/lib/Diagnostics.svelte` — 진단 도구 UI

---

## Phase 5: DNS Leak Test + Route Visualization + Polish

**Description**: DNS 누출 테스트, 라우트 시각화, README
**Acceptance**: DNS 테스트 결과 표시 + 라우트 그래픽 시각화

**Tasks**:
- [ ] T035 `internal/diag/dnsleak.go` — DNS 누출 테스트 (외부 DNS 서버에 쿼리 → 응답 IP 확인)
- [ ] T036 `frontend/src/lib/DNSLeakTest.svelte` — DNS 테스트 결과 UI
- [ ] T037 `internal/diag/routes.go` — 현재 라우팅 테이블 조회 (OS별)
- [ ] T038 `frontend/src/lib/RouteVisualization.svelte` — 라우트 시각화 (대역 → 인터페이스 매핑 그래픽)
- [ ] T039 README.md 작성 (설치, 사용법, 스크린샷, 향후 계획 — 앱별 스플릿 "향후 검토" 포함)
- [ ] T040 i18n: 모든 새 UI 문자열 3개 언어 완성
- [ ] T041 전체 빌드 + E2E 테스트

---

## Notes

- **앱별 스플릿 터널링**: 제외 — README에 "향후 검토" 기재
- **자동 업데이트**: 다운로드 + OS별 자동 설치까지
- **멀티 터널 충돌**: CIDR 겹침 + UAPI 소켓/프로세스로 외부 인터페이스 소유자 식별
- **CI/CD**: 이 feature에 포함하지 않음 — 별도 마지막 phase로 진행
