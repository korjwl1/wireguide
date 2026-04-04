# Tasks: WireGuide — WireGuard Desktop Client MVP

**Input**: `specs/001-wireguard-mvp/plan.md` + `wireguard-app.md` Phase 1
**Prerequisites**: plan.md (완료), clarification decisions (완료)

## Execution Strategy

Solo 개발이므로 Sequential 방식:
```
WP00 → WP01 → WP02 → WP03 → WP04 → WP05/06(병렬) → WP07 → WP08
```

**타겟**: macOS + Windows + Linux 3 OS 동시
**i18n**: 영어/한국어/일본어 MVP부터 지원
**Pre/PostUp**: 경고 다이얼로그 후 실행 허용

---

## Phase 0: Foundation Slice

### WP00: Project Bootstrap

**Vertical Scope**: Go + Wails v3 프로젝트 초기화 + 핵심 스택 검증 (빈 앱 실행 + 트레이 + 바인딩 + wireguard-go 빌드)

| Layer | Deliverable |
|-------|-------------|
| Environment | Go 1.26.1 + Wails v3 CLI 설치 |
| Backend | Go 모듈 초기화, 패키지 구조 생성, wireguard-go 의존성 |
| Frontend | Svelte + Vite + TypeScript 초기화 |
| Config | Wails v3 설정 (alpha.74 pinned) |
| Verification | 5가지 스택 검증 (아래 참조) |

**Tasks**:
- [x] T001 환경 설정: Go 1.26.1 설치 (`brew install go`) + Wails v3 CLI 설치 (`go install ...wails3@v3.0.0-alpha.74`) + `wails3 doctor`
- [x] T002 Wails v3 프로젝트 초기화 (`wails3 init -n wireguide -t svelte`)
- [x] T003 `internal/` 패키지 디렉토리 구조 생성 (config, tunnel, network, storage, app) + `build/` 디렉토리
- [x] T004 wireguard-go, wgctrl-go, wintun 의존성 추가 (`go get`) + `go build` 성공 확인
- [x] T005 Go ↔ Svelte 바인딩 라운드트립 검증 (Go 메서드 호출 → 결과 Svelte에 표시)
- [x] T006 시스템 트레이 조기 검증 (기본 아이콘 + "WireGuide" 툴팁 + 메뉴 표시)
- [x] T007 `wails3 dev`로 빈 앱 실행 확인 (창 렌더링 + 트레이 아이콘)

**Checkpoint (5가지 검증)**:
1. `wails3 dev` → Svelte 창 렌더링 ✓
2. Go 메서드 → Svelte 호출 바인딩 동작 ✓
3. 시스템 트레이 아이콘 + 메뉴 표시 ✓
4. wireguard-go import 후 `go build` 성공 ✓
5. `go test ./internal/...` 실행 가능 ✓

---

## Phase 1: Core Slices (MVP)

### WP01: .conf Parser + Validator

**Vertical Scope**: WireGuard .conf 파일을 파싱하고 유효성 검사하는 핵심 라이브러리

| Layer | Deliverable |
|-------|-------------|
| Backend | `internal/config/` — parser, validator, types |
| Test | 파서 단위 테스트 (유효/무효 .conf 케이스) |

**Acceptance Criteria**:
- [x] [Interface] + [Peer] 섹션을 구조체로 파싱
- [x] 다중 [Peer] 지원
- [x] 필수 필드 누락 시 구체적 에러 ("PrivateKey가 없습니다")
- [x] 키 형식 (Base64 32바이트), CIDR 형식, Endpoint 형식 검증
- [x] PreUp/PostUp/PreDown/PostDown 필드 감지 + 경고 플래그
- [x] 구조체 → .conf 텍스트 직렬화 (export용)

**Tasks**:
- [ ] T007 `internal/config/types.go` — WireGuardConfig, InterfaceConfig, PeerConfig 타입 정의
- [x] T008 `internal/config/parser.go` — INI 파싱 로직 (직접 구현, 외부 의존성 없음)
- [x] T009 `internal/config/validator.go` — 유효성 검사 (키, CIDR, endpoint, 필수 필드)
- [x] T010 스크립트 감지 — types.go의 HasScripts()/Scripts() 메서드로 구현 (별도 파일 불필요)
- [x] T011 `internal/config/parser_test.go` — 18개 테스트: 정상 .conf, 필드 누락, 형식 오류, 다중 Peer, PreUp 경고
- [x] T012 직렬화: Serialize() 함수 + 라운드트립 테스트

**Deploy Check**: 라이브러리이므로 독립 테스트 가능 ✓

---

### WP02: Storage Layer (터널/설정 저장)

**Vertical Scope**: 터널 .conf 파일 및 앱 설정을 파일시스템에 저장/로드

| Layer | Deliverable |
|-------|-------------|
| Backend | `internal/storage/` — tunnels, settings, paths |
| Test | 저장/로드/삭제 단위 테스트 |

**Acceptance Criteria**:
- [x] OS별 올바른 경로에 저장 (macOS: ~/Library/..., Windows: %APPDATA%/..., Linux: ~/.config/...)
- [x] .conf 파일 퍼미션 0600 적용
- [x] 터널 CRUD (Create, Read, Update, Delete)
- [x] 앱 설정 JSON 로드/저장
- [x] 터널 목록 조회

**Tasks**:
- [x] T013 `internal/storage/paths.go` — OS별 경로 헬퍼 + EnsureDirs()
- [x] T014 `internal/storage/tunnels.go` — 터널 CRUD + ImportFromContent + 파일 퍼미션 0600
- [x] T015 `internal/storage/settings.go` — 앱 설정 JSON + DefaultSettings() (언어, 테마 등)
- [x] T016 단위 테스트: 13개 테스트 (CRUD, 퍼미션, 경로, import, 설정 기본값)

**Deploy Check**: 라이브러리이므로 독립 테스트 가능 ✓

**Dependencies**: WP01 (Config 타입 사용)

---

### WP03: WireGuard Engine + OS Networking

**Vertical Scope**: wireguard-go 임베딩으로 실제 VPN 터널을 생성/연결/해제하고, OS별 IP/라우팅/DNS 설정

| Layer | Deliverable |
|-------|-------------|
| Backend | `internal/tunnel/` — engine, manager, status |
| Backend | `internal/network/` — OS별 네트워킹 구현 |
| Test | 연결/해제 통합 테스트 (실제 인터페이스, sudo 필요) |

**Acceptance Criteria**:
- [x] wireguard-go로 TUN 디바이스 생성
- [x] wgctrl-go로 WireGuard 설정 (키, 피어, 엔드포인트) 적용
- [x] IP 주소 할당 (OS별)
- [x] 라우팅 테이블 설정 (AllowedIPs 기반, 풀터널 0.0.0.0/0 포함)
- [x] DNS 설정 (OS별)
- [x] 연결 해제 시 인터페이스/라우트/DNS 정리
- [x] 연결 상태 조회 (RX/TX 바이트, 핸드셰이크 시간, 연결 시간)
- [x] macOS/Windows/Linux 3 OS 모두 컴파일 가능 (통합 테스트는 sudo 필요)
- [x] PreUp/PostUp 스크립트 경고 후 실행 허용

**Tasks**:
- [x] T017 `internal/tunnel/engine.go` — wireguard-go TUN 생성 + WG 디바이스 시작
- [x] T018 `internal/tunnel/engine.go` — wgctrl-go로 설정 적용 (private key, peers, allowed IPs, keepalive)
- [x] T019 `internal/network/interface.go` — NetworkManager 인터페이스 정의
- [x] T020 `internal/network/darwin.go` — macOS: ifconfig IP, route 라우팅, networksetup DNS
- [x] T021 `internal/network/linux.go` — Linux: ip 명령 기반 IP/라우팅, resolvconf DNS
- [x] T022 `internal/network/windows.go` — Windows: netsh 기반 IP/라우팅/DNS
- [x] T023 `internal/tunnel/manager.go` — 터널 연결/해제 오케스트레이션 (engine + network + scripts)
- [x] T024 `internal/tunnel/manager.go` — Pre/PostUp/Down 스크립트 실행 (scriptsAllowed 플래그)
- [x] T025 `internal/tunnel/status.go` — ConnectionStatus + GetStatus() + formatDuration()
- [x] T026 풀터널 macOS: 스플릿 라우트 (0.0.0.0/1 + 128.0.0.0/1 + 엔드포인트 바이패스)
- [x] T027 풀터널 Linux: fwmark 정책 라우팅 + suppress_prefixlength
- [x] T028 풀터널 Windows: 인터페이스 메트릭 조정
- [x] T029 연결 해제 시 정리 (RemoveRoutes + RestoreDNS + Cleanup)
- [x] T030 `internal/tunnel/recovery.go` — 크래시 복구 (5개 테스트 통과)
- [ ] T031 macOS 통합 테스트 (`sudo` 필요 — 실제 WG 서버 환경에서 수동 테스트)
- [ ] T032 Linux 통합 테스트 (CI 환경에서 테스트 예정)
- [ ] T033 Windows 통합 테스트 (CI 환경에서 테스트 예정)

**Deploy Check**: CLI로 독립 테스트 가능 ✓ (임시 main.go에서 연결 테스트)

**Dependencies**: WP01 (Config 타입), WP02 (설정 저장)

---

### WP04: Main UI — 터널 목록 + 상세 + 연결

**Vertical Scope**: 메인 화면 UI (좌우 분할: 터널 목록 + 상세 패널 + 연결/해제)

| Layer | Deliverable |
|-------|-------------|
| Backend | `internal/app/app.go` — Wails 바인딩 (터널 CRUD, 연결/해제, 상태 조회) |
| Frontend | TunnelList, TunnelDetail, StatusBar 컴포넌트 |
| Integration | Go ↔ Svelte 바인딩 연결 |

**Acceptance Criteria**:
- [x] 좌측에 터널 목록 표시 (이름 + 상태 아이콘 ●/○)
- [x] 터널 선택 시 우측에 상세 정보 표시
- [x] 연결/해제 버튼 동작
- [x] 연결 중 실시간 상태 표시 (RX/TX 속도, 핸드셰이크, 연결 시간)
- [x] 터널 삭제 동작
- [x] 신호등 색상 시스템 (초록/노랑/빨강)
- [x] 다크 모드 기본 테마

**Tasks**:
- [x] T034 `internal/app/app.go` — TunnelService (ListTunnels, Connect, Disconnect, GetStatus, DeleteTunnel, ImportConfig, ValidateConfig, GetConfigText, UpdateConfig, ExportConfig, GetSettings, SaveSettings)
- [x] T035 i18n — en.json + ko.json + ja.json + index.js (시스템 언어 감지)
- [x] T036 stores/tunnels.js — tunnels, selectedTunnel, connectionStatus stores + 1초 폴링
- [x] T037 TunnelList.svelte — 터널 목록 (검색, 상태 dot, 선택 하이라이팅, empty state)
- [x] T038 TunnelDetail.svelte — 상세 패널 (상태 배지, stats grid, 연결/해제/편집/삭제)
- [x] T039 StatusBar — TunnelDetail에 stats grid로 통합 (RX/TX, handshake, duration)
- [x] T040 ScriptWarning — 기본 구현 (Connect 시 has_scripts 체크, WP05에서 UI 확장)
- [x] T041 App.svelte — 좌우 분할 + import/editor 모달 + drag-and-drop
- [x] T042 연결 상태 폴링 (1초 간격 stores/tunnels.js)
- [x] T043 CSS 테마 — 다크 모드 (#1a1a2e), 신호등 (#00b894/#fdcb6e/#d63031)

**Deploy Check**: Wails dev로 확인 가능 ✓

**Dependencies**: WP00 (Wails), WP01 (Config), WP02 (Storage), WP03 (Engine)

---

### WP05: Config Import + Validation UI

**Vertical Scope**: .conf 파일 가져오기 (드래그 앤 드롭 + 파일 선택 + 클립보드) + 유효성 검사 UI

| Layer | Deliverable |
|-------|-------------|
| Backend | Import 바인딩 (파일 읽기 + 파싱 + 저장) |
| Frontend | ImportDialog 컴포넌트 (드롭존 + 파일 선택 + 미리보기 + 에러) |

**Acceptance Criteria**:
- [ ] 드래그 앤 드롭으로 .conf import
- [ ] 파일 선택 다이얼로그로 import
- [ ] 클립보드 붙여넣기로 import
- [ ] Import 시 유효성 검사 → 구체적 에러 메시지 표시
- [ ] 유효한 파일은 요약 미리보기 (터널명, 엔드포인트, AllowedIPs, DNS) 후 확인
- [ ] 첫 실행 시 empty state가 드롭존
- [ ] .conf 더블클릭으로 앱 열림 (OS 파일 연동 — 가능한 범위에서)

**Tasks**:
- [ ] T044 `internal/app/app.go` — ImportFromFile, ImportFromClipboard, ValidateConfig 바인딩
- [ ] T045 `ImportDialog.svelte` — 드롭존 UI + 파일 선택 버튼 + 클립보드 버튼
- [ ] T046 Import 미리보기 화면 (파싱 결과 요약 + PreUp/PostUp 경고 표시)
- [ ] T047 유효성 검사 에러 표시 (구체적 에러 목록, i18n 적용)
- [ ] T048 Empty state — 터널이 없을 때 드롭존 + 안내 텍스트
- [ ] T049 OS 파일 연동 — .conf 더블클릭 시 앱 열림 (OS 지원 범위에서만)

**Deploy Check**: 독립 테스트 가능 ✓

**Dependencies**: WP01 (Parser), WP02 (Storage), WP04 (Main UI)

---

### WP06: Config Editor + Export

**Vertical Scope**: .conf 내용 편집 (텍스트 에디터) + 파일 내보내기

| Layer | Deliverable |
|-------|-------------|
| Backend | Config 업데이트 + Export 바인딩 |
| Frontend | ConfigEditor 컴포넌트 (textarea + 저장/취소) |

**Acceptance Criteria**:
- [ ] 터널 상세에서 "편집" 클릭 → Config 에디터 열림
- [ ] textarea에 .conf 전체 텍스트 표시 + 편집
- [ ] 저장 시 유효성 검사 → 통과하면 저장, 실패하면 에러 표시
- [ ] 취소 시 원래 상태로 복원
- [ ] Export: 현재 터널의 .conf를 파일로 저장 (OS 파일 저장 다이얼로그)

**Tasks**:
- [ ] T050 `internal/app/app.go` — UpdateTunnelConfig, ExportConfig 바인딩
- [ ] T051 `ConfigEditor.svelte` — textarea 에디터 (줄번호는 CSS로)
- [ ] T052 저장 시 유효성 검사 + 에러 인라인 표시 (i18n 적용)
- [ ] T053 Export 기능 — Wails SaveFileDialog + .conf 파일 쓰기

**Deploy Check**: 독립 테스트 가능 ✓

**Dependencies**: WP01 (Parser/Validator), WP02 (Storage), WP04 (Main UI)

---

### WP07: System Tray

**Vertical Scope**: 시스템 트레이 아이콘 + 컨텍스트 메뉴 + 상태 표시

| Layer | Deliverable |
|-------|-------------|
| Backend | 트레이 아이콘 관리 + 메뉴 구성 |
| Asset | 아이콘 세트 (연결/미연결/연결중 상태별) |

**Acceptance Criteria**:
- [ ] macOS 메뉴바 / Windows 시스템 트레이 / Linux 트레이에 아이콘 표시
- [ ] 아이콘 상태 변경: 초록(연결), 회색(미연결), 노랑(연결중)
- [ ] 우클릭 컨텍스트 메뉴: 터널 목록 (연결/해제 인라인 토글), 설정 열기, 종료
- [ ] 창 닫기 시 트레이로 최소화 (종료가 아님)
- [ ] 트레이 아이콘 클릭 시 메인 창 표시/숨기기

**Tasks**:
- [ ] T054 아이콘 에셋 준비 — VPN 로고 + 상태별 초록점/회색/노랑 (각 OS 해상도별)
- [ ] T055 Wails v3 시스템 트레이 본격 구성 (WP00 검증 기반 확장)
- [ ] T056 컨텍스트 메뉴 — 터널 목록 + 연결/해제 토글 + 설정 + 종료 (i18n 적용)
- [ ] T057 연결 상태에 따른 아이콘 동적 변경 (VPN 로고 + 초록점)
- [ ] T058 창 닫기 → 트레이 최소화 동작
- [ ] T059 트레이 아이콘 클릭 → 창 표시/숨기기

**Deploy Check**: Wails dev로 확인 가능 ✓

**Dependencies**: WP00 (Wails), WP03 (Engine 상태), WP04 (Main UI)

---

## Phase 2: Integration & Polish

### WP08: End-to-End Integration + Polish

**Vertical Scope**: 전체 기능 연결, 에러 핸들링 강화, UX 마무리

| Area | Deliverable |
|------|-------------|
| Integration | 모든 WP 연결 + 에지 케이스 처리 |
| UX | 에러 메시지 한국어/영어, 로딩 상태, 전환 애니메이션 |
| Security | .conf 파일 퍼미션 재확인, 입력값 검증 |
| Test | E2E 수동 테스트 (macOS 우선) |

**Tasks**:
- [ ] T060 연결 실패 시 사용자 친화적 에러 메시지 (네트워크 오류, 키 불일치 등) — 3개 언어
- [ ] T061 연결 상태 전환 애니메이션 (색상 트랜지션 300ms)
- [ ] T062 i18n 번역 완성도 검수 (en/ko/ja 전체 키 매칭 확인)
- [ ] T063 macOS E2E 테스트 (import → 연결 → 상태 확인 → 해제 → export)
- [ ] T064 Linux E2E 테스트
- [ ] T065 Windows E2E 테스트
- [ ] T066 빌드 스크립트 정리 + README 작성

---

## Dependency Map

```
WP00 (Project Bootstrap)
 │
 ├──→ WP01 (.conf Parser) ─────────────────────────────→ 독립 실행 가능
 │     │
 │     ├──→ WP02 (Storage) ─────────────────────────────→ 독립 실행 가능
 │     │     │
 │     │     ├──→ WP03 (WireGuard Engine + Networking) ─→ CLI 테스트 가능
 │     │     │     │
 │     │     │     ├──→ WP04 (Main UI) ─────────────────→ Wails dev 실행
 │     │     │     │     │
 │     │     │     │     ├──→ WP05 (Import + Validation)
 │     │     │     │     ├──→ WP06 (Editor + Export)
 │     │     │     │     └──→ WP07 (System Tray)
 │     │     │     │           │
 │     │     │     │           └──→ WP08 (Integration)
```

## Notes

- **프로젝트명**: wireguide
- **Go 1.25+** (Wails v3 요구사항). 권장: Go 1.26.1
- **Wails v3 alpha.74 pinned** — `internal/app/` 어댑터 레이어로 API 격리
- **권한 상승**: macOS(osascript), Linux(pkexec), Windows(매니페스트 requireAdministrator)
- **3 OS 동시 개발**: macOS/Windows/Linux — WP03에서 셋 다 구현, WP08에서 각각 E2E 테스트
- **i18n**: MVP부터 영어/한국어/일본어 3개 언어. WP04에서 구조 세팅, 모든 UI 컴포넌트에 적용.
- **PreUp/PostUp**: 경고 다이얼로그로 사용자 확인 후 실행. WP01에서 감지, WP03에서 실행, WP04에서 UI.
- **크래시 복구**: WP03에서 활성 터널 상태 파일 + 시작 시 고아 정리 구현
- **트레이 아이콘**: VPN 로고 + 초록점(연결). 모노크롬 옵션 MVP 제외.
- **터널 수**: 제한 없음. 파일 연동: OS 지원 범위에서만.
- **wireguard-go**: MIT, 순수 Go (CGO 불필요). 크로스 컴파일 용이.
- **wintun.dll**: Windows 빌드 시 번들 필요 (MIT 라이선스)
- **총 태스크**: 9 WP, 66 Tasks
