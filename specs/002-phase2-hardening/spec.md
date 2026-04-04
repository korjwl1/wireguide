# Feature Specification: WireGuide Phase 2 — Hardening & UX

**Feature Branch**: `002-phase2-hardening`
**Created**: 2026-04-05
**Status**: Draft
**Input**: `wireguard-app.md` Phase 2 + Phase 3 일부

## User Scenarios & Testing

### User Story 1 - 권한 분리: sudo 없이 앱 사용 (Priority: P1)

사용자는 앱을 일반 사용자로 실행하고, 네트워크 작업(TUN 생성, 라우팅, DNS)만 특권 데몬이 처리하도록 하고 싶다. 매번 sudo를 입력하지 않아야 한다.

**Why this priority**: 배포의 전제조건. sudo로 GUI 앱을 실행하는 것은 보안 위험이며 사용자 경험이 나쁨.

**Independent Test**: 앱을 일반 사용자로 실행 → 터널 연결 시 비밀번호 프롬프트 없이 동작 확인.

**Acceptance Scenarios**:

1. **Given** 데몬이 설치된 상태, **When** 사용자가 `wireguide`를 일반 사용자로 실행하면, **Then** GUI가 정상 표시되고 데몬과 IPC로 통신한다.

2. **Given** GUI에서 터널 연결 요청, **When** 데몬이 TUN 생성 + 라우팅 설정을 수행하면, **Then** 사용자에게 추가 비밀번호 입력 없이 연결된다.

3. **Given** 데몬이 실행 중이 아닌 상태, **When** GUI를 실행하면, **Then** "데몬이 실행되지 않고 있습니다" 메시지와 설치 안내가 표시된다.

---

### User Story 2 - 킬 스위치 + DNS 누출 방지 (Priority: P1)

VPN이 끊겼을 때 인터넷 트래픽이 VPN 밖으로 나가는 것을 차단하고, DNS 요청도 VPN 터널을 통해서만 나가야 한다.

**Why this priority**: VPN의 핵심 보안 기능. 이게 없으면 VPN을 쓰는 의미가 반감.

**Independent Test**: VPN 연결 후 킬 스위치 ON → 터널 강제 종료 → 인터넷 접속 불가 확인.

**Acceptance Scenarios**:

1. **Given** 킬 스위치가 ON이고 VPN이 연결된 상태, **When** VPN 연결이 예기치 않게 끊기면, **Then** 모든 인터넷 트래픽이 차단되고 "BLOCKING" 상태가 표시된다.

2. **Given** 킬 스위치가 ON이고 차단 중인 상태, **When** VPN이 재연결되면, **Then** 트래픽 차단이 해제되고 정상 통신이 재개된다.

3. **Given** DNS 보호가 ON인 상태, **When** VPN이 연결되면, **Then** DNS 쿼리가 VPN 터널의 DNS 서버로만 전송된다 (포트 53 필터링).

4. **Given** 킬 스위치가 OFF인 상태, **When** VPN이 끊기면, **Then** 인터넷은 정상 접속 가능 (기존 동작).

---

### User Story 3 - 자동 재연결 + 죽은 연결 감지 (Priority: P1)

VPN 연결이 끊기거나 핸드셰이크가 타임아웃되면 자동으로 재연결하고, sleep/wake 후에도 자동으로 복구한다.

**Why this priority**: 사용자가 VPN 상태를 항상 모니터링할 수 없음. 자동 재연결은 필수 편의 기능.

**Acceptance Scenarios**:

1. **Given** 자동 재연결이 ON인 상태, **When** VPN 연결이 끊기면, **Then** 5초 후 자동 재연결을 시도하고, 실패 시 지수 백오프로 재시도한다.

2. **Given** VPN이 연결된 상태, **When** 핸드셰이크가 2분 이상 없으면, **Then** "죽은 연결 감지" 경고가 표시되고 자동 재연결을 시도한다.

3. **Given** VPN이 연결된 상태에서 macOS가 sleep 진입, **When** wake되면, **Then** 자동으로 VPN 재연결을 시도한다.

---

### User Story 4 - CodeMirror 6 에디터 (Priority: P2)

Config 편집 시 WireGuard .conf 문법 하이라이팅과 키워드 자동완성을 제공하여 편집 실수를 줄인다.

**Why this priority**: UX 개선이지만 기능적으로 필수는 아님. 기존 textarea 대체.

**Acceptance Scenarios**:

1. **Given** 터널 편집 화면, **When** Config 에디터가 열리면, **Then** [Interface], [Peer] 섹션 헤더가 색상으로 하이라이팅된다.

2. **Given** 에디터에서 타이핑 중, **When** "Priv"를 입력하면, **Then** "PrivateKey" 자동완성 제안이 표시된다.

3. **Given** 에디터에 잘못된 키 형식이 입력된 상태, **When** 저장을 시도하면, **Then** 해당 줄에 인라인 에러가 표시된다.

---

### User Story 5 - 시작 시 자동 실행 (Priority: P2)

OS 부팅 시 앱이 자동으로 트레이에 최소화 상태로 시작되고, 마지막으로 연결되어 있던 터널에 자동 연결한다.

**Acceptance Scenarios**:

1. **Given** 자동 시작이 ON인 상태, **When** OS가 부팅되면, **Then** 앱이 트레이에 최소화 상태로 시작된다.

2. **Given** 자동 연결이 설정된 상태, **When** 앱이 시작되면, **Then** 지정된 터널에 자동 연결한다.

---

### User Story 6 - 다크/라이트 모드 (Priority: P2)

시스템 테마를 자동 감지하여 다크/라이트 모드를 전환하고, 수동 선택도 가능하다.

**Acceptance Scenarios**:

1. **Given** 테마가 "시스템"으로 설정, **When** OS가 다크 모드이면, **Then** 앱이 다크 테마로 표시된다.

2. **Given** 설정에서 테마를 "라이트"로 변경, **When** 적용되면, **Then** 즉시 라이트 테마로 전환된다.

---

### User Story 7 - 로그 뷰어 + OS 알림 (Priority: P3)

진단용 로그를 앱 내에서 확인하고, 연결/해제/에러 이벤트에 대해 OS 알림을 받는다.

**Acceptance Scenarios**:

1. **Given** 앱이 실행 중, **When** 로그 뷰어를 열면, **Then** 레벨별 필터링(debug/info/warn/error) 가능한 로그가 표시된다.

2. **Given** VPN 연결이 예기치 않게 끊긴 경우, **When** 이벤트가 발생하면, **Then** OS 알림("VPN 연결이 끊겼습니다")이 표시된다.

---

### Edge Cases

- 데몬이 크래시하면? → GUI에 "데몬 연결 끊김" 표시 + 재시작 시도
- 킬 스위치 ON 상태에서 데몬이 죽으면? → macOS pf / Windows WFP 동적 세션으로 규칙 자동 해제
- sleep 중 데몬이 죽으면? → wake 시 데몬 재시작 + 터널 복구
- 재연결이 10회 이상 실패하면? → 재연결 중단 + 사용자에게 알림
- CodeMirror 로딩 실패 시? → textarea fallback

## Requirements

### Functional Requirements

- **FR-001**: GUI는 비특권 프로세스로 실행되어야 한다
- **FR-002**: 데몬은 특권 프로세스(macOS: LaunchDaemon, Linux: systemd, Windows: SCM Service)로 실행되어야 한다
- **FR-003**: GUI ↔ 데몬 IPC는 Unix Socket (macOS/Linux) / Named Pipe (Windows)로 통신해야 한다
- **FR-004**: 킬 스위치는 OS 방화벽(macOS: pf, Windows: WFP, Linux: nftables)으로 구현해야 한다
- **FR-005**: DNS 누출 방지는 포트 53 트래픽을 VPN DNS로만 허용해야 한다
- **FR-006**: 자동 재연결은 지수 백오프(5s, 10s, 20s, 40s, max 60s)로 재시도해야 한다
- **FR-007**: 핸드셰이크 타임아웃(기본 120초)을 감지하고 경고 + 재연결해야 한다
- **FR-008**: sleep/wake 이벤트를 감지하고 자동 재연결해야 한다
- **FR-009**: CodeMirror 6으로 WireGuard .conf 문법 하이라이팅 + 키워드 자동완성을 제공해야 한다
- **FR-010**: OS 부팅 시 자동 시작을 지원해야 한다 (macOS: LaunchAgent, Linux: XDG autostart, Windows: Registry Run)
- **FR-011**: 시스템 테마 감지 + 수동 테마 전환을 지원해야 한다
- **FR-012**: 앱 내 로그 뷰어(레벨 필터링)를 제공해야 한다
- **FR-013**: 연결/해제/에러 이벤트에 대해 OS 알림을 전송해야 한다

### Key Entities

- **Daemon**: 특권 프로세스. TUN 생성, 라우팅, DNS, 킬 스위치, 방화벽 관리.
- **IPC Protocol**: GUI ↔ 데몬 통신 프로토콜 (Connect, Disconnect, Status, ListTunnels 등).
- **Firewall Rules**: 킬 스위치 + DNS 보호용 OS 방화벽 규칙.
- **Reconnect State**: 자동 재연결 상태 (시도 횟수, 백오프 타이머, 최대 재시도).

## Success Criteria

- **SC-001**: 일반 사용자로 앱 실행 → 비밀번호 입력 없이 터널 연결/해제 가능
- **SC-002**: 킬 스위치 ON + VPN 강제 종료 시 인터넷 트래픽 0 (leak test 통과)
- **SC-003**: 네트워크 끊김 후 60초 이내 자동 재연결 완료
- **SC-004**: sleep → wake 후 10초 이내 자동 재연결 완료
- **SC-005**: CodeMirror 에디터에서 WireGuard 키워드 하이라이팅 동작
- **SC-006**: OS 부팅 후 앱이 자동 시작되어 트레이에 표시
