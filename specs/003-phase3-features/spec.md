# Feature Specification: WireGuide Phase 3+4 — Advanced Features

**Feature Branch**: `003-phase3-features`
**Created**: 2026-04-05
**Status**: Draft
**Input**: `wireguard-app.md` Phase 3 (#21-26) + Phase 4 (#28-35), CI/CD 제외

## User Scenarios & Testing

### User Story 1 - WiFi SSID 기반 자동 연결 (Priority: P1)

특정 WiFi에 연결되면 자동으로 VPN이 켜지고, 신뢰하는 WiFi에서는 꺼진다. 매번 수동으로 VPN을 켜고 끄지 않아도 된다.

**Acceptance Scenarios**:

1. **Given** "회사WiFi"를 자동 연결 SSID로 설정, **When** 해당 WiFi에 연결되면, **Then** 지정된 터널이 자동 연결된다.
2. **Given** "집WiFi"를 신뢰 SSID로 설정, **When** 해당 WiFi에 연결되면, **Then** VPN이 자동 해제된다.
3. **Given** 알 수 없는 WiFi에 연결, **When** "신뢰하지 않는 네트워크 자동 연결"이 ON이면, **Then** 기본 터널이 자동 연결된다.

---

### User Story 2 - 스플릿 터널링 UI (Priority: P1)

AllowedIPs를 쉽게 설정할 수 있는 UI. "모든 트래픽" / "지정 대역만" 프리셋을 제공하고, CIDR를 직접 입력하지 않아도 된다.

**Acceptance Scenarios**:

1. **Given** 터널 편집 화면, **When** "모든 트래픽" 프리셋 선택, **Then** AllowedIPs가 `0.0.0.0/0, ::/0`으로 설정된다.
2. **Given** "지정 대역만" 선택, **When** 서브넷을 추가/삭제, **Then** AllowedIPs가 해당 대역 목록으로 업데이트된다.
3. **Given** 현재 AllowedIPs가 `10.0.0.0/8, 192.168.0.0/16`, **When** UI가 열리면, **Then** "지정 대역만" 프리셋이 선택되고 서브넷 2개가 표시된다.

---

### User Story 3 - 연결 통계 대시보드 (Priority: P2)

실시간 속도 그래프와 연결 이력을 시각적으로 확인한다.

**Acceptance Scenarios**:

1. **Given** VPN이 연결된 상태, **When** 대시보드를 열면, **Then** 실시간 RX/TX 속도 그래프가 표시된다.
2. **Given** 대시보드가 열린 상태, **When** 30초 경과, **Then** 그래프에 30초분의 속도 데이터가 표시된다.
3. **Given** 연결/해제를 여러 번 수행, **When** 이력 탭을 열면, **Then** 각 세션의 시작/종료 시간, 전송량이 목록으로 표시된다.

---

### User Story 4 - QR 코드 Import (Priority: P2)

WireGuard 설정 QR 코드를 이미지 파일이나 스크린샷에서 읽어서 import한다.

**Acceptance Scenarios**:

1. **Given** import 화면, **When** QR 코드 이미지 파일을 선택하면, **Then** QR에서 .conf 내용이 디코딩되어 import된다.
2. **Given** QR이 유효하지 않은 이미지, **When** 파일을 선택하면, **Then** "QR 코드를 찾을 수 없습니다" 에러가 표시된다.

---

### User Story 5 - 키 생성 (Priority: P2)

앱 내에서 WireGuard 키페어를 생성하여 새 터널 설정에 바로 사용한다.

**Acceptance Scenarios**:

1. **Given** 새 터널 생성 화면, **When** "키 생성" 버튼을 클릭하면, **Then** PrivateKey + PublicKey 쌍이 생성되어 폼에 자동 입력된다.
2. **Given** 키가 생성된 상태, **When** PublicKey를 클릭하면, **Then** 클립보드에 복사된다.

---

### User Story 6 - 자동 업데이트 (Priority: P2)

GitHub Releases에서 새 버전을 확인하고, 다운로드 + 설치를 안내한다.

**Acceptance Scenarios**:

1. **Given** 새 버전이 릴리즈됨, **When** 앱이 업데이트 확인, **Then** "새 버전 사용 가능" 알림이 표시된다.
2. **Given** 알림에서 "업데이트"를 클릭, **When** 다운로드가 완료되면, **Then** 릴리즈 페이지 또는 설치 가이드가 열린다.

---

### User Story 7 - 미니 모드 (Priority: P3)

상태 + 토글만 보이는 작은 플로팅 위젯. Tailscale의 mini player 참고.

**Acceptance Scenarios**:

1. **Given** 메인 창에서 "미니 모드" 전환, **When** 전환되면, **Then** 작은 플로팅 위젯으로 상태 + 연결/해제 토글만 표시된다.

---

### User Story 8 - 네트워크 진단 + 속도 테스트 (Priority: P3)

CIDR 계산기, 엔드포인트 도달 테스트, 속도/레이턴시 측정.

**Acceptance Scenarios**:

1. **Given** 진단 도구, **When** 엔드포인트 도달 테스트를 실행하면, **Then** ping 결과와 레이턴시가 표시된다.
2. **Given** 속도 테스트 실행, **When** 완료되면, **Then** 다운로드/업로드 속도가 표시된다.

---

### User Story 9 - 키보드 단축키 (Priority: P3)

Ctrl/Cmd+1~9로 터널 빠른 연결, 글로벌 VPN 토글 핫키.

**Acceptance Scenarios**:

1. **Given** 터널 3개 등록, **When** Cmd+1을 누르면, **Then** 첫 번째 터널에 연결된다.
2. **Given** VPN이 연결된 상태, **When** 글로벌 핫키를 누르면, **Then** VPN이 해제된다.

---

### User Story 10 - 동시 멀티 터널 + 라우팅 충돌 감지 (Priority: P3)

여러 터널을 동시에 연결하되, 라우팅 충돌을 자동 검사한다. WireGuide 터널뿐만 아니라 Tailscale 등 외부 WireGuard 인터페이스도 감지하여 경고한다.

**Acceptance Scenarios**:

1. **Given** 터널 A (10.0.0.0/24)와 B (192.168.0.0/16), **When** 둘 다 연결하면, **Then** 각자의 대역으로 라우팅된다.
2. **Given** 풀터널 A와 서브넷 B, **When** 동시 연결 시도, **Then** 충돌 경고가 표시된다.
3. **Given** Tailscale이 utun3에서 0.0.0.0/0으로 동작 중, **When** WireGuide 풀터널 연결 시도, **Then** "utun3 (Tailscale에서 사용 중): 0.0.0.0/0과 충돌" 경고가 표시된다.
4. **Given** 연결 시도, **When** 기존 utun/wg 인터페이스를 스캔하면, **Then** UAPI 소켓 경로 + 프로세스로 소유자(WireGuide/Tailscale/기타)를 식별한다.

---

### User Story 11 - DNS 누출 테스트 + 라우트 시각화 (Priority: P3)

내장 DNS 누출 테스트와 라우팅 경로 시각화.

**Acceptance Scenarios**:

1. **Given** VPN 연결 상태, **When** DNS 누출 테스트를 실행하면, **Then** DNS 쿼리가 VPN DNS로만 가는지 확인 결과가 표시된다.
2. **Given** 라우트 시각화, **When** 열면, **Then** 각 대역이 어느 인터페이스로 나가는지 그래픽으로 표시된다.

---

### Edge Cases

- WiFi SSID가 숨겨진(hidden) 네트워크인 경우? → SSID 수동 입력 지원
- QR 이미지가 여러 개 포함된 경우? → 첫 번째 유효한 QR만 사용
- 멀티 터널에서 DNS 서버 충돌? → 마지막 연결된 터널의 DNS 우선
- Tailscale 등 외부 인터페이스가 감지 안 되는 경우? → 라우팅 테이블 기반 fallback 검사
- 부분적 CIDR 겹침 (10.0.0.0/16 vs 10.0.5.0/24)? → 경고 표시, 더 구체적인 라우트 우선 설명
- 자동 업데이트 서버 접근 불가 시? → 조용히 실패, 다음 주기에 재시도

## Requirements

### Functional Requirements

- **FR-001**: WiFi SSID 감지 + SSID별 자동 연결/해제 규칙 관리
- **FR-002**: AllowedIPs 프리셋 UI (모든 트래픽 / 지정 대역) + 서브넷 추가/삭제
- **FR-003**: 실시간 속도 그래프 (RX/TX) + 연결 이력 저장
- **FR-004**: QR 코드 이미지 디코딩 → .conf import
- **FR-005**: WireGuard 키페어 생성 (Curve25519) + 클립보드 복사
- **FR-006**: GitHub Releases API로 새 버전 확인 + 다운로드 안내
- **FR-007**: 미니 모드 플로팅 위젯
- **FR-008**: CIDR 계산기 + 엔드포인트 도달 테스트 + 속도 테스트
- **FR-009**: 키보드 단축키 (Cmd+1~9 터널, 글로벌 VPN 토글)
- **FR-010**: 동시 멀티 터널 + 라우팅 충돌 자동 검사
- **FR-011**: 외부 WireGuard 인터페이스 감지 (Tailscale 등) — UAPI 소켓 + 프로세스 소유자 식별
- **FR-012**: DNS 누출 테스트 + 라우트 시각화

## Success Criteria

- **SC-001**: WiFi 전환 시 5초 이내 자동 연결/해제
- **SC-002**: AllowedIPs 프리셋으로 CIDR 직접 입력 없이 스플릿 터널 설정 가능
- **SC-003**: 실시간 그래프가 1초 단위로 업데이트
- **SC-004**: QR 이미지에서 3초 이내 .conf 디코딩
- **SC-005**: 키 생성 즉시 (< 100ms)
