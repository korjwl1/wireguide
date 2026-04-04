# Feature Specification: WireGuide MVP

**Feature Branch**: `001-wireguard-mvp`
**Created**: 2026-04-04
**Status**: Draft
**Input**: `wireguard-app.md` Phase 1 + Phase 2 일부 (i18n)

## Clarification Decisions (2026-04-04)

| # | 질문 | 결정 |
|---|------|------|
| 1 | 프로젝트 이름 | **wireguide** |
| 2 | Wails 버전 | **v3 (알파)** — 시스템 트레이 내장 지원 |
| 3 | 프론트엔드 | **Svelte** |
| 4 | MVP i18n | **3개 언어 (영어/한국어/일본어)** |
| 5 | MVP 타겟 OS | **3 OS 동시 (macOS/Windows/Linux)** |
| 6 | Pre/PostUp 처리 | **경고 다이얼로그 후 실행 허용** |
| 7 | 터널 수 제한 | **없음** (실용적으로 100개 이상 사용 사례 없음) |
| 8 | .conf 파일 연동 | **OS가 지원하는 범위에서만** |
| 9 | 트레이 아이콘 | **VPN/WireGuard 로고 + 연결 시 초록색 점**. 모노크롬 옵션 MVP 제외 |

## User Scenarios & Testing

### User Story 1 - .conf 파일 Import 및 터널 연결 (Priority: P1)

사용자는 WireGuard 서버 관리자로부터 받은 .conf 파일을 앱에 가져와서, 원클릭으로 VPN에 연결하고자 한다. 연결 후 실시간으로 트래픽 상태와 핸드셰이크 정보를 확인할 수 있어야 한다.

**Why this priority**: VPN 클라이언트의 가장 기본적인 가치. 이것 없이는 앱의 존재 이유가 없다.

**Independent Test**: .conf 파일 하나를 드래그 앤 드롭으로 import한 뒤, 연결 버튼을 눌러 VPN이 활성화되고, 외부 IP가 변경되는 것을 확인한다.

**Acceptance Scenarios**:

1. **Given** 앱이 실행 중이고 터널이 없는 상태, **When** 사용자가 유효한 .conf 파일을 앱 창에 드래그 앤 드롭하면, **Then** 파일이 파싱되어 요약 미리보기(터널명, 엔드포인트, AllowedIPs, DNS)가 표시되고, "Import" 확인 후 터널 목록에 추가된다.

2. **Given** 터널이 목록에 있고 미연결 상태, **When** 사용자가 연결 버튼을 클릭하면, **Then** 상태가 "연결 중"(노랑) → "연결됨"(초록)으로 전환되고, RX/TX 속도, 핸드셰이크 시간, 연결 지속 시간이 실시간 표시된다.

3. **Given** 터널이 연결된 상태, **When** 사용자가 연결 해제 버튼을 클릭하면, **Then** VPN이 해제되고 인터페이스/라우트/DNS가 원래 상태로 복원된다.

4. **Given** 앱이 실행 중인 상태, **When** 사용자가 파일 선택 다이얼로그로 .conf를 선택하면, **Then** 드래그 앤 드롭과 동일하게 import된다.

5. **Given** 앱이 실행 중인 상태, **When** 사용자가 클립보드에 .conf 내용을 복사한 뒤 "클립보드에서 붙여넣기"를 클릭하면, **Then** 텍스트가 파싱되어 import된다.

---

### User Story 2 - Config 유효성 검사 및 에러 안내 (Priority: P1)

사용자는 잘못된 .conf 파일을 import하거나 편집했을 때, 무엇이 잘못되었는지 구체적으로 안내받고자 한다. "연결 실패"가 아니라 "PrivateKey가 없습니다" 같은 명확한 메시지가 필요하다.

**Why this priority**: 공식 WireGuard 앱의 가장 큰 불만 중 하나가 불친절한 에러 메시지. 핵심 차별화 포인트.

**Independent Test**: 의도적으로 필드가 누락되거나 형식이 잘못된 .conf를 import하여, 각각에 대해 구체적인 에러 메시지가 표시되는지 확인한다.

**Acceptance Scenarios**:

1. **Given** 사용자가 .conf를 import 시도, **When** PrivateKey가 누락되어 있으면, **Then** "PrivateKey가 없습니다" 에러가 표시되고 import가 거부된다.

2. **Given** 사용자가 .conf를 import 시도, **When** AllowedIPs 형식이 잘못되어 있으면 (예: "10.0.0/24"), **Then** "AllowedIPs 형식이 잘못되었습니다: 10.0.0/24" 에러가 표시된다.

3. **Given** 사용자가 .conf를 import 시도, **When** 키 형식이 유효하지 않으면 (Base64 32바이트가 아닌 경우), **Then** "PrivateKey 형식이 올바르지 않습니다 (Base64 인코딩된 32바이트 키 필요)" 에러가 표시된다.

4. **Given** 사용자가 Config 에디터에서 편집 후 저장, **When** 유효성 검사에 실패하면, **Then** 에러가 에디터 내에 인라인으로 표시되고 저장이 차단된다.

5. **Given** 유효성 검사에 여러 오류가 있는 경우, **When** import 또는 저장 시도, **Then** 모든 오류가 목록으로 한꺼번에 표시된다.

---

### User Story 3 - 시스템 트레이에서 빠른 제어 (Priority: P2)

사용자는 앱 창을 열지 않고도, 시스템 트레이(macOS 메뉴바 / Windows 트레이 / Linux 트레이)에서 VPN 상태를 확인하고, 터널을 전환하고자 한다.

**Why this priority**: VPN 앱은 백그라운드에서 상시 동작. 매번 창을 열어야 한다면 불편하다. 트레이는 일상적 사용의 핵심 인터페이스.

**Independent Test**: 앱 창을 닫고, 트레이 아이콘의 컨텍스트 메뉴에서 터널을 선택하여 연결/해제가 동작하는지 확인한다.

**Acceptance Scenarios**:

1. **Given** 앱이 실행 중이고 1개 이상 터널이 존재, **When** 사용자가 트레이 아이콘을 우클릭하면, **Then** 터널 목록이 표시되고, 각 터널 옆에 연결/해제 토글이 있다.

2. **Given** 트레이 컨텍스트 메뉴가 열린 상태, **When** 미연결 터널의 "연결" 버튼을 클릭하면, **Then** 해당 터널이 연결되고 트레이 아이콘에 초록색 점이 표시된다.

3. **Given** VPN이 연결된 상태, **When** 사용자가 앱 창을 닫으면, **Then** 앱이 종료되지 않고 트레이로 최소화되며, VPN 연결은 유지된다.

4. **Given** 앱이 트레이에만 있는 상태, **When** 트레이 아이콘을 클릭하면, **Then** 메인 창이 다시 표시된다.

5. **Given** VPN이 연결된 상태, **When** 트레이 아이콘 위에 마우스를 올리면, **Then** 툴팁으로 "터널명 | 연결됨 | 시간 | 속도" 정보가 표시된다.

---

### User Story 4 - 터널 관리 (추가/삭제/편집/내보내기) (Priority: P2)

사용자는 여러 VPN 터널을 관리하고자 한다. 새 터널 추가, 기존 터널 삭제, Config 편집, .conf 파일로 내보내기가 가능해야 한다.

**Why this priority**: 복수 VPN 프로필을 사용하는 사용자(회사 VPN + 개인 VPN 등)에게 필수. P1 이후 자연스러운 확장.

**Independent Test**: 터널 3개를 추가하고, 1개를 편집하고, 1개를 삭제하고, 1개를 export하여 원본과 동일한지 확인한다.

**Acceptance Scenarios**:

1. **Given** 메인 화면이 표시된 상태, **When** 좌측 목록에서 터널을 선택하면, **Then** 우측에 상세 정보(상태, 엔드포인트, AllowedIPs, Public Key, 핸드셰이크 등)가 표시된다.

2. **Given** 터널이 선택된 상태, **When** "편집" 버튼을 클릭하면, **Then** Config 에디터(textarea)가 열리고 .conf 전체 텍스트가 표시된다.

3. **Given** Config 에디터에서 내용을 변경, **When** "저장"을 클릭하면, **Then** 유효성 검사 통과 후 .conf 파일이 업데이트된다.

4. **Given** Config 에디터에서 내용을 변경, **When** "취소"를 클릭하면, **Then** 변경 내용이 폐기되고 원래 상태로 복원된다.

5. **Given** 터널이 선택된 상태, **When** "삭제" 버튼을 클릭하면, **Then** 확인 다이얼로그 후 터널이 목록과 파일시스템에서 제거된다.

6. **Given** 터널이 선택된 상태, **When** "내보내기"를 클릭하면, **Then** OS 파일 저장 다이얼로그가 열리고 .conf 파일이 저장된다.

---

### User Story 5 - 다국어 지원 (Priority: P2)

사용자는 앱을 자신의 OS 언어에 맞게 사용하고자 한다. 영어, 한국어, 일본어를 지원하며, 시스템 언어를 자동 감지하되 수동 전환도 가능해야 한다.

**Why this priority**: 타겟 사용자가 다국어권(영어/한국어/일본어). UX 완성도의 핵심 요소.

**Independent Test**: OS 언어를 영어 → 한국어 → 일본어로 전환하며, 앱의 모든 텍스트가 해당 언어로 표시되는지 확인한다.

**Acceptance Scenarios**:

1. **Given** OS 언어가 한국어로 설정된 상태에서 앱을 처음 실행, **When** 메인 화면이 로드되면, **Then** 모든 UI 텍스트가 한국어로 표시된다.

2. **Given** 앱이 영어로 표시된 상태, **When** 설정에서 언어를 "日本語"로 변경하면, **Then** 즉시 모든 UI가 일본어로 전환된다.

3. **Given** OS 언어가 지원하지 않는 언어인 경우, **When** 앱을 실행하면, **Then** 영어(기본값)로 표시된다.

---

### User Story 6 - PreUp/PostUp 스크립트 실행 (Priority: P3)

.conf 파일에 PreUp/PostUp/PreDown/PostDown 스크립트가 포함된 경우, 사용자에게 경고를 표시하고 명시적 허용 후 실행한다.

**Why this priority**: 보안 민감 기능이지만, 일부 VPN 설정에 필수. 차단이 아닌 경고 후 허용으로 유연성 확보.

**Independent Test**: PreUp이 포함된 .conf를 import하여, 경고 다이얼로그가 표시되고, 허용/거부가 각각 올바르게 동작하는지 확인한다.

**Acceptance Scenarios**:

1. **Given** 사용자가 PreUp 필드가 있는 .conf를 import, **When** 파싱이 완료되면, **Then** "이 설정에 시스템 명령 실행 스크립트가 포함되어 있습니다" 경고와 스크립트 내용이 표시된다.

2. **Given** 스크립트 경고 다이얼로그가 표시된 상태, **When** "허용"을 클릭하면, **Then** 연결 시 해당 스크립트가 실행된다.

3. **Given** 스크립트 경고 다이얼로그가 표시된 상태, **When** "거부"를 클릭하면, **Then** 터널은 import되지만 스크립트는 실행되지 않고 비활성화 상태로 저장된다.

---

### Edge Cases

- 앱이 sudo/admin 권한 없이 실행된 경우 어떻게 되는가? → 연결 시도 시 "관리자 권한이 필요합니다" 에러 표시
- 동일한 이름의 터널을 중복 import하면? → "이미 존재하는 터널입니다. 덮어쓰시겠습니까?" 확인 다이얼로그
- 연결 중에 네트워크가 끊기면? → 상태를 "연결 실패"(빨강)로 표시 + 에러 메시지 (자동 재연결은 Phase 2)
- .conf 파일이 빈 파일이면? → "빈 파일입니다" 에러
- 파일 확장자가 .conf가 아니면? → 경고 표시 후 파싱 시도 ("지원하지 않는 파일 형식일 수 있습니다")
- 연결된 터널을 삭제하려 하면? → "연결 중인 터널입니다. 먼저 연결을 해제하세요" 에러
- 연결된 터널의 Config를 편집하려 하면? → "연결 중인 터널은 편집할 수 없습니다. 먼저 연결을 해제하세요"
- OS 파일 퍼미션으로 .conf에 접근 불가한 경우? → "파일을 읽을 수 없습니다. 파일 권한을 확인하세요"
- Private key가 포함된 .conf를 export할 때? → 그대로 export (키는 이미 사용자 소유)
- 앱이 터널 연결 중 크래시하면? → 다음 실행 시 고아 TUN 인터페이스/라우트/DNS 감지 + 자동 정리
- 터널이 100개 이상이면? → 제한 없음. 목록 성능 이슈 시 가상 스크롤 고려 (Phase 3)

## Requirements

### Functional Requirements

- **FR-001**: 시스템은 WireGuard .conf 파일을 파싱하여 [Interface] 및 다중 [Peer] 섹션을 구조화된 데이터로 변환해야 한다
- **FR-002**: 시스템은 import 및 저장 시 유효성 검사를 수행해야 한다 (필수 필드, 키 형식, CIDR 형식, Endpoint 형식)
- **FR-003**: 시스템은 유효성 검사 실패 시 구체적인 에러 메시지를 표시해야 한다 (필드명 + 문제 내용)
- **FR-004**: 사용자는 .conf 파일을 드래그 앤 드롭, 파일 선택, 클립보드 붙여넣기로 import할 수 있어야 한다
- **FR-005**: 시스템은 import 전 미리보기(터널명, 엔드포인트, AllowedIPs, DNS)를 표시해야 한다
- **FR-006**: 사용자는 원클릭으로 터널을 연결/해제할 수 있어야 한다
- **FR-007**: 시스템은 연결 시 TUN 디바이스 생성, IP 할당, 라우팅, DNS 설정을 수행해야 한다
- **FR-008**: 시스템은 연결 해제 시 인터페이스, 라우트, DNS를 원래 상태로 복원해야 한다
- **FR-009**: 시스템은 연결 중 실시간 상태를 표시해야 한다 (RX/TX 속도, 핸드셰이크 시간, 연결 지속 시간)
- **FR-010**: 시스템은 macOS 메뉴바, Windows 시스템 트레이, Linux 트레이에 VPN 로고 아이콘으로 상주하며, 연결 시 초록색 점으로 상태를 표시해야 한다
- **FR-011**: 사용자는 트레이 컨텍스트 메뉴에서 터널 연결/해제를 1클릭으로 전환할 수 있어야 한다
- **FR-012**: 창 닫기 시 앱이 종료되지 않고 트레이로 최소화되어야 한다
- **FR-013**: 사용자는 Config를 텍스트 에디터(textarea)로 편집할 수 있어야 한다
- **FR-014**: 사용자는 터널의 .conf를 파일로 내보낼 수 있어야 한다
- **FR-015**: 시스템은 .conf 파일을 OS별 적절한 경로에 저장하고, 파일 퍼미션 0600을 적용해야 한다
- **FR-016**: 시스템은 영어, 한국어, 일본어를 지원하고, 시스템 언어를 자동 감지하되 수동 전환도 가능해야 한다
- **FR-017**: PreUp/PostUp/PreDown/PostDown 스크립트가 포함된 .conf를 감지하고, 경고 다이얼로그로 사용자 확인 후 실행해야 한다
- **FR-018**: 시스템은 macOS, Windows, Linux 3개 OS에서 동작해야 한다
- **FR-019**: 시스템은 풀터널(0.0.0.0/0) 라우팅을 지원해야 한다 (OS별 적절한 방법으로)
- **FR-020**: 시스템은 .conf 더블클릭 시 앱이 열리도록 OS 파일 연동을 지원해야 한다 (가능한 범위에서)

### Key Entities

- **Tunnel**: 하나의 WireGuard VPN 연결 단위. .conf 파일로 표현. 이름, 연결 상태, 설정, 통계 정보를 가짐.
- **InterfaceConfig**: [Interface] 섹션. PrivateKey, Address, DNS, MTU, ListenPort, Pre/PostUp/Down 스크립트 포함.
- **PeerConfig**: [Peer] 섹션. PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive 포함. 하나의 Tunnel에 다중 Peer 가능.
- **ConnectionStatus**: 터널의 실시간 상태. RX/TX 바이트, 핸드셰이크 시간, 연결 시작 시각, 연결 상태(disconnected/connecting/connected/error).
- **AppSettings**: 앱 전역 설정. 테마, 언어, 트레이 아이콘 스타일 등.

## Success Criteria

### Measurable Outcomes

- **SC-001**: 사용자는 .conf 파일 import부터 VPN 연결까지 3클릭 이내에 완료할 수 있다 (드래그 → Import 확인 → 연결)
- **SC-002**: 유효성 검사 에러 메시지가 항상 문제가 된 필드명과 구체적 원인을 포함한다
- **SC-003**: 연결/해제 상태 전환이 10초 이내에 완료된다 (정상 네트워크 환경)
- **SC-004**: 연결 상태 정보(RX/TX, 핸드셰이크)가 2초 이내 지연으로 실시간 업데이트된다
- **SC-005**: 트레이 메뉴에서 터널 전환이 1클릭으로 가능하다
- **SC-006**: 앱이 macOS, Windows, Linux 3개 OS에서 동일한 핵심 기능을 제공한다
- **SC-007**: 모든 UI 텍스트가 영어/한국어/일본어 3개 언어로 번역되어 있다
- **SC-008**: 연결 해제 후 OS의 네트워크 설정(DNS, 라우트)이 연결 전 상태로 완전 복원된다
