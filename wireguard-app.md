# WireGuard Desktop Client — 프로젝트 계획

## 배경

- WireGuard 공식 macOS 앱이 2022년 이후 방치 상태
- macOS Tahoe(26.x)에서 네트워크 익스텐션 CPU wakeup 폭주 등 심각한 호환성 문제 발생
- Windows 공식 앱은 관리되고 있으나, 킬 스위치/자동 연결 규칙 등 편의 기능 부재
- 크로스플랫폼 WireGuard GUI 클라이언트가 사실상 부재 (기존 서드파티 프로젝트는 단일 OS이거나 방치)

## 목표

- macOS, Windows, Linux에서 동작하는 WireGuard GUI 클라이언트
- macOS 네트워크 익스텐션을 사용하지 않음 (userspace 기반, CPU 폭주 문제 회피)
- .conf 파일 기반 범용 클라이언트 (특정 서버/서비스 종속 없음)
- OpenVPN Connect 수준의 간결한 UX + 파워유저 기능
- 오픈소스 개인 프로젝트
- UI 언어: 시스템 언어 자동 감지 (영어/한국어/일본어 지원). 사용자가 수동 선택도 가능.
- 프로젝트 이름: TBD

## 핵심 기능

### MVP (Phase 1)

1. **터널 관리**: 추가/삭제/편집, 다중 터널 목록
2. **.conf 파일 import**: 드래그 앤 드롭 / 파일 선택 다이얼로그 / 클립보드 붙여넣기 (1개씩)
   - import 시 즉시 유효성 검사: 파일 확장자, INI 파싱, 필수 필드(PrivateKey, Address, PublicKey, Endpoint) 존재 여부, 키 형식, CIDR 형식 체크
   - 유효하지 않으면 구체적 에러 메시지와 함께 거부 ("PrivateKey가 없습니다", "AllowedIPs 형식이 잘못되었습니다: 10.0.0/24" 등)
3. **원클릭 연결/해제**: 터널 선택 후 토글
4. **시스템 트레이 상주**: macOS 메뉴바 / Windows 시스템 트레이 / Linux 트레이
   - 연결 상태에 따라 아이콘 변경 (초록: 연결됨, 회색: 미연결)
   - 우클릭 컨텍스트 메뉴: 터널 목록, 연결/해제 토글, 설정 열기, 종료
5. **연결 상태 표시**: RX/TX 바이트, 최종 핸드셰이크 시간, 연결 지속 시간
6. **Config 유효성 검사**: 연결 전 파싱 + 에러 메시지 표시
7. **Config 편집**: 기본 텍스트 에디터 (textarea)로 .conf 내용 편집
8. **Config export**: 파일 저장

※ Phase 1에서는 단일 프로세스로 동작 (sudo/관리자 권한으로 실행). 권한 분리는 Phase 2에서 구현.

### Phase 2 — 안정화 + UX 강화

9. **권한 분리 데몬**: GUI(비특권) ↔ 데몬(특권) 분리
    - macOS: LaunchDaemon, Windows: SCM Service, Linux: systemd
10. **Config 에디터 업그레이드**: CodeMirror 6 기반 문법 하이라이팅 + 자동완성
11. **킬 스위치**: VPN 끊기면 인터넷 차단 (macOS: pf, Windows: WFP, Linux: iptables/nftables)
12. **DNS 누출 방지**: OS별 방화벽으로 포트 53 트래픽 필터링
13. **자동 재연결**: 연결 끊김 감지 후 자동 복구
14. **죽은 연결 감지**: 핸드셰이크 타임아웃 시 알림 + 자동 재연결
15. **시작 시 자동 실행**: OS 부팅 시 트레이에 최소화 상태로 시작
16. **sleep/wake 재연결**: OS 이벤트 감지 후 자동 재연결
17. **크래시 복구**: 비정상 종료 시 스테일 라우트/DNS 정리를 위한 복구 journal
18. **로그 뷰어**: 진단용 로그 표시 (레벨 필터링)
19. **OS 알림**: 연결/해제/에러 이벤트 알림
20. **다크/라이트 모드**: 시스템 테마 추종 + 수동 전환

### Phase 3 — 배포 + 편의 기능

21. **자동 연결 규칙**: 특정 WiFi SSID에서 자동 연결, SSID 화이트/블랙리스트
22. **스플릿 터널링 UI**: AllowedIPs를 쉽게 설정하는 UI (프리셋: 모든 트래픽 / 지정 대역만)
23. **연결 통계 대시보드**: 속도 그래프, 트래픽 추이, 연결 이력
24. **터널 검색/필터**: 터널이 많을 때 빠른 탐색
25. **QR 코드 import**: 스크린샷/이미지 파일에서 QR 디코딩
26. **키 생성**: 앱 내에서 WireGuard 키페어 생성
27. **자동 업데이트**: GitHub Releases 기반 업데이트 확인 + 설치

### Phase 4 — 고급 기능

28. 앱별 스플릿 터널링 (OS 레벨 트래픽 인터셉션 필요)
29. 동시 멀티 터널 (라우팅 충돌 관리 필요)
30. DNS 누출 테스트 (내장)
31. 라우트 시각화 (라우팅 결정을 시각적으로 표시)
32. 네트워크 진단 도구 (CIDR 계산기, 엔드포인트 도달 테스트)
33. 속도/레이턴시 테스트
34. 미니 모드 (Tailscale 참고 — 상태+토글만 보이는 작은 플로팅 위젯)
35. 키보드 단축키 (Ctrl/Cmd+1~9 터널 빠른 연결, 글로벌 VPN 토글 핫키)
36. 다국어 지원 확장 (영어/한국어/일본어 외 추가 언어)

## 기술 스택

### 언어: Go

WireGuard 공식 생태계가 Go 중심이므로, 엔진부터 GUI까지 단일 언어로 통일.

### GUI: Wails v3 + CodeMirror 6

- **Wails v3**: Go 백엔드 + OS 네이티브 웹뷰 (macOS: WebKit, Windows: WebView2, Linux: WebKitGTK)
  - 시스템 트레이 내장 지원 (트레이 전용 모드 공식 지원)
  - Electron과 달리 브라우저 번들 없음 — 바이너리 ~10MB, 유휴 메모리 ~20-30MB
  - Go ↔ JS 자동 바인딩
  - WebView2 보급률: Windows 10 (2004+) / 11 기본 탑재, 미설치 시 자동 프롬프트
  - **주의**: Wails v3는 현재 알파 (v3.0.0-alpha.68, 2026.02 기준). API가 안정적이라고 명시하고 있고 프로덕션 사용 사례 있으나, 정식 릴리즈 일정 미정. 대안으로 Wails v2 (안정)로 시작 후 v3 마이그레이션도 가능. 단, v2는 시스템 트레이 지원이 제한적.
- **CodeMirror 6**: .conf 에디터용
  - WireGuard conf 문법 하이라이팅 (커스텀 language mode)
  - 자동완성 (키워드: PrivateKey, PublicKey, AllowedIPs, DNS, MTU 등)
  - 줄 번호, 괄호 매칭, 에러 표시
- **프론트엔드**: HTML/CSS/TypeScript
  - 추천: Svelte (가벼움, 빌드 결과물이 작아 WebView에 적합) 또는 React (생태계 넓음)
  - Wails v3는 프레임워크 무관 — 어떤 JS 프레임워크든 사용 가능

### WireGuard 엔진: wireguard-go (임베딩)

- `golang.zx2c4.com/wireguard` — 공식 userspace WireGuard 구현
  - TUN 디바이스 생성 (macOS: utun, Windows: wintun, Linux: /dev/net/tun)
  - Windows: wintun.dll 필요 (앱에 번들, [wintun.com](https://www.wintun.net/)에서 배포)
  - WireGuard 프로토콜 (Noise handshake, 암호화/복호화)
  - Jason Donenfeld (WireGuard 창시자) 관리
- `golang.zx2c4.com/wireguard/wgctrl` — 공식 WireGuard 제어 라이브러리
  - 인터페이스 설정 (키, 피어, 엔드포인트, AllowedIPs)
  - 통계 읽기 (RX/TX, 핸드셰이크 시간)
  - 커널 모듈 + userspace 모두 지원

### OS별 네트워킹 (IP/라우팅/DNS)

wireguard-go + wgctrl-go는 TUN 생성과 WG 프로토콜만 담당.
IP 할당, 라우팅, DNS 설정은 OS별로 구현 필요:

| OS | IP 할당 | 라우팅 | DNS |
|----|---------|--------|-----|
| **Linux** | `vishvananda/netlink` | `vishvananda/netlink` (정책 라우팅, fwmark) | `resolvconf` / systemd-resolved |
| **Windows** | `wireguard/windows/tunnel/winipcfg` (공식) | `winipcfg` (공식) | `winipcfg` (공식) |
| **macOS** | `ifconfig` subprocess / syscall | `golang.org/x/net/route` (라우팅 소켓) | `networksetup` subprocess |

- Windows: WireGuard 공식 팀의 `winipcfg` 패키지가 IP/라우팅/DNS를 완벽 커버
- Linux: `netlink` 패키지가 사실상 표준
- macOS: 순수 Go 라이브러리가 부족하여 일부 subprocess 호출 필요
- 풀터널(0.0.0.0/0):
  - macOS: 0.0.0.0/1 + 128.0.0.0/1 스플릿 라우트 + 엔드포인트 바이패스 라우트
  - Linux: fwmark 정책 라우팅 + suppress_prefixlength
  - Windows: `winipcfg`의 `SetRoutes` + 인터페이스 메트릭 조정으로 기본 라우트 우선순위 제어

### 아키텍처: 권한 분리 (GUI ↔ 데몬)

VPN 클라이언트는 TUN 생성/라우팅 변경에 root/admin 권한이 필요하므로,
GUI(비특권)와 데몬(특권)을 분리:

```
┌──────────────────┐      IPC       ┌──────────────────┐
│  Wails GUI       │ ←────────────→ │  Go Daemon       │
│  (일반 사용자)     │  Unix Socket  │  (root/admin)    │
│                  │  / Named Pipe  │                  │
│  - 트레이 아이콘   │               │  - wireguard-go  │
│  - 설정 UI       │               │  - wgctrl-go     │
│  - 상태 표시      │               │  - IP/라우팅/DNS  │
│  - 에디터        │               │  - 킬 스위치      │
└──────────────────┘               └──────────────────┘
```

- macOS: LaunchDaemon으로 데몬 등록, Unix Socket IPC
- Windows: Windows Service (SCM)로 등록, Named Pipe IPC
- Linux: systemd 서비스로 등록, Unix Socket IPC
- IPC 프로토콜: gRPC 또는 JSON-RPC

### .conf 파서

- WireGuard .conf는 INI 형식. Go의 `gopkg.in/ini.v1` 또는 직접 구현
- [Interface] 섹션: PrivateKey, Address, DNS, MTU, ListenPort, PreUp/PostUp/PreDown/PostDown, Table, FwMark
- [Peer] 섹션: PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive
- 다중 [Peer] 지원
- 유효성 검사: 키 형식 (Base64, 32바이트), CIDR 형식, 엔드포인트 형식 (host:port), 필수 필드 체크

### 설정/상태 저장

- **앱 설정** (테마, 자동 시작, 자동 연결 규칙 등):
  - macOS: `~/Library/Application Support/<app>/config.json`
  - Windows: `%APPDATA%/<app>/config.json`
  - Linux: `~/.config/<app>/config.json` (XDG_CONFIG_HOME)
- **터널 config 파일** (.conf):
  - macOS: `~/Library/Application Support/<app>/tunnels/`
  - Windows: `%APPDATA%/<app>/tunnels/`
  - Linux: `~/.config/<app>/tunnels/`
  - **주의**: .conf에 private key가 평문으로 포함되므로 파일 퍼미션 0600 (소유자만 읽기/쓰기) 적용
- **데몬 상태/복구 journal**:
  - macOS: `/Library/Application Support/<app>/`
  - Windows: `%PROGRAMDATA%/<app>/`
  - Linux: `/var/lib/<app>/`
- **로그**:
  - macOS: `~/Library/Logs/<app>/`
  - Windows: `%APPDATA%/<app>/logs/`
  - Linux: systemd journal 또는 `~/.local/share/<app>/logs/`

### 보안 고려사항

- **Private key 보호**: .conf 파일 퍼미션 0600 강제. 가능하면 OS 키체인/자격 증명 저장소 연동 (Phase 4)
- **IPC 인증**: GUI ↔ 데몬 통신 시, 연결하는 클라이언트가 정당한 GUI 프로세스인지 검증
  - macOS: Unix Socket 퍼미션 + 프로세스 코드 사이닝 검증
  - Windows: Named Pipe ACL + 프로세스 서명 검증
  - Linux: Unix Socket 퍼미션 + SO_PEERCRED
- **코드 사이닝**: macOS 공증(notarization) 필수, Windows는 Authenticode 서명 권장
- **PreUp/PostUp/PreDown/PostDown**: 임의 명령 실행이므로, 사용자에게 경고 표시 후 명시적 허용 필요

## 설계 포인트

### 자동 시작

- macOS: LaunchAgent plist (GUI) + LaunchDaemon plist (데몬)
- Windows: 레지스트리 Run 키 (GUI) + SCM 자동 시작 (데몬)
- Linux: XDG autostart (GUI) + systemd enable (데몬)

### sleep/wake 재연결

- macOS: `NSWorkspace` willSleep/didWake notification (cgo 또는 subprocess)
- Windows: `WM_POWERBROADCAST` 이벤트
- Linux: systemd `sleep.target` / `suspend.target`
- 네트워크 변경 감지 후 자동 재연결

### 크래시 복구

r-wg 프로젝트의 recovery journal 패턴 참고:

1. 연결 시: 현재 시스템 상태 (DNS, 라우팅)를 journal 파일에 저장
2. 정상 해제 시: journal 읽고 원래 상태 복원 → journal 삭제
3. 앱 시작 시: journal 파일이 남아있으면 → 이전 크래시로 판단 → 자동 복원
4. 저장 경로: macOS `/Library/Application Support/<app>/`, Windows `%PROGRAMDATA%/<app>/`, Linux `/var/lib/<app>/`

### 킬 스위치 + DNS 누출 방지 (구현 전략)

킬 스위치와 DNS 누출 방지는 동일한 방화벽 메커니즘으로 구현:

| OS | 방화벽 | 킬 스위치 | DNS 누출 방지 |
|----|--------|----------|-------------|
| **macOS** | `pfctl` (pf) | WG 인터페이스 + 엔드포인트 외 차단 | 포트 53을 터널 DNS만 허용 |
| **Windows** | WFP | 동적 세션 (크래시 시 자동 해제) | 포트 53 필터링 |
| **Linux** | iptables/nftables | OUTPUT 체인에서 WG 외 DROP | fwmark 마킹 + resolvconf exclusive |

- Windows WFP "동적 세션"은 프로세스가 죽으면 규칙이 자동 제거됨 — 크래시 복구와 시너지
- r-wg의 `firewall.rs` (WFP 구현)가 주요 레퍼런스

## UI/UX 설계

### 디자인 원칙

1. **정보 밀도 > 장식**: OpenVPN Connect v3.8이 패딩/여백을 늘리고 인라인 토글을 제거했다가 유저 반발을 받음. 화면에 유용한 정보를 밀도 있게 보여주되, 시각적으로 깔끔하게.
2. **원클릭 연결**: 트레이 메뉴에서 1클릭으로 연결/해제. 터널 전환도 1클릭.
3. **신호등 시스템**: 빨강(미연결/위험) → 노랑(연결 중) → 초록(연결됨). 메인 화면, 트레이 아이콘, 알림에 일관 적용.
4. **점진적 공개**: 메인 화면은 터널명 + 상태 + 연결 버튼 + 실시간 통계만. 상세(config 텍스트, 핸드셰이크, 로그)는 한 단계 아래에.
5. **실패를 명확하게**: "Connected"인데 핸드셰이크가 2분 이상 없으면 경고. 에러 시 원인 + 해결 방법을 사람이 읽을 수 있는 메시지로.
6. **기본값이 안전**: 킬 스위치/DNS 누출 방지 토글을 눈에 잘 보이게. 자동 재연결 기본 활성화.

### 참고 앱별 장점 채용

| 앱 | 가져올 것 | 안 가져올 것 |
|----|----------|------------|
| **WireGuard Windows** | Config 텍스트 직접 편집, 실시간 로그, 좌우 분할(목록+상세) | 날것의 텍스트 에디터만 있는 UI, 시각적 상태 표시 부재 |
| **WireGuard macOS** | On-demand 규칙 (WiFi/이더넷), 키 자동 생성 | 네트워크 익스텐션 의존, App Store 전용 배포 |
| **OpenVPN Connect** | 드래그 앤 드롭 import, 더블클릭 .conf 연동, Seamless Tunnel(킬 스위치) 토글, 테마 | v3.8의 과도한 패딩, 정보 밀도 저하 |
| **Mullvad** | 신호등 색상 시스템, 트레이 아이콘 상태, 설정 단일 페이지, 모노크롬 아이콘 옵션 | 지도 뷰 (VPN 클라이언트에 불필요), Electron 무게 |
| **Tailscale** | 미니 모드 (상태+토글만), 검색, 독 아이콘 빨간 점(에러) | 메시 VPN 전용 기능들 |

### 화면 구성

#### 1. 메인 화면 (터널 목록 + 상세)

```
┌─────────────────────────────────────────────────────┐
│  [앱 아이콘]  WireGuard Client          [─] [□] [×] │
├──────────────────┬──────────────────────────────────┤
│                  │                                  │
│  🔍 검색...      │  ● vpn-office                    │
│                  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  ● vpn-office    │  상태: 연결됨 (2시간 34분)         │
│  ○ vpn-home      │  ↓ 12.4 MB/s   ↑ 1.2 MB/s       │
│  ○ vpn-aws       │  핸드셰이크: 8초 전                │
│                  │  엔드포인트: vpn.company.com:51820 │
│                  │                                  │
│                  │  [연결 해제]  [편집]  [삭제]        │
│                  │                                  │
│  ──────────────  │  ── 상세 정보 (접기/펼치기) ──────  │
│  [+ Import]      │  Public Key: aBcDe...            │
│  [+ 새 터널]     │  AllowedIPs: 0.0.0.0/0           │
│                  │  DNS: 1.1.1.1                    │
│                  │  킬 스위치: [ON]                   │
│                  │  DNS 보호: [ON]                    │
└──────────────────┴──────────────────────────────────┘
```

- **좌측**: 터널 목록. 인라인 상태 아이콘 (●=연결, ○=미연결). 검색바 상단.
- **우측**: 선택된 터널 상세. 실시간 속도, 핸드셰이크 나이, 연결 시간.
- **하단 토글**: 킬 스위치, DNS 보호를 **메인 화면에서 바로 제어** (설정에 묻지 않음).
- WireGuard Windows의 좌우 분할 + OpenVPN Connect의 간결함 + Mullvad의 색상 시스템 조합.

#### 2. Config 에디터 (Phase 2에서 CodeMirror로 업그레이드)

```
┌─────────────────────────────────────────────────────┐
│  터널 편집: vpn-office                    [저장] [취소]│
├─────────────────────────────────────────────────────┤
│  [폼 뷰]  [텍스트 뷰]                                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ── 폼 뷰 ──                                        │
│  서버 주소:  [vpn.company.com:51820      ] ✓ 도달 가능│
│  Private Key: [••••••••••••••••••••] [👁] [붙여넣기]  │
│  Public Key:  aBcDeFgHiJkL... (자동 생성)             │
│  Address:     [10.0.0.2/24               ]          │
│  DNS:         [1.1.1.1    ] 프리셋: [Cloudflare ▼]   │
│  MTU:         [1420                      ]          │
│  AllowedIPs:  ◉ 모든 트래픽 (0.0.0.0/0)              │
│               ○ 지정 대역만: [____________]           │
│                                                     │
│  ── 텍스트 뷰 (탭 전환) ──                            │
│  1│ [Interface]                                     │
│  2│ PrivateKey = aBcDeFgH...                        │
│  3│ Address = 10.0.0.2/24                           │
│  4│ DNS = 1.1.1.1        ← 문법 하이라이팅 + 자동완성  │
│  5│ MTU = 1420                                      │
└─────────────────────────────────────────────────────┘
```

- **듀얼 뷰**: 폼 뷰 (초보자) / 텍스트 뷰 (파워유저) 탭 전환.
- 폼 뷰에서 AllowedIPs를 "모든 트래픽" / "지정 대역만" 프리셋으로 제공 — raw CIDR 입력 불필요.
- 텍스트 뷰에서 CodeMirror 6으로 문법 하이라이팅 + 자동완성.
- 엔드포인트 도달 가능 여부 실시간 표시 (✓/✗).

#### 3. Import 플로우

```
┌─────────────────────────────────────────┐
│                                         │
│     .conf 파일을 여기에 드래그하세요       │
│     또는                                │
│     [파일 선택]  [클립보드에서 붙여넣기]   │
│                                         │
└─────────────────────────────────────────┘
         ↓ 파일 드롭 또는 선택 시
┌─────────────────────────────────────────┐
│  ✓ 유효한 WireGuard 설정 파일입니다       │
│                                         │
│  터널 이름: vpn-office                   │
│  엔드포인트: vpn.company.com:51820       │
│  AllowedIPs: 0.0.0.0/0                  │
│  DNS: 1.1.1.1                           │
│                                         │
│           [Import]  [취소]               │
└─────────────────────────────────────────┘
         또는 유효하지 않으면
┌─────────────────────────────────────────┐
│  ✗ 설정 파일에 문제가 있습니다            │
│                                         │
│  • [Peer] 섹션에 PublicKey가 없습니다     │
│  • AllowedIPs 형식 오류: "10.0.0/24"     │
│                                         │
│              [닫기]                      │
└─────────────────────────────────────────┘
```

- 1개씩 import. 드롭 즉시 파싱 + 유효성 검사 + 미리보기.
- 유효하면 요약 정보 표시 후 확인. 유효하지 않으면 구체적 에러.
- 첫 실행 시 empty state가 드롭존.
- .conf 파일 더블클릭으로 앱 열림 (OS 파일 연동).

#### 4. 시스템 트레이

```
우클릭 메뉴:
┌─────────────────────────┐
│ ● vpn-office  [연결 해제] │
│ ○ vpn-home    [연결]     │
│ ○ vpn-aws     [연결]     │
│ ─────────────────────── │
│ 킬 스위치: ON             │
│ ─────────────────────── │
│ 설정 열기                 │
│ 로그 보기                 │
│ 종료                     │
└─────────────────────────┘
```

- **인라인 토글**: 각 터널에 연결/해제 버튼. 목록에서 바로 전환 (OpenVPN v3.7 방식).
- **아이콘 상태**: 연결(초록), 미연결(회색), 연결 중(노랑), 차단 중(빨강 — 킬 스위치 활성).
- **모노크롬 옵션**: OS 테마에 맞는 단색 아이콘 제공 (Mullvad 참고).
- **툴팁**: 호버 시 "vpn-office | 연결됨 | 2h 34m | ↓12.4 ↑1.2 MB/s".

#### 5. 설정 화면

```
┌─────────────────────────────────────────┐
│  설정                                    │
├─────────────────────────────────────────┤
│  ── 일반 ──                              │
│  시작 시 자동 실행          [ON]          │
│  테마                      [시스템 ▼]    │
│  언어                      [시스템 ▼]    │  (English / 한국어 / 日本語)
│  트레이 아이콘 스타일        [컬러 ▼]     │
│  연결 해제 확인 대화상자     [ON]          │
│                                         │
│  ── 연결 ──                              │
│  자동 재연결               [ON]           │
│  죽은 연결 감지 (타임아웃)   [120초 ▼]    │
│  킬 스위치 기본값           [ON]          │
│  DNS 누출 방지 기본값       [ON]          │
│                                         │
│  ── 자동 연결 규칙 ──                     │
│  신뢰하지 않는 WiFi에서 자동 연결  [ON]    │
│  제외할 SSID: [HomeWiFi, ...]            │
│  자동 연결 터널: [vpn-office ▼]           │
│                                         │
│  ── 고급 ──                              │
│  로그 레벨               [Info ▼]        │
│  Pre/PostUp 스크립트 허용  [OFF]          │
│  업데이트 확인 주기        [매일 ▼]       │
└─────────────────────────────────────────┘
```

- 단일 페이지, 스크롤 (Mullvad 방식). 탭/중첩 네비게이션 없음.
- 섹션별 그룹핑: 일반 / 연결 / 자동 연결 규칙 / 고급.
- 킬 스위치와 DNS 보호가 설정에서도 기본값 제어 가능 (터널별 오버라이드는 터널 상세에서).

### 시각 디자인 방향

- **모던 플랫 디자인**: 둥근 모서리, 미묘한 그림자, 깔끔한 타이포그래피
- **컬러 팔레트**: 
  - 다크 모드 기본: 배경 #1a1a2e, 카드 #16213e, 악센트 #0f3460
  - 연결 상태: 초록 #00b894, 노랑 #fdcb6e, 빨강 #d63031
- **폰트**: 시스템 기본 (macOS: SF Pro, Windows: Segoe UI, Linux: 시스템 sans-serif)
- **애니메이션**: 연결 상태 전환 시 부드러운 색상 트랜지션 (300ms ease). 과도한 애니메이션 지양.
- **아이콘**: Lucide 또는 Phosphor 아이콘 세트 (경량, MIT, 일관된 스타일)

### UX 개선 포인트 (vs 공식 앱)

| 공식 앱의 문제 | 우리의 해결 |
|-------------|-----------|
| "Connected"인데 핸드셰이크 없음 → 실제론 끊김 | 핸드셰이크 타임아웃 감지 + 경고 + 자동 재연결 |
| Config 텍스트 편집이 초보자에게 어려움 | 폼 뷰 / 텍스트 뷰 듀얼 모드 |
| AllowedIPs가 뭔지 모르는 사용자 | "모든 트래픽" / "지정 대역만" 프리셋 |
| 킬 스위치가 config 텍스트에 묻혀있음 | 메인 화면에 토글 |
| 에러 메시지가 기술적 | 사람이 읽을 수 있는 메시지 + 해결 방법 제안 |
| Import 후 아무 안내 없음 | 첫 실행 empty state + 드롭존 + 가이드 텍스트 |
| 터널 전환에 여러 클릭 필요 | 트레이에서 인라인 1클릭 전환 |

## 배포

### GitHub Releases (공통)

- 태그 푸시 → CI 크로스 컴파일 → 바이너리 자동 릴리즈

### macOS

- Homebrew tap: `brew install <tap>/<name>`
- .dmg 다운로드
- 코드 사이닝 + 공증(notarization) — 권한 분리 데몬은 별도 서명 필요

### Windows

- winget 등록: `winget install <name>`
- .msi 인스톨러
  - wintun.dll 번들
  - Windows Service 자동 등록

### Linux

- .AppImage (범용)
- .deb / .rpm (주요 배포판)
- systemd 서비스 파일 포함

## CI/CD

- GitHub Actions
- targets:
  - `darwin-amd64` (Intel Mac)
  - `darwin-arm64` (Apple Silicon)
  - macOS Universal Binary (lipo)
  - `windows-amd64`
  - `linux-amd64`
  - `linux-arm64` (Raspberry Pi, ARM 서버)
- 태그 기반 자동 릴리즈
- CGO 크로스 컴파일:
  - Wails는 CGO 필수 (각 OS 네이티브 웹뷰 바인딩)
  - macOS → macOS: 로컬 빌드 또는 GitHub Actions macOS runner
  - Linux → Linux: 로컬 빌드 또는 GitHub Actions ubuntu runner
  - Windows: mingw-w64 크로스 컴파일 또는 GitHub Actions windows runner
  - 현실적으로 각 OS용 GitHub Actions runner에서 네이티브 빌드가 가장 안정적

## 로드맵

각 Phase의 기능 상세는 "핵심 기능" 섹션 참조.

### Phase 1 — MVP

- [ ] 프로젝트 구조 (Go 모듈 + Wails v3 초기화)
- [ ] .conf 파서 구현
- [ ] wireguard-go 임베딩 + 터널 연결/해제 (단일 프로세스, sudo/admin 실행)
- [ ] OS별 IP 할당 / 라우팅 / DNS 설정
- [ ] 시스템 트레이 + 우클릭 메뉴 + 상태 아이콘
- [ ] 설정 UI (터널 목록, 추가/삭제/편집)
- [ ] .conf 파일 import (드래그 앤 드롭 + 파일 선택, 1개씩 + 유효성 검사)
- [ ] .conf 파일 연동 (더블클릭 시 앱으로 열림 — OS별 파일 타입 등록)
- [ ] Config 유효성 검사 + 에러 표시
- [ ] Config export

### Phase 2 — 안정화 + UX 강화

- [ ] 권한 분리 (GUI ↔ 데몬 IPC 분리)
- [ ] Config 에디터 업그레이드 (CodeMirror 6 + 하이라이팅 + 자동완성)
- [ ] 킬 스위치 + DNS 누출 방지
- [ ] 자동 재연결 + 죽은 연결 감지
- [ ] 시작 시 자동 실행 + sleep/wake 재연결
- [ ] 크래시 복구 journal
- [ ] 로그 뷰어 + OS 알림 + 다크/라이트 모드

### Phase 3 — 배포 + 편의 기능

- [ ] CI/CD (GitHub Actions, OS별 네이티브 빌드)
- [ ] 배포 패키징 (Homebrew tap, winget, .dmg, .msi, .deb/.rpm, .AppImage)
- [ ] 자동 연결 규칙 (SSID 기반)
- [ ] 스플릿 터널링 UI
- [ ] 연결 통계 대시보드
- [ ] 터널 검색/필터
- [ ] QR 코드 import + 키 생성
- [ ] 자동 업데이트

### Phase 4 — 고급 기능

- [ ] 앱별 스플릿 터널링
- [ ] 동시 멀티 터널
- [ ] DNS 누출 테스트 (내장)
- [ ] 라우트 시각화
- [ ] 네트워크 진단 도구
- [ ] 속도/레이턴시 테스트

## 레퍼런스 프로젝트

| 프로젝트 | 참고 포인트 |
|---------|-----------|
| [wireguard-windows](https://git.zx2c4.com/wireguard-windows/) | Go 기반 공식 Windows 앱. wg-quick 로직의 Go 구현 레퍼런스 |
| [r-wg](https://github.com/lurenjia534/r-wg) | 크래시 복구, WFP 방화벽, DNS 누출 방지, 권한 분리 설계 |
| [DefGuard Client](https://github.com/DefGuard/client) | Tauri 기반 클라이언트. 연결 통계, 죽은 연결 감지, .conf 파서 |
| [gluetun](https://github.com/qdm12/gluetun) | Go에서 wireguard-go 임베딩 + wg-quick 로직 재구현 (Linux) |
| [wireproxy](https://github.com/windtf/wireproxy) | Go에서 wireguard-go 임베딩 + .conf 파서 |

## 참고 자료

- [wireguard-go 공식 레포](https://git.zx2c4.com/wireguard-go/)
- [wgctrl-go 공식 레포](https://github.com/WireGuard/wgctrl-go)
- [wireguard-windows winipcfg 패키지](https://pkg.go.dev/golang.zx2c4.com/wireguard/windows/tunnel/winipcfg)
- [vishvananda/netlink](https://github.com/vishvananda/netlink)
- [golang.org/x/net/route](https://pkg.go.dev/golang.org/x/net/route)
- [Wails v3](https://v3alpha.wails.io/)
- [CodeMirror 6](https://codemirror.net/)
- [WireGuard macOS 앱 방치 이슈 (HN)](https://news.ycombinator.com/item?id=43369111)
- [WireGuard Embedding Guide](https://www.wireguard.com/embedding/)
- [WireGuard Cross-platform Interface](https://www.wireguard.com/xplatform/)
