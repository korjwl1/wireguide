<p align="center">
  <img src="docs/appicon.png" width="128" alt="WireGuide" />
</p>

<h1 align="center">WireGuide</h1>

<p align="center">
  킬 스위치와 자동 재연결을 지원하는 크로스 플랫폼 WireGuard VPN 클라이언트
</p>

<p align="center">
  <a href="https://github.com/korjwl1/wireguide/releases/latest"><img src="https://img.shields.io/github/v/release/korjwl1/wireguide?style=flat-square" alt="Release" /></a>
  <a href="https://github.com/korjwl1/wireguide/stargazers"><img src="https://img.shields.io/github/stars/korjwl1/wireguide?style=flat-square" alt="Stars" /></a>
  <a href="#설치"><img src="https://img.shields.io/badge/homebrew-tap-blue?style=flat-square" alt="Homebrew" /></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform" />
  <a href="LICENSE"><img src="https://img.shields.io/github/license/korjwl1/wireguide?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <a href="README.md">English</a>
</p>

---

<table>
  <tr>
    <td align="center"><img src="docs/screenshots/06-connected.png" width="400" /><br><sub>VPN 연결됨</sub></td>
    <td align="center"><img src="docs/screenshots/02-editor.png" width="400" /><br><sub>설정 에디터</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="docs/screenshots/03-autocomplete.png" width="400" /><br><sub>자동완성</sub></td>
    <td align="center"><img src="docs/screenshots/05-settings.png" width="400" /><br><sub>설정</sub></td>
  </tr>
</table>

---

## 설치

**macOS 15+ (Apple Silicon)** 및 **Windows 11 (amd64)** 에서 테스트 완료.

### macOS (Homebrew) — 권장

```bash
brew tap korjwl1/tap
brew install --cask wireguide
```

### macOS (수동)

[Releases](https://github.com/korjwl1/wireguide/releases)에서 다운로드 후 `/Applications`으로 이동.

> macOS에서 "앱이 손상되었습니다" 경고가 뜨면: `xattr -cr /Applications/WireGuide.app`

### Windows (설치 파일)

[Releases](https://github.com/korjwl1/wireguide/releases)에서 `WireGuide-windows-amd64.exe`
(또는 `-arm64.exe`) 설치 파일을 다운로드 후 실행. NSIS 인스톨러가 헬퍼 서비스와 단축 아이콘을
등록합니다.

> Windows SmartScreen에서 "확인되지 않은 게시자" 경고가 뜰 수 있습니다 — 현재 코드 서명이
> 없습니다. "추가 정보" → "실행"을 클릭하세요.

### 소스에서 빌드

```bash
brew install go node
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/wailsapp/wails/v3/cmd/wails3@latest

task build
./bin/wireguide
```

---

## 기능

| 기능 | 설명 |
|------|------|
| **Wi-Fi 자동연결** | 터널별 SSID 규칙: 네트워크 진입 시 자동연결, 이탈 시 자동해제, 신뢰 네트워크 지원. GUI 종료 시에도 헬퍼에서 독립 동작. |
| **멀티 터널** | 여러 WireGuard 터널을 동시에 연결하고 터널별 독립 상태 관리 |
| **터널 관리** | `.conf` 파일 가져오기, 생성, 편집, 내보내기. 드래그 앤 드롭 지원. |
| **설정 에디터** | CodeMirror 6 기반 WireGuard 문법 강조 및 자동완성 |
| **시스템 트레이** | 연결 상태 뱃지, 1클릭 연결/해제 |
| **킬 스위치** | VPN 외 모든 트래픽 차단 — macOS `pf`, Linux `nftables`, Windows WFP (선택) |
| **루프 보호** | 항상 켜진 WFP 필터가 암호화된 피어 트래픽이 터널 어댑터로 다시 들어가는 것을 차단 — bypass /32 호스트 라우트가 누락돼도 Windows 풀터널 라우팅 루프(업로드 폭증 버그)를 막아냄 |
| **DNS 보호** | DNS 쿼리를 VPN 터널로만 강제 (선택) |
| **헬스 체크** | 핸드셰이크 상태 모니터링 및 자동 재연결 (선택) |
| **슬립/웨이크 복구** | macOS `NSWorkspace`, Linux `systemd-logind`, Windows 전원 알림 |
| **라우트 모니터** | 게이트웨이 변경 시 엔드포인트 바이패스 라우트 재적용 — macOS `RTM`, Linux netlink, Windows `NotifyIpInterfaceChange` |
| **인터페이스 고정** | WiFi + 이더넷 동시 연결 시 지연 스파이크 방지 |
| **충돌 감지** | Tailscale 등 다른 WG 인터페이스와의 라우트 충돌 경고 |
| **진단 도구** | DNS 유출 검사, 라우트 테이블 시각화 |
| **자동 업데이트** | GitHub Releases 확인; `brew upgrade` 및 직접 설치 지원 |
| **속도 대시보드** | 실시간 RX/TX 그래프 |
| **다국어** | 영어, 한국어, 일본어 |
| **테마** | 다크 / 라이트 / 시스템 자동 |

[wireguard-go](https://git.zx2c4.com/wireguard-go) 2025년 5월 빌드 사용 (공식 앱 대비 57커밋 앞섬).

---

## 아키텍처

```mermaid
graph LR
    subgraph GUI["GUI 프로세스 (일반 권한)"]
        A1[Wails + Svelte]
        A2[설정 에디터]
        A3[시스템 트레이]
        A4[진단 도구]
    end

    subgraph Helper["Helper 프로세스 (root)"]
        B1[wireguard-go + wgctrl]
        B2[TUN / 라우팅 / DNS]
        B3[킬 스위치 / 방화벽]
        B4[재연결 모니터]
        B5[라우트 모니터]
    end

    GUI <-->|"JSON-RPC over UDS"| Helper
```

- **단일 바이너리** — `wireguide`가 GUI 또는 helper로 동작 (`--helper` 플래그)
- **권한 분리** — GUI는 일반 권한; helper는 root로 실행
- **IPC** — Unix 소켓 (macOS/Linux) 또는 Named Pipe (Windows) 위 JSON-RPC

---

## 기술 스택

| 구성 요소 | 기술 |
|-----------|------|
| 언어 | Go 1.25+ |
| GUI | [Wails v3](https://wails.io) |
| 프론트엔드 | Svelte + Vite |
| WireGuard | [wireguard-go](https://git.zx2c4.com/wireguard-go) + [wgctrl-go](https://github.com/WireGuard/wgctrl-go) |
| 에디터 | [CodeMirror 6](https://codemirror.net/) |
| 방화벽 | macOS `pf` / Linux `nftables` / Windows WFP (Filtering Platform) |

---

## 기여

개발 환경 설정 및 가이드라인은 [CONTRIBUTING.md](CONTRIBUTING.md)를 참조하세요.

버그를 발견하셨나요? [이슈를 등록](https://github.com/korjwl1/wireguide/issues/new/choose)해 주세요.

---

## 후원

<a href="https://github.com/sponsors/korjwl1">
  <img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink?style=for-the-badge&logo=github" alt="Sponsor" />
</a>

WireGuide가 유용하셨다면 후원으로 개발을 지원해 주세요.

---

## 라이선스

[MIT](LICENSE)

---

## 코드 사이닝

SignPath Foundation 오픈소스 프로그램 승인이 완료되면 Windows
인스톨러는 SignPath를 통해 코드 사이닝됩니다. 사이닝 인프라는
[SignPath.io](https://signpath.io)에서 제공하며, 인증서는
[SignPath Foundation](https://signpath.org)에서 발급합니다.
사이닝 정책은 [SIGNING-POLICY.md](SIGNING-POLICY.md)에
문서화되어 있습니다.

> Free code signing provided by [SignPath.io](https://signpath.io),
> certificate by [SignPath Foundation](https://signpath.org).

SignPath 승인 전까지는 unsigned 빌드가 릴리스되며 첫 실행 시
SmartScreen이 노란색 "확인되지 않은 게시자" 경고를 표시합니다.
CI 워크플로우는 SignPath 시크릿이 없으면 unsigned `.exe`를 그대로
릴리스에 첨부하고 워크플로우 경고만 출력합니다(릴리스 실패가 아닙니다).

SignPath 승인이 거절될 경우 — OSS 프로그램에 명시적인 별 수 / 프로젝트
연차 기준은 없지만 통계적으로 더 성숙한 프로젝트가 통과하는 경향 —
대안은 Microsoft Azure **Artifact Signing** (2026년 1월 "Trusted
Signing"에서 이름 변경)입니다. 단, 개인 개발자 신원 검증을 거친
Public Trust 인증서 발급은 현재 미국·캐나다 거주자에게만 열려
있어, 그 외 국가 (한국 포함) 메인테이너는 법인 등록 후 조직
신원으로만 사용할 수 있습니다. 즉, 한국 단일 메인테이너 입장에서
이 폴백 경로는 "월 ~$10 구독"이 아니라 "법인 설립 + 월 ~$10
구독"이 됩니다.
