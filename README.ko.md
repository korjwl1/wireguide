<p align="center">
  <img src="docs/appicon.png" width="128" alt="WireGuide" />
</p>

<h1 align="center">WireGuide</h1>

<p align="center">
  사실상 방치된 공식 WireGuard 클라이언트를 대체하는 크로스 플랫폼 VPN 클라이언트
</p>

<p align="center">
  <a href="https://github.com/korjwl1/wireguide/releases/latest"><img src="https://img.shields.io/github/v/release/korjwl1/wireguide?style=flat-square" alt="Release" /></a>
  <a href="#설치"><img src="https://img.shields.io/badge/homebrew-tap-blue?style=flat-square" alt="Homebrew" /></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform" />
  <a href="LICENSE"><img src="https://img.shields.io/github/license/korjwl1/wireguide?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <a href="README.md">English</a>
</p>

---

## 왜 만들었나?

공식 WireGuard 클라이언트는 macOS와 Windows 모두 사실상 방치 상태이며, 최신 OS에서 심각한 문제가 발생합니다.

### macOS: 마지막 업데이트 2023년 2월 — 3년 이상 방치

[공식 macOS 앱](https://apps.apple.com/us/app/wireguard/id1451685025?mt=12) (v1.0.16)은 2023년 2월 15일 이후 단 한 번도 업데이트되지 않았습니다. macOS 14 Sonoma, 15 Sequoia, 16 Tahoe 대응 업데이트가 **전무**합니다.

| 문제 | 영향 | 출처 |
|------|------|------|
| **Split DNS 미작동** | AllowedIPs가 `0.0.0.0/0`이 아니면 터널 DNS가 무시됨. Split-tunnel 사용자는 VPN DNS를 사용할 수 없음. | [wireguard-apple PR #11](https://github.com/WireGuard/wireguard-apple/pull/11) — 4년째 미병합 |
| **연결 해제 후 DNS 잔류** | 슬립/웨이크 후 연결을 끊어도 DNS 설정이 원래대로 돌아오지 않음. 재부팅 전까지 DNS가 오염됨. | [wireguard-tools PR #22](https://github.com/WireGuard/wireguard-tools/pull/22) |
| **슬립 후 터널 사망** | macOS 슬립 후 UDP 소켓이 "closed" 상태가 됨. 모든 통신이 조용히 실패. 자동 복구 없음. | [KaringX/karing#1360](https://github.com/KaringX/karing/issues/1360), [wireguard-go#41](https://github.com/inverse-inc/wireguard-go/issues/41) |
| **On-Demand 무한 루프** | macOS 사용자 전환 시 VPN 설정이 on/off 무한 루프에 빠지며 CPU 점유율 상승. | [WireGuard 메일링 리스트, 2023.11](https://lists.zx2c4.com/pipermail/wireguard/2023-November/008247.html) |
| **Sequoia 방화벽 충돌** | macOS 15의 "들어오는 연결 차단" 설정이 DNS 응답을 차단하여 VPN 연결이 깨짐. | [mjtsai.com](https://mjtsai.com/blog/2024/09/18/macos-firewall-regressions-in-sequoia/) |
| **킬 스위치 없음** | 터널이 끊어지면 트래픽이 ISP로 새어나감. | — |
| **자동 재연결 없음** | 네트워크 변경이나 슬립/웨이크 후 수동으로 다시 연결해야 함. | — |
| **GitHub 이슈 비활성화** | 공개 버그 트래커 없음. [커뮤니티에서 버그를 보고할 방법이 없음.](https://news.ycombinator.com/item?id=43369111) | [HN, 2025.3](https://news.ycombinator.com/item?id=43369111) |

### Windows: 마지막 릴리스 2021년 12월 — 4년 이상 경과

[공식 Windows 클라이언트](https://git.zx2c4.com/wireguard-windows) (v0.5.3)는 2021년 12월 22일이 마지막 릴리스입니다.

| 문제 | 영향 | 출처 |
|------|------|------|
| **Split tunnel DNS 유출** | DNS 쿼리가 모든 인터페이스로 전송되어 VPN 프라이버시가 무력화됨. | [Engineer Workshop](https://engineerworkshop.com/blog/dont-let-wireguard-dns-leaks-on-windows-compromise-your-security-learn-how-to-fix-it/) |
| **엔드포인트 재해석 없음** | 동적 DNS 엔드포인트를 최초 1회만 해석. 서버 IP가 변경되면 터널이 조용히 죽음. | [wireguard-windows#18](https://github.com/WireGuard/wireguard-windows/issues/18) — 4년 이상 미해결 |
| **킬 스위치 = LAN 차단** | Full-tunnel 킬 스위치가 프린터, NAS 등 로컬 장치까지 차단. /1 라우트로 우회하면 킬 스위치가 비활성화됨. | [netquirk.md](https://github.com/WireGuard/wireguard-windows/blob/master/docs/netquirk.md) |
| **자동 재연결 없음** | 워치독이나 헬스체크 메커니즘 없음. | — |

### WireGuide가 해결하는 것

WireGuide는 `wg-quick`의 전체 로직을 Go로 구현했습니다 — [`darwin.bash`](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/darwin.bash), [`linux.bash`](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/linux.bash), [wireguard-windows](https://git.zx2c4.com/wireguard-windows) 소스와 라인별로 대조 검증했습니다.

- DNS를 **모든** 네트워크 서비스에 적용 (활성 서비스 하나만이 아닌)
- 게이트웨이 변경 시 라우트 모니터가 엔드포인트 바이패스 재적용
- pf/nftables/WFAS 기반 킬 스위치 (엔드포인트 + DHCP 예외 포함)
- 슬립/웨이크 및 네트워크 변경 후 지수 백오프 자동 재연결
- 매 라우트 이벤트마다 `wg show`에서 엔드포인트 재조회 (로밍 지원)
- 터널 활성 중에는 helper 프로세스가 절대 종료되지 않음 (wg-quick 시맨틱)

---

## 기능

| 기능 | 설명 |
|------|------|
| **터널 관리** | `.conf` 파일 가져오기, 생성, 편집, 내보내기. 드래그 앤 드롭 지원. |
| **설정 에디터** | CodeMirror 6 기반 WireGuard 문법 강조 및 자동완성 |
| **시스템 트레이** | 연결 상태 뱃지 (초록 점), 1클릭 연결/해제 |
| **킬 스위치** | VPN 외 모든 트래픽 차단 (macOS `pf` / Linux `nftables` / Windows `WFAS`) |
| **DNS 보호** | DNS 쿼리를 VPN 터널로만 강제 |
| **자동 재연결** | 지수 백오프 + 연결 상태 감시 |
| **슬립/웨이크 복구** | 시스템 슬립 후 자동 재연결 |
| **라우트 모니터** | 게이트웨이 변경 시 엔드포인트 바이패스 라우트 재적용 |
| **충돌 감지** | Tailscale 등 다른 WG 인터페이스와의 라우트 충돌 경고 |
| **진단 도구** | Ping 테스트, DNS 유출 검사, 라우트 테이블 시각화 |
| **자동 업데이트** | GitHub Releases 확인; `brew upgrade` 및 직접 설치 지원 |
| **속도 대시보드** | 실시간 RX/TX 그래프 |
| **다국어** | 영어, 한국어, 일본어 |
| **테마** | 다크 / 라이트 / 시스템 자동 |

---

## 설치

### macOS (Homebrew)

```bash
brew tap korjwl1/tap
brew install --cask wireguide
```

### macOS (수동)

[Releases](https://github.com/korjwl1/wireguide/releases)에서 다운로드 후 `/Applications`으로 이동.

### 소스에서 빌드

```bash
# 사전 요구
brew install go node
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/wailsapp/wails/v3/cmd/wails3@latest

# 빌드
task build

# 실행
./bin/wireguide
```

---

## 아키텍처

```
┌─────────────────────┐         ┌──────────────────────────┐
│   GUI 프로세스        │  UDS    │   Helper 프로세스 (root)   │
│   (Wails + Svelte)   │◄──────►│   wireguard-go + wgctrl  │
│                      │ JSON-  │   TUN / 라우팅 / DNS       │
│   설정 에디터          │  RPC   │   킬 스위치 / 방화벽        │
│   시스템 트레이        │        │   재연결 모니터             │
│   진단 도구           │        │   라우트 모니터             │
└─────────────────────┘         └──────────────────────────┘
```

- **단일 바이너리** — `wireguide`가 GUI 또는 helper로 동작 (`--helper` 플래그)
- **권한 분리** — GUI는 일반 권한; helper는 root로 실행
- **IPC** — Unix 소켓 (macOS/Linux) 또는 Named Pipe (Windows) 위 JSON-RPC
- **Helper 수명** — 터널 활성 중에는 종료하지 않음 (wg-quick 시맨틱)

---

## 라이선스

MIT
