# Implementation Plan: WireGuide — WireGuard Desktop Client MVP

**Branch**: `001-wireguard-mvp` | **Date**: 2026-04-04 | **Spec**: [wireguard-app.md](../../wireguard-app.md)
**Input**: `wireguard-app.md` Phase 1 요구사항 + `research-wireguard-approaches.md` + `research-vpn-client-ux.md`

## Clarification Decisions (2026-04-04)

| # | 질문 | 결정 | 영향 |
|---|------|------|------|
| 1 | 프로젝트 이름 | **wireguide** | Go 모듈 경로, OS 저장 경로, 바이너리명 |
| 2 | Wails 버전 | **v3 (알파)** | 시스템 트레이 내장 지원, API 변경 리스크 감수 |
| 3 | 프론트엔드 | **Svelte** | 경량 빌드, WebView 최적 |
| 4 | MVP i18n | **3개 언어 (영어/한국어/일본어)** | i18n 구조 + 번역 모두 MVP에 포함 |
| 5 | MVP 타겟 OS | **3 OS 동시 (macOS/Windows/Linux)** | WP03에서 3 OS 네트워킹 모두 구현 |
| 6 | Pre/PostUp 처리 | **경고 후 실행 허용** | 사용자 확인 다이얼로그 필요 |
| 7 | 터널 수 제한 | **없음** | 실용적으로 100개 이상 사용 사례 없음 |
| 8 | .conf 파일 연동 | **OS 지원 범위에서만** | 불가능한 OS는 스킵 |
| 9 | 트레이 아이콘 | **VPN 로고 + 초록점** | 모노크롬 옵션 MVP 제외 |

## Summary

**WireGuide** — macOS/Windows/Linux 크로스플랫폼 WireGuard GUI 클라이언트 MVP 구현.
Go + Wails v3 기반으로 wireguard-go를 임베딩하여 단일 바이너리로 배포.
Phase 1에서는 단일 프로세스(sudo/admin)로 동작하며, 터널 관리/연결/상태 표시/시스템 트레이의 핵심 기능을 3 OS에서 동시 구현한다.
UI는 영어/한국어/일본어 3개 언어를 MVP부터 지원한다.

## Technical Context

**Project Name**: wireguide
**Language/Version**: Go 1.25+ (권장: Go 1.26.1, Wails v3 go.mod 요구사항)
**Primary Dependencies**: Wails v3 (alpha.74, pinned), wireguard-go, wgctrl-go, wintun (Windows), vishvananda/netlink (Linux), winipcfg (Windows)
**Frontend**: Svelte + TypeScript + Vite
**Storage**: JSON (앱 설정) + .conf 파일 (터널)
**Testing**: `go test` (백엔드), Vitest (프론트엔드)
**Target Platform**: macOS (arm64/amd64), Windows (amd64), Linux (amd64/arm64) — **3 OS 동시**
**Project Type**: Desktop App (Go backend + Web frontend via Wails)
**i18n**: 영어(en) / 한국어(ko) / 일본어(ja) — MVP부터
**Constraints**: sudo/admin 권한 필요 (TUN 생성), Windows에 wintun.dll 번들 필요
**Pre/PostUp Scripts**: 사용자 확인 다이얼로그 후 실행 허용

## Project Structure

### Documentation

```text
specs/001-wireguard-mvp/
├── plan.md              # 이 파일
├── tasks.md             # 태스크 목록
└── walkthrough-*.md     # 각 Phase 완료 후 생성
```

### Source Code

```text
/
├── main.go                      # Wails 앱 진입점
├── go.mod / go.sum              # 모듈: github.com/<user>/wireguide
├── wails.json                   # Wails v3 프로젝트 설정
│
├── internal/
│   ├── config/
│   │   ├── parser.go            # .conf 파서 (INI → 구조체)
│   │   ├── validator.go         # 유효성 검사 (키, CIDR, 필수 필드)
│   │   ├── types.go             # WireGuard Config 타입 정의
│   │   ├── scripts.go           # PreUp/PostUp 스크립트 감지 + 실행
│   │   └── parser_test.go
│   │
│   ├── tunnel/
│   │   ├── manager.go           # 터널 CRUD + 연결/해제 오케스트레이션
│   │   ├── engine.go            # wireguard-go 임베딩 + TUN 생성
│   │   ├── status.go            # 연결 상태 조회 (RX/TX, handshake)
│   │   ├── recovery.go          # 크래시 복구 (고아 인터페이스/라우트/DNS 정리)
│   │   └── manager_test.go
│   │
│   ├── network/
│   │   ├── interface.go         # OS별 네트워킹 인터페이스
│   │   ├── linux.go             # Linux: netlink IP/라우팅/DNS
│   │   ├── darwin.go            # macOS: ifconfig/route/networksetup
│   │   ├── windows.go           # Windows: winipcfg
│   │   └── network_test.go
│   │
│   ├── storage/
│   │   ├── tunnels.go           # 터널 .conf 파일 저장/로드/삭제
│   │   ├── settings.go          # 앱 설정 JSON 저장/로드
│   │   └── paths.go             # OS별 경로 (XDG, AppData, Library)
│   │
│   └── app/
│       └── app.go               # Wails 바인딩: Go ↔ JS 브릿지
│
├── frontend/
│   ├── src/
│   │   ├── App.svelte           # 메인 앱 컴포넌트
│   │   ├── lib/
│   │   │   ├── TunnelList.svelte    # 좌측 터널 목록
│   │   │   ├── TunnelDetail.svelte  # 우측 상세 패널
│   │   │   ├── ImportDialog.svelte  # Import 다이얼로그
│   │   │   ├── ConfigEditor.svelte  # Config textarea 에디터
│   │   │   ├── StatusBar.svelte     # 연결 상태 (RX/TX, handshake)
│   │   │   ├── Settings.svelte      # 설정 화면
│   │   │   └── ScriptWarning.svelte # PreUp/PostUp 경고 다이얼로그
│   │   ├── i18n/
│   │   │   ├── index.ts         # i18n 초기화 + 시스템 언어 감지
│   │   │   ├── en.json          # 영어
│   │   │   ├── ko.json          # 한국어
│   │   │   └── ja.json          # 일본어
│   │   ├── stores/
│   │   │   ├── tunnels.ts       # 터널 상태 스토어
│   │   │   └── connection.ts    # 연결 상태 스토어
│   │   └── main.ts
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
│
└── build/
    ├── darwin/                  # macOS 빌드 리소스
    ├── windows/                 # Windows 빌드 리소스 (wintun.dll)
    └── linux/                   # Linux 빌드 리소스
```

**Structure Decision**: Wails v3 표준 구조를 따르되, Go 백엔드는 `internal/` 패키지로 분리하여 관심사를 명확히 구분. 프론트엔드는 Svelte (경량, WebView에 적합)를 사용.

## Privilege Escalation Strategy (MVP)

MVP에서는 권한 분리 데몬 없이, GUI 프로세스에서 직접 권한 상승:

| OS | 방법 | 상세 |
|----|------|------|
| **macOS** | `osascript` admin 프롬프트 | GUI는 일반 사용자로 실행. 네트워크 작업(TUN 생성, 라우팅, DNS) 시 `osascript -e 'do shell script "..." with administrator privileges'`로 privileged subprocess 실행 |
| **Linux** | `pkexec` (PolicyKit) | 네트워크 작업 시 pkexec로 권한 상승. PolicyKit policy 파일 번들 |
| **Windows** | 앱 매니페스트 `requireAdministrator` | 실행 시 UAC 프롬프트 자동 표시 |

Phase 2에서 GUI ↔ 데몬 분리로 마이그레이션 예정.

## Crash Recovery Strategy (MVP)

터널 연결 중 앱 크래시 시 TUN/라우트/DNS가 고아 상태가 되는 문제 대응:

1. **상태 파일 기록**: 연결 시 `<data_dir>/active-tunnel.json`에 활성 터널 상태 저장 (인터페이스명, 원본 DNS, 원본 라우트)
2. **정상 해제**: 연결 해제 시 상태 파일 읽고 원래 상태 복원 → 상태 파일 삭제
3. **시작 시 정리**: 앱 시작 시 상태 파일이 남아있으면 → 이전 크래시로 판단 → 고아 인터페이스/라우트/DNS 자동 정리
4. **파일 위치**: macOS `/Library/Application Support/wireguide/`, Windows `%PROGRAMDATA%/wireguide/`, Linux `/var/lib/wireguide/`

## Risk Mitigation

| 리스크 | 영향 | 완화 |
|--------|------|------|
| Wails v3 알파 API 변경 | 높음 | alpha.74 pin + `internal/app/` 어댑터 레이어로 Wails API 격리 |
| DNS 설정 OS별 복잡성 | 높음 | WP03에서 OS별 스파이크 먼저 실행 |
| 풀터널 라우팅 복잡성 | 높음 | OS별 별도 구현 + wireguard-windows/wg-quick 레퍼런스 |
| macOS sudo GUI 제약 | 중간 | osascript 패턴으로 privileged subprocess |
| wireguard-go 순수 Go (CGO 불필요) | 낮음 | 크로스 컴파일 용이 — 오히려 장점 |
