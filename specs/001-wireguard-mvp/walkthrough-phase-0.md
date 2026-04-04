# Walkthrough: Phase 0 - Project Bootstrap (WP00)

**생성일**: 2026-04-04
**커밋 수**: 1

## 요약
WireGuide 프로젝트의 기반을 구축했다. Go 1.26.1 + Wails v3 alpha.74 + Svelte 프론트엔드 스택을 초기화하고, wireguard-go/wgctrl-go 의존성 빌드 검증, Go-Svelte 바인딩 라운드트립, 시스템 트레이 동작을 모두 확인했다. 바이너리 ~7.6MB로 빌드 성공.

## 변경된 파일
| 상태 | 파일 | 설명 |
|------|------|------|
| A | main.go | Wails 앱 진입점 (창 + 시스템 트레이) |
| A | greetservice.go | Go-Svelte 바인딩 테스트용 서비스 |
| A | go.mod / go.sum | Go 모듈 (wireguide + wails v3 + wireguard-go) |
| A | Taskfile.yml | Wails 빌드 태스크 |
| A | .gitignore | Git 무시 규칙 |
| A | build/ | OS별 빌드 리소스 (darwin, windows, linux, 아이콘) |
| A | build/config.yml | Wails 프로젝트 설정 (WireGuide 메타데이터) |
| A | frontend/ | Svelte + Vite 프론트엔드 (App.svelte, bindings) |
| A | internal/config/ | .conf 파서 패키지 placeholder |
| A | internal/tunnel/ | 터널 관리 패키지 placeholder |
| A | internal/network/ | OS 네트워킹 패키지 placeholder |
| A | internal/storage/ | 저장소 패키지 placeholder |
| A | internal/app/ | Wails 바인딩 패키지 placeholder |
| A | specs/001-wireguard-mvp/ | spec.md, plan.md, tasks.md |

## 상세 변경 내역

### main.go
**목적**: Wails 앱 진입점. 창(900x600, 다크 배경) + 시스템 트레이(WireGuide 툴팁, Show/Quit 메뉴) 설정.

주요 설정:
- `ApplicationShouldTerminateAfterLastWindowClosed: false` — 창 닫아도 트레이에 유지
- `BackgroundColour: NewRGB(26, 26, 46)` — 다크 모드 기본 (#1a1a2e)
- 시스템 트레이: 기본 아이콘 + "WireGuide - Disconnected" 툴팁 + Show/Quit 메뉴

### greetservice.go
**목적**: Go ↔ Svelte 바인딩 검증용 최소 서비스. WP01부터 실제 서비스로 교체 예정.

### go.mod
**목적**: `github.com/korjwl1/wireguide` 모듈. Wails v3 alpha.74 + wireguard-go + wgctrl-go + wintun 의존성.

### frontend/src/App.svelte
**목적**: Wails 템플릿 기본 Svelte 앱. `changeme` → `github.com/korjwl1/wireguide` 바인딩 경로 수정.

## 주요 결정 사항
- **결정**: Wails v3 `wails3 init -t svelte`로 프로젝트 생성 후 필요 파일만 프로젝트 루트에 복사
  - **이유**: 기존 specs/ 디렉토리와 충돌 방지. 임시 디렉토리(/tmp)에서 init 후 선택적 복사.
  - **고려한 대안**: 빈 디렉토리에서 init 후 specs를 이동 — 더 복잡하고 git 히스토리 손실 위험.

- **결정**: wireguard-go blank import로 빌드 검증 후 제거
  - **이유**: WP00에서는 wireguard-go 코드를 실제로 사용하지 않으므로, 빌드 가능 여부만 확인하고 blank import는 제거.

- **결정**: 시스템 트레이를 WP00에서 조기 검증
  - **이유**: 트레이는 WP07 핵심 기능. Wails v3 알파에서 실제 동작하는지 WP00에서 확인하여 리스크 조기 제거.

## 작업 메모리 노트
> - Wails v3 alpha.74에서 바인딩 생성 시 `frontend/frontend/bindings/` (중복 경로) 디렉토리도 생성됨 — 버그로 보이나 빌드에 영향 없음
> - `wails3 build` 명령이 자동으로 bindings 생성 + frontend build + Go 빌드를 모두 수행
> - 모듈 경로를 `changeme`에서 변경 후 App.svelte의 import 경로도 반드시 동기화 필요
> - macOS에서 `ApplicationShouldTerminateAfterLastWindowClosed: false` 설정이 트레이 상주에 필수
> - NSIS가 미설치 상태 (Windows 인스톨러용) — Windows 패키징 시 설치 필요

## 커밋
| 해시 | 메시지 |
|------|--------|
| 7900b09 | [WP00] Project bootstrap: Wails v3 + Svelte + wireguard-go |
