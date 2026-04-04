---
description: Spec Kit 웹 대시보드 실행
scripts:
  sh: echo "대시보드는 specify CLI로 관리됩니다. 실행: spec-mix dashboard"
  ps: Write-Host "대시보드는 specify CLI로 관리됩니다. 실행: spec-mix dashboard"
---

## 사용자 입력

```text
$ARGUMENTS

```text
진행하기 전에 사용자 입력을 **반드시** 고려해야 합니다(비어있지 않은 경우).

## 개요

이 명령은 Spec Kit 웹 대시보드를 실행하고 관리하는 데 도움을 줍니다. 대시보드는 기능, 칸반 보드 및 프로젝트 산출물을 모니터링하기 위한 시각적 인터페이스를 제공합니다.

## 대시보드 기능

대시보드는 다음을 제공합니다:

1. **기능 개요**: 모든 기능의 상태 및 작업 수 확인

2. **칸반 보드**: 각 기능의 작업 레인(계획됨/진행 중/검토 대기/완료) 시각화

3. **산출물 뷰어**: 명세, 계획 및 기타 문서 읽기

4. **헌장**: 프로젝트 원칙 및 가이드라인 보기

5. **자동 새로고침**: 2초마다 실시간 업데이트

## 대시보드 실행

### 빠른 시작

```bash

# 대시보드 시작 및 브라우저에서 열기

spec-mix dashboard

```text

### 고급 옵션

```bash

# 특정 포트에서 시작

spec-mix dashboard start --port 9000

# 브라우저를 열지 않고 시작

spec-mix dashboard start

# 수동으로 브라우저 열기

spec-mix dashboard start --open

```text

## 대시보드 명령어

| 명령어 | 설명 |
|--------|------|
| `spec-mix dashboard` | 대시보드 시작 및 브라우저 열기 (기본) |
| `spec-mix dashboard start` | 대시보드 서버 시작 |
| `spec-mix dashboard start --port <port>` | 특정 포트에서 시작 |
| `spec-mix dashboard start --open` | 시작 후 브라우저에서 열기 |
| `spec-mix dashboard stop` | 실행 중인 대시보드 중지 |
| `spec-mix dashboard status` | 대시보드 실행 여부 확인 |

## 대시보드 URL

시작되면 대시보드는 다음 주소에서 사용 가능합니다:

```text
http://localhost:9237

```text
또는 지정된 경우 사용자 정의 포트:

```text
http://localhost:<PORT>

```text

## 대시보드가 표시하는 내용

### 기능 뷰

- `specs/` 디렉토리의 모든 기능 목록

- 워크트리의 기능 (`.worktrees/`)

- 레인별 작업 수

- 사용 가능한 산출물 (spec, plan, tasks 등)

### 칸반 보드

- 4개 레인: 계획됨, 진행 중, 검토 대기, 완료

- 각 레인의 작업(워크 패키지)

- 작업 제목 및 ID

- 작업 세부정보 보기 위한 클릭

### 산출물

- 명세 문서

- 구현 계획

- 작업 분해

- 연구 노트

- 데이터 모델

- 수락 보고서

## 대시보드 중지

```bash

# 대시보드 중지

spec-mix dashboard stop

# 또는 포그라운드 실행 중이면 Ctrl+C 사용

```text

## 대시보드 파일

대시보드는 다음에 상태를 저장합니다:

```text
.spec-mix/
├── dashboard.pid    # 프로세스 ID

├── dashboard.port   # 현재 포트

└── dashboard.token  # 종료 인증 토큰

```text

## 지원되는 워크플로우

### 기능 진행 모니터링

1. 대시보드 시작: `spec-mix dashboard`

2. 기능 목록 보기

3. 기능을 클릭하여 칸반 보드 확인

4. 실시간으로 레인을 통해 이동하는 작업 관찰

### 산출물 검토

1. 대시보드 열기

2. 기능 카드의 산출물 배지 클릭

3. 렌더링된 마크다운 콘텐츠 읽기

4. 뒤로 버튼으로 돌아가기

### 다중 기능 개발

1. 대시보드는 모든 워크트리의 기능 표시

2. 각 기능이 독립적으로 표시됨

3. 배지는 워크트리를 나타냄 (있는 경우)

## 기술 세부사항

- **포트 범위**: 기본 9237, 사용 중이면 자동 증가

- **새로고침 속도**: 기능 목록은 2초

- **접근**: localhost만 (네트워크에 노출되지 않음)

- **종료**: 보안을 위해 인증 토큰 필요

## 워크플로우와의 통합

대시보드는 다음 명령어를 보완합니다:
- `/spec-mix.specify` - 대시보드에 표시되는 기능 생성

- `/spec-mix.implement` - 레인을 통해 작업 이동

- `/spec-mix.review` - 칸반에 표시되는 작업 상태 변경

- `/spec-mix.accept` - 산출물로 표시되는 acceptance.md 생성

- `/spec-mix.merge` - 기능 라이프사이클 완료

## 문제 해결

**대시보드가 시작되지 않음:**

- 포트가 이미 사용 중인지 확인: `spec-mix dashboard status`

- 다른 포트 시도: `spec-mix dashboard start --port 9000`

**기능이 표시되지 않음:**

- `specs/` 디렉토리가 존재하는지 확인

- 기능 디렉토리에 `spec.md` 확인

- UI의 버튼으로 수동 새로고침

**대시보드가 중지되지 않음:**

- `spec-mix dashboard stop` 사용

- 멈춘 경우, 프로세스 찾기: `lsof -i :9237`

- 수동 종료: `kill <PID>`

## 참고사항

- 대시보드는 읽기 전용 (웹 UI를 통한 편집 불가)

- 마크다운 렌더링은 marked.js 라이브러리 사용

- 대시보드를 닫으면 자동 새로고침 비활성화

- 다국어 지원 (UI는 시스템 로케일에 적응)
