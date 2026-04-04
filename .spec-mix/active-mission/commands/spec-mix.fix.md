---
description: 최소한의 문서로 경량 버그 수정 생성
scripts:
  sh: scripts/bash/create-fix.sh --json "{ARGS}"
  ps: scripts/powershell/create-fix.ps1 -Json "{ARGS}"
---

## 사용자 입력

```text
$ARGUMENTS
```

진행하기 전에 사용자 입력을 **반드시** 고려해야 합니다(비어있지 않은 경우).

## 개요

`/spec-mix.fix` 명령어는 버그 수정을 위한 경량 워크플로우를 생성하며, 전체 사양 프로세스를 피합니다. 다음에 중점을 둡니다:

1. **최소 문서화**: 문제 → 분석 → 해결 → 검증
2. **컨텍스트 연결**: 모든 기능에서 관련 Work Package 자동 검색
3. **빠른 실행**: 3단계 워크플로우 (분석 → 계획 → 실행)

## 실행 흐름

### Step 1: Fix 브랜치 및 문서 생성

1. **버그 설명 파싱** (`{ARGS}`에서):
   - 비어있는 경우: 사용자에게 버그 설명 요청

2. **컨텍스트 감지**:
   - feature 브랜치 (예: `001-user-auth`): feature-scoped fix 생성
   - main/master: hotfix 생성

3. **스크립트 실행** `{SCRIPT}`:
   ```bash
   {SCRIPT}
   ```

4. **JSON 출력 파싱**:
   - `FIX_ID`: Fix 식별자 (예: FIX01, HOTFIX-01-auth)
   - `FIX_TYPE`: "fix" 또는 "hotfix"
   - `BRANCH_NAME`: 생성된 브랜치 이름
   - `FIX_FILE`: Fix 문서 경로
   - `RELATED_WPS`: 발견된 관련 Work Package
   - `PRIORITY`: 제안된 우선순위 (P0-P3)

### Step 2: 원인 분석

1. **Fix 문서 읽기** (`FIX_FILE` 경로)

2. **관련 컨텍스트 검색**:
   - 버그 설명의 에러 메시지나 키워드로 코드베이스 grep
   - 버그와 관련된 파일 찾기
   - 영향받는 영역의 최근 커밋 히스토리 확인

3. **원인 분석 섹션 작성**:
   - 가설: 문제의 원인으로 추정되는 것
   - 증거: 코드 참조, 로그, 재현 단계
   - 관련 코드: 구체적인 file:line 참조 나열

4. **관련 Work Package 검토** (`RELATED_WPS`에 나열된):
   - 각 WP를 로드하여 원래 구현 이해
   - 수정에 관련된 컨텍스트 메모

### Step 3: 수정 계획 작성

1. **수정 접근 방식 결정**:
   - 1-2문장으로 요약
   - 최소한으로 유지 - 이것은 기능이 아니라 수정임

2. **필요한 변경 나열**:
   - 수정할 구체적인 파일
   - 추가하거나 업데이트할 테스트

3. **위험도 평가**:
   - Low: 격리된 변경, 부작용 없음
   - Medium: 여러 파일, 일부 통합 지점
   - High: 핵심 기능, 신중한 테스트 필요

4. **사용자와 우선순위 확인**:
   - 키워드 기반 제안된 우선순위 표시
   - 필요시 사용자가 재정의 가능

### Step 4: 수정 실행

1. **수정 구현**:
   - 버그 해결을 위한 최소한의 변경
   - 기존 코드 패턴 따르기
   - 범위 확대 방지 - 보고된 문제만 수정

2. **테스트 추가/업데이트**:
   - 버그를 재현하는 테스트 케이스 (수정 후 통과해야 함)
   - 필요에 따라 회귀 테스트

3. **Fix 참조로 커밋**:
   ```bash
   git add .
   git commit -m "[FIX_ID] 수정 내용 간략 설명"
   ```

4. **Fix 문서 업데이트**:
   - 검증 체크박스 완료로 표시
   - frontmatter의 status를 "done"으로 업데이트
   - 완료 타임스탬프와 함께 활동 로그 항목 추가

### Step 5: PR 생성

검증 완료 후:

1. **브랜치 푸시**:
   ```bash
   git push -u origin {BRANCH_NAME}
   ```

2. **Pull Request 생성**:
   ```bash
   gh pr create --title "[FIX_ID] 간략한 설명" --body "## 수정 요약

   **버그**: {BUG_DESCRIPTION}
   **우선순위**: {PRIORITY}
   **Fix 문서**: {FIX_FILE}

   ## 변경 사항
   - [변경 목록]

   ## 테스트
   - [추가/검증된 테스트]

   ## 관련
   - Work Packages: {RELATED_WPS}
   "
   ```

3. **PR URL 보고**

## 우선순위 키워드 참조

| 우선순위 | 트리거 키워드 |
|----------|---------------|
| P0 (Critical) | security, crash, data loss, production, urgent, 보안, 크래시, 데이터손실, 프로덕션, 긴급 |
| P1 (High) | broken, error, fails, blocking, regression, 오류, 실패, 차단, 회귀 |
| P2 (Medium) | incorrect, wrong, unexpected, issue, bug, 잘못된, 예상치못한, 이슈, 버그 |
| P3 (Low) | minor, cosmetic, typo, improvement, 사소한, 외관, 오타, 개선 |

## Fix 유형

### Feature-scoped Fix
- **브랜치**: `{FEATURE}-fix-{NUM}` (예: `001-user-auth-fix-01`)
- **문서**: `specs/{FEATURE}/fixes/FIX{NUM}.md`
- **사용 시점**: 버그가 기존 feature 범위 내에 있을 때

### Hotfix
- **브랜치**: `hotfix-{NUM}-{description}` (예: `hotfix-01-auth-timeout`)
- **문서**: `specs/hotfix/HOTFIX-{NUM}-{description}.md`
- **사용 시점**: main에서 즉각적인 주의가 필요한 중요 버그

## 완료

PR 생성 성공 후 사용자에게 보고:
- Fix ID 및 브랜치 이름
- Fix 문서 위치
- PR URL
- 참조된 관련 Work Package
