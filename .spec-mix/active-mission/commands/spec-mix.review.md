---
description: 완료된 작업을 검토하고 승인된 작업을 done 레인으로 이동
---

## 사용자 입력

```text

$ARGUMENTS

```text

진행하기 전에 사용자 입력을 **반드시** 고려해야 합니다(비어있지 않은 경우).

## 개요

이 명령은 완료되어 `for_review` 레인으로 이동된 작업을 검토하는 데 도움을 줍니다. 각 작업을 검토하고, 수락 기준을 충족하는지 확인한 후, 승인(done으로 이동)하거나 변경을 요청합니다.

## 실행 흐름

1. **기능 디렉토리 식별**:
- 현재 브랜치를 사용하여 기능 찾기 (예: `001-feature-name`)
- `specs/{feature}/tasks/for_review/` 디렉토리 위치 확인

1. **검토 대상 작업 스캔**:
   ```bash

   ls specs/{feature}/tasks/for_review/*.md
   ```

- 작업이 없으면 사용자에게 알리고 종료
- 검토 대기 중인 모든 작업 패키지 나열

1. **for_review의 각 작업에 대해**:

   a. **작업 패키지 읽기**:
      - `WPxx.md` 파일 열기
      - 목표, 수락 기준, 구현 노트 검토
      - 컨텍스트를 위한 활동 로그 확인

   b. **완료 확인**:
      - ✅ 모든 수락 기준이 충족되었는가?
      - ✅ 코드 품질이 수용 가능한가?
      - ✅ 프로젝트 원칙을 따르는가 (`specs/constitution.md`가 존재하는 경우)?
      - ✅ 테스트가 통과하는가(해당되는 경우)?
      - ✅ 문서가 업데이트되었는가?
      - ✅ 명백한 버그나 문제가 없는가?

   c. **결정**:
      - **승인**: 작업이 모든 기준 충족
      - **변경 요청**: 수정이 필요한 문제 발견

1. **승인된 작업의 경우**:
   ```bash

   .spec-mix/scripts/bash/move-task.sh WPxx for_review done specs/{feature}
   ```

- 작업 패키지를 `for_review/`에서 `done/`으로 이동
- 프론트매터 업데이트: `lane: done`, `completed_at: <timestamp>`
- 활동 로그에 추가

1. **변경이 필요한 작업의 경우**:
   ```bash

   .spec-mix/scripts/bash/move-task.sh WPxx for_review doing specs/{feature}
   ```

- `doing/` 레인으로 되돌리기
- **중요**: WP 파일의 활동 로그에 구조화된 리뷰 피드백 추가
- 아래 형식을 사용하여 명확하고 실행 가능한 피드백 제공

1. **tasks.md 업데이트**:
- 완료된 작업을 `[x]`로 표시
- 상태 요약 업데이트

1. **요약 보고**:
   ```

   검토 요약:
   ✅ 승인됨: WP01, WP03, WP05
   🔄 변경 필요: WP02 (테스트 누락), WP04 (문서 불완전)
   📊 진행률: 3/5 작업 완료 (60%)
   ```

## 품질 검사

작업을 승인하기 전에 확인:

- [ ] **기능**: 사양대로 작동

- [ ] **코드 품질**: 읽기 쉽고, 유지보수 가능하며, 규칙 준수

- [ ] **헌장 준수**: `specs/constitution.md`에 정의된 프로젝트 원칙 준수 (존재하는 경우)

- [ ] **테스트**: 적절한 테스트 커버리지

- [ ] **문서**: 코드 주석, README 업데이트

- [ ] **회귀 없음**: 기존 기능이 여전히 작동

- [ ] **수락 기준**: WP 파일의 모든 기준 충족

## 엣지 케이스

- **빈 for_review 레인**: 검토할 작업이 없음을 사용자에게 알림

- **부분 완료**: 일부 기준은 충족하지만 전부는 아닌 경우, 구체적인 피드백 제공

- **여러 검토자**: 중복 검토를 피하기 위해 작업에 검토 메타데이터가 있는지 확인

## 출력 형식

검토 결과를 명확하게 제시:

```markdown

# 검토 보고서: {feature-name}

## 검토 날짜: {date}

### ✅ 승인된 작업 (done으로 이동)

#### WP01: 사용자 인증

- 모든 수락 기준 충족

- 테스트 통과

- 문서 업데이트됨

- 문제 없음

### 🔄 변경이 필요한 작업 (doing으로 되돌림)

#### WP02: 비밀번호 재설정

- ❌ 엣지 케이스에 대한 단위 테스트 누락

- ❌ 오류 메시지가 사용자 친화적이지 않음

- ✅ 핵심 기능은 작동함

**필요한 조치**: 테스트 추가 및 오류 처리 개선

## 다음 단계

- WP02에 대한 피드백 처리

- 남은 계획된 작업 계속 진행

- 모든 작업이 done 레인에 있을 때 `/spec-mix.accept` 실행

## 구조화된 리뷰 피드백 형식

Work Package 파일의 활동 로그에 리뷰 피드백을 추가할 때는 명확성과 일관성을 위해 다음 구조화된 형식을 사용하세요:

### 승인된 작업의 경우:

```markdown
- {TIMESTAMP}: [REVIEW] APPROVED by {REVIEWER_NAME}
  - ✅ 모든 수락 기준 충족
  - ✅ 코드 품질이 기준 충족
  - ✅ 테스트 통과
  - ✅ 문서 업데이트됨
```

### 변경이 필요한 작업의 경우:

```markdown
- {TIMESTAMP}: [REVIEW] CHANGES REQUESTED by {REVIEWER_NAME}
  - ❌ 문제 1: {문제 설명}
    - 위치: {file:line 또는 section}
    - 조치: {수정해야 할 사항}
  - ❌ 문제 2: {문제 설명}
    - 위치: {file:line 또는 section}
    - 조치: {수정해야 할 사항}
  - ✅ {잘 된 부분}
  - 다음 단계: {필요한 변경사항 요약}
```

### 예시 - 승인됨:

```markdown
- 2025-11-18T10:30:00Z: [REVIEW] APPROVED by Claude
  - ✅ 모든 수락 기준 충족
  - ✅ HttpMethod enum이 GET, POST, PUT, DELETE, PATCH를 올바르게 구현
  - ✅ 단위 테스트가 100% 커버리지로 모든 메서드 포함
  - ✅ Type hint와 docstring 완료
  - ✅ 프로젝트 코드 스타일 가이드라인 준수
```

### 예시 - 변경 요청:

```markdown
- 2025-11-18T10:45:00Z: [REVIEW] CHANGES REQUESTED by Claude
  - ❌ 로그인 함수에 오류 처리 누락
    - 위치: src/auth/login.py:45-60
    - 조치: 네트워크 오류 및 잘못된 자격 증명에 대한 try-catch 블록 추가
  - ❌ 테스트 커버리지 부족
    - 위치: tests/test_auth.py
    - 조치: 엣지 케이스 테스트 추가 (빈 비밀번호, 특수 문자, SQL injection)
  - ❌ API 문서 업데이트 필요
    - 위치: docs/api.md
    - 조치: 새로운 오류 코드로 인증 엔드포인트 문서 업데이트
  - ✅ 핵심 인증 로직이 견고하고 잘 구조화됨
  - ✅ 비밀번호 해싱 구현이 모범 사례 준수
  - 다음 단계: 위 3가지 문제 해결 후 for_review로 다시 이동
```

### 구조화된 형식의 장점:

- **명확성**: 리뷰어와 구현자 모두 필요한 사항을 이해
- **실행 가능성**: 구체적인 위치와 조치로 수정이 간단함
- **추적 가능성**: 다음 리뷰에서 모든 문제 해결 여부 확인 용이
- **긍정적**: 문제뿐만 아니라 잘된 부분도 인정
- **감사 추적**: WP 파일의 활동 로그에 영구 기록 생성
- **대시보드 준비**: 구조화된 형식을 파싱하여 타임라인에 표시 가능

### WP 파일에 추가하는 방법:

`move-task.sh` 실행 후, WP 파일에 리뷰 피드백을 수동으로 추가:

```bash
# 예시: 리뷰 피드백 추가
echo "" >> specs/{feature}/tasks/doing/WP02.md
echo "- $(date -u +%Y-%m-%dT%H:%M:%SZ): [REVIEW] CHANGES REQUESTED by Claude" >> specs/{feature}/tasks/doing/WP02.md
echo "  - ❌ 로그인 함수에 오류 처리 누락" >> specs/{feature}/tasks/doing/WP02.md
echo "    - 위치: src/auth/login.py:45-60" >> specs/{feature}/tasks/doing/WP02.md
echo "    - 조치: 네트워크 오류에 대한 try-catch 블록 추가" >> specs/{feature}/tasks/doing/WP02.md
# ... 등
```

또는 WP 파일을 직접 편집하여 활동 로그 섹션에 구조화된 피드백을 추가하세요.

```text
