---
description: Execute phase-based implementation with walkthrough and review (Normal Mode)
---

## Overview

Normal Mode executes implementation **phase by phase**:
1. Execute one phase at a time
2. Generate walkthrough after completion
3. Present review → User accepts/rejects
4. Proceed to next phase after acceptance

## Step 1: Load Phase Info

```bash
# Get feature directory
FEATURE_DIR=$(cat .spec-mix/config.json | grep -o '"feature_dir"[^,]*' | cut -d'"' -f4)
```

Read `$FEATURE_DIR/tasks.md` and display:
```
Phase Progress:
├─ Phase 1: {name} - ✓ Complete
├─ Phase 2: {name} - ⏳ Current
└─ Phase 3: {name} - ○ Pending
```

## Step 2: Execute Current Phase

1. Display phase name and deliverables
2. Implement all deliverables
3. Write tests if applicable
4. Commit with descriptive messages
5. Mark phase complete in tasks.md

## Step 3: Walkthrough 생성 (필수)

각 단계 완료 후 **반드시 walkthrough 파일을 작성**해야 합니다. 이 파일은 프로젝트의 **작업 메모리** 역할을 합니다 - 무엇을 했고 왜 했는지에 대한 기록입니다.

1. 변경된 파일과 diff 가져오기:
   ```bash
   # 변경된 파일 목록
   git diff --name-status HEAD~{N}  # N = 이 단계의 커밋 수

   # 실제 코드 변경 내용
   git diff HEAD~{N} --unified=5
   ```

2. `$FEATURE_DIR/walkthrough-phase-{N}.md` **파일 작성**:

```markdown
# Walkthrough: Phase {N} - {Name}

**생성일**: {현재 날짜/시간}
**커밋 수**: {이 단계의 커밋 수}

## 요약
{이 단계에서 수행한 작업을 2-3문장으로 설명}

## 변경된 파일
| 상태 | 파일 | 설명 |
|------|------|------|
| M | src/component.ts | 유효성 검사 로직 추가 |
| A | src/utils/helper.ts | 새 유틸리티 함수 |
{git diff로 얻은 변경 파일 테이블}

## 상세 변경 내역

### {파일 경로 1}
**목적**: {이 파일을 변경한 이유}

```diff
{이 파일의 실제 diff - git diff HEAD~N -- path/to/file 사용}
```

### {파일 경로 2}
**목적**: {이 파일을 변경한 이유}

```diff
{이 파일의 실제 diff}
```

{변경된 각 중요 파일에 대해 반복}

## 주요 결정 사항
- **결정**: {어떤 결정을 내렸는지}
  - **이유**: {이 접근 방식을 선택한 이유}
  - **고려한 대안**: {거부된 다른 옵션들}

## 작업 메모리 노트
> 나중에 이 코드를 다시 볼 때 참고할 컨텍스트와 메모:
> - {구현 선택에 대한 중요한 컨텍스트}
> - {주의할 점이나 기억해야 할 사항}
> - {확인해야 할 의존성이나 관련 파일}

## 커밋
| 해시 | 메시지 |
|------|--------|
{git log --oneline으로 이 단계의 커밋 목록}
```

**중요**:
- 이 파일은 **작업 메모리** 역할을 합니다 - 당신이나 다른 개발자가 무엇을 했고 왜 했는지 이해할 수 있을 정도로 충분한 세부 정보를 포함하세요
- 중요한 변경 사항에 대한 실제 diff를 포함하세요
- 결정 사항과 그 이유를 문서화하세요
- 나중에 이 코드를 다시 볼 때 도움이 될 메모를 추가하세요

## Step 4: Present Review

```markdown
## Phase {N} Complete - Review

📄 Walkthrough: `walkthrough-phase-{N}.md`

### Summary
{2-3 sentences}

### Files Modified
- {file list}

---
| Choice | Action |
|--------|--------|
| **ACCEPT** | Proceed to next phase |
| **REJECT** | Request changes |

Type ACCEPT or REJECT:
```

## Step 5: Handle Decision

**ACCEPT**: Mark accepted, proceed to next phase (or final completion)
**REJECT**: Get feedback, make changes, re-generate walkthrough

## Step 6: Final Completion

When all phases accepted:
```markdown
## Implementation Complete

All phases accepted. Run `/spec-mix.merge` to finalize.
```
