---
description: Execute implementation with Work Package lane workflow (Pro Mode)
scripts:
  sh: scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks
  ps: scripts/powershell/check-prerequisites.ps1 -Json -RequireTasks -IncludeTasks
---

## User Input

```text
$ARGUMENTS
```

## Lane Workflow (MANDATORY)

```
planned → doing → for_review → done
```

**Rules**:
- Task MUST be in `doing` before coding
- Commits MUST include `[WP##]`
- Completed tasks MUST move to `for_review`

## Execution Flow

### 1. Run Prerequisites Script

```bash
{SCRIPT}
```
Parse FEATURE_DIR from output.

### 2. Check Lane Status

```bash
ls $FEATURE_DIR/tasks/{planned,doing,for_review,done}/*.md 2>/dev/null | wc -l
```

Display:
```
Lane Status:
├─ planned:    X tasks
├─ doing:      X tasks
├─ for_review: X tasks
└─ done:       X tasks
```

### 3. Select Task

- If task in `doing`: Continue or select new
- If no task in `doing`: Select from `planned`

Move task:
```bash
bash .spec-mix/scripts/bash/move-task.sh WP## planned doing $FEATURE_DIR
```

### 4. Load Context

Read (in order):
1. `{SPEC_DIR}/tasks.md` - task list
2. `{SPEC_DIR}/plan.md` - architecture
3. `specs/constitution.md` - project principles (if exists)
4. `{SPEC_DIR}/data-model.md` (if exists)

### 5. Implement

**Before coding**: Verify task in `doing`

Execute by phase:
- Setup → Tests → Core → Integration → Polish
- Respect dependencies
- Follow TDD when applicable

### 6. Commit

Format:
```bash
git commit -m "[WP##] Brief description

- Change 1
- Change 2"
```

### 7. Complete Task

Move to review:
```bash
bash .spec-mix/scripts/bash/move-task.sh WP## doing for_review $FEATURE_DIR
```

### 8. Walkthrough 생성 (필수 - 반드시 실행)

⚠️ **이 단계를 건너뛰지 마세요!** Walkthrough 파일은 리뷰 프로세스에 필수입니다.

1. 변경된 파일 확인:
   ```bash
   git diff --name-status HEAD~1
   ```

2. **반드시** `$FEATURE_DIR/walkthrough.md` 파일을 생성하세요:

```markdown
# Implementation Walkthrough

**Generated**: {현재 날짜/시간}
**Task**: WP## - {작업 제목}

## Summary
{구현한 내용을 2-3문장으로 설명}

## Files Modified
| Status | File |
|--------|------|
{git diff 결과로 변경된 파일 테이블}

## Key Changes
- **{파일 경로}**: {무엇이 왜 변경되었는지}

## Commits
{[WP##] 태그가 포함된 이 작업의 커밋 목록}

## Next Steps
1. `/spec-mix.review` 실행하여 구현 검토
2. 승인 후 `/spec-mix.accept` 실행
3. 마지막으로 `/spec-mix.merge`로 main에 병합
```

⚠️ **중요**: 이 파일이 없으면 대시보드에서 리뷰 상태를 확인할 수 없습니다.

## Next Steps

```
✓ Implementation complete for WP##

Next:
1. /spec-mix.review - Review completed work
2. /spec-mix.accept - Acceptance check
3. /spec-mix.merge - Merge to main
```
