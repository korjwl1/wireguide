---
description: 기능 브랜치를 main에 병합하고 정리
scripts:
  sh: scripts/bash/merge-feature.sh --json "{ARGS}"
  ps: scripts/powershell/merge-feature.ps1 -Json "{ARGS}"
---

## 사용자 입력

```text

$ARGUMENTS

```text

진행하기 전에 사용자 입력을 **반드시** 고려해야 합니다(비어있지 않은 경우).

## 개요

이 명령은 완료된 기능을 main 브랜치에 통합하며, 병합 전략 및 정리 옵션을 제공합니다.

## 전제조건

이 명령을 실행하기 전에:

1. ✅ 기능이 수락되어야 함 (먼저 `/spec-mix.accept` 실행)

1. ✅ 모든 작업이 `done/` 레인에 있어야 함

1. ✅ 모든 테스트가 통과해야 함

1. ✅ 작업 디렉토리가 깨끗해야 함 (커밋되지 않은 변경사항 없음)

## 병합 전략

### 표준 병합 (기본값)

```bash

/spec-mix.merge

```text

전체 기능 히스토리를 보존하는 병합 커밋을 생성합니다.

### 스쿼시 병합

```bash

/spec-mix.merge --strategy squash

```text

모든 기능 커밋을 단일 커밋으로 결합합니다.

### Fast-Forward 병합

```bash

/spec-mix.merge --strategy ff-only

```text

fast-forward 가능한 경우에만 병합 (선형 히스토리).

## 옵션

| 옵션 | 설명 |
|------|------|
| `--strategy <type>` | 병합 전략: `merge`, `squash`, `ff-only` (기본값: `merge`) |
| `--push` | 병합 후 자동으로 원격에 푸시 |
| `--cleanup-worktree` | 성공적인 병합 후 워크트리 디렉토리 제거 |
| `--keep-branch` | 병합 후 기능 브랜치 유지 (기본값: 삭제) |
| `--dry-run` | 실행하지 않고 미리보기 |
| `--no-verify` | 사전 병합 검증 건너뛰기 |

## 실행 흐름

1. **사전 병합 검증** (`--no-verify`가 아닌 경우):
   ```bash

   # 수락 상태 확인

   if [[ -f "specs/{feature}/acceptance.md" ]]; then
       # 상태가 APPROVED인지 확인

   else
       echo "Error: 기능이 수락되지 않음. 먼저 /spec-mix.accept 실행"
       exit 1
   fi

   # 커밋되지 않은 변경사항 확인

   if ! git diff-index --quiet HEAD --; then
       echo "Error: 작업 디렉토리에 커밋되지 않은 변경사항 있음"
       exit 1
   fi
   ```

1. **병합 준비**:
   ```bash

   # 변경사항 임시저장 (만약을 위해)

   git stash save "Pre-merge stash"

   # main 브랜치로 전환

   git checkout main

   # 최신 변경사항 가져오기

   git pull origin main
   ```

1. **병합 실행**:

   **표준 병합**:
   ```bash

   git merge {feature-branch} --no-ff -m "Merge feature {feature}"
   ```

   **스쿼시 병합**:
   ```bash

   git merge {feature-branch} --squash
   git commit -m "feat: {feature-description}

   $(cat specs/{feature}/spec.md | head -20)

   Closes #{feature-number}"
   ```

   **Fast-forward**:
   ```bash

   git merge {feature-branch} --ff-only
   ```

1. **병합 후 조치**:

   a. **원격에 푸시** (`--push`인 경우):
      ```bash

      git push origin main
      ```

   b. **워크트리 정리** (`--cleanup-worktree`인 경우):
      ```bash

      .spec-mix/scripts/bash/setup-worktree.sh --feature {feature} --cleanup
      ```

   c. **기능 브랜치 삭제** (`--keep-branch`가 아닌 경우):
      ```bash

      git branch -d {feature-branch}
      # 존재하는 경우 원격 브랜치도 삭제

      git push origin --delete {feature-branch} 2>/dev/null || true
      ```

1. **기능 문서 보관** (선택사항):
   ```bash

   # specs를 아카이브로 이동

   mkdir -p archive/
   mv specs/{feature}/ archive/{feature}/
   git add archive/{feature}/
   git commit -m "chore: archive {feature} documentation"
   ```

1. **요약 보고**:
   ```markdown

   ✅ 기능이 성공적으로 병합되었습니다!

   **기능**: {feature}
   **전략**: {merge-strategy}
   **커밋**: {commit-count}
   **브랜치**: main

### 변경사항

- 변경된 파일: {file-count}
- 추가: {additions}
- 삭제: {deletions}

### 다음 단계

- 기능 브랜치 삭제됨: {feature-branch}
- 워크트리 정리됨: .worktrees/{feature}
- 문서 보관됨: archive/{feature}/

   다음 기능을 시작할 준비 완료! 실행:
   /spec-mix.specify "다음 기능 설명"
   ```

## 충돌 해결

병합 충돌이 발생하는 경우:

1. **충돌 파일 표시**:
   ```bash

   git status
   ```

1. **해결 가이드**:
   ```markdown

   ⚠️ 다음 파일에서 병합 충돌 감지됨:
- {file1}
- {file2}

   수동으로 충돌을 해결하세요:
   1. 충돌된 파일 열기
   1. 충돌 해결을 위해 편집
   1. 해결된 파일 스테이징: git add {file}
   1. 병합 완료: git commit

   또는 병합 중단: git merge --abort
   ```

1. **해결 대기**: 충돌이 해결될 때까지 명령 일시 중지

## 롤백

병합이 실패하거나 취소하려는 경우:

```bash

# 진행 중인 병합 중단

git merge --abort

# 또는 완료된 병합 후 리셋 (위험)

git reset --hard HEAD~1

# 필요시 워크트리 복원

git worktree add .worktrees/{feature} {feature-branch}

```text

## Dry Run 출력

`--dry-run` 사용 시:

```markdown

🔍 병합 미리보기: {feature}

**전략**: {merge-strategy}
**현재 브랜치**: main
**대상 브랜치**: {feature-branch}

### 병합될 변경사항:

- 커밋: {commit-count}

- 변경된 파일: {file-count}

- 테스트 상태: ✅ 통과

### 수행될 작업:

1. main 브랜치로 전환

1. 최신 변경사항 가져오기

1. {strategy}를 사용하여 {feature-branch} 병합

1. [x] 원격에 푸시

1. [x] 워크트리 정리

1. [x] 기능 브랜치 삭제

⚠️  이것은 dry run입니다. 변경사항이 적용되지 않았습니다.
실행하려면 --dry-run 플래그 없이 실행하세요.

```text

## 예시

### 간단한 병합

```bash

/spec-mix.merge

```text

### 스쿼시 및 푸시

```bash

/spec-mix.merge --strategy squash --push

```text

### 전체 정리

```bash

/spec-mix.merge --push --cleanup-worktree

```text

### 미리보기만

```bash

/spec-mix.merge --dry-run

```text

## 안전 기능

- ✅ 병합 전 수락 필요

- ✅ 커밋되지 않은 변경사항 확인

- ✅ 병합 전 최신 main 가져오기

- ✅ 자동으로 백업 stash 생성

- ✅ 문제 발생 시 롤백 지침 제공
