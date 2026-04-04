---
id: [WP_ID]
task_id: [TASK_ID]
title: [TITLE]
phase: [PHASE]
lane: planned
status: pending
created_at: [DATE]
started_at: null
completed_at: null
estimated_time: [ESTIMATED_TIME]
actual_time: null
depends_on: [DEPENDENCIES]
files_modified: []
---

# [WP_ID]: [TITLE]

## Objective

[OBJECTIVE]

## File Paths

[FILE_PATHS]

## Work Content

[WORK_CONTENT]

## Acceptance Criteria

[ACCEPTANCE_CRITERIA]

## Dependencies

[DEPENDENCIES_DETAIL]

## Parallel Execution

[PARALLEL_EXECUTION]

## Unit Tests

[UNIT_TESTS]

## Git History

**Commits**: Automatically tracked when commit messages include task ID in any format:
- `[WP_ID] Description` (bracketed format)
- `feat: WP_ID Description` (conventional commits)
- `WP_ID: Description` (plain format)

**Modified Files**: Listed in frontmatter `files_modified` field

<!--
This section is auto-populated by move-task.sh when git commits are detected.
Format: - [TIMESTAMP]: [GIT] [commit_hash] - [commit_message]
-->

## Activity Log

**Format**:
- `[TIMESTAMP]: [ACTION]` - Lane transitions, status changes
- `[TIMESTAMP]: [GIT] [hash] - [message]` - Git commits
- `[TIMESTAMP]: [NOTE] [description]` - Manual notes
- `[TIMESTAMP]: [REVIEW] [decision] by [reviewer]` - Review outcomes

**Log**:
- [DATE]: Task created
