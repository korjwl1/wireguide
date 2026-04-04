---
description: Execute implementation using STDD (Spec & Test Driven Development) methodology
---

## User Input

```text
$ARGUMENTS
```

## Overview

STDD executes each implementation unit (phase or work package) through a 5-stage cycle
with decoupled Coder/Tester roles and Error-as-Prompt feedback loops.

**Core Principles:**

- **Zero-Ambiguity**: All specs use O/X (pass/fail) criteria, no subjective language
- **Test-First**: Tests written before implementation
- **Decoupled Roles**: Coder and Tester operate independently to prevent hallucination cascades
- **Error as Prompt**: Test failure logs become the next instruction

## Step 1: Setup

### 1.1 Load Context

Run prerequisites script to get FEATURE_DIR:

```bash
.spec-mix/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks
```

Parse `FEATURE_DIR` from JSON output.

Read (in order):

1. `$FEATURE_DIR/plan.md` or `$FEATURE_DIR/tasks.md` (required)
2. `specs/constitution.md` (if exists)

### 1.2 Create STDD Directory

```bash
mkdir -p $FEATURE_DIR/stdd
```

### 1.3 Agent Configuration

```text
[STDD] Agent configuration:

| Option | Description                                            |
|--------|--------------------------------------------------------|
| multi  | 4 agents: spec-analyst, coder, tester, loop-driver     |
| single | Single agent with role separation (default)            |

Select [single]:
```

- **multi**: Create 4 teammate agents with decoupled roles
- **single**: One agent alternating between roles (still maintains role separation)

### 1.4 Loop Mode

```text
[STDD] Loop mode:

| Mode   | Description                            |
|--------|----------------------------------------|
| auto   | Auto-retry until pass (max 5 loops)    |
| semi   | Confirm between loops (recommended)    |
| manual | Approve each step                      |

Select [semi]:
```

## Step 2: Identify Work Units

Determine implementation units from plan:

- **Normal mode**: Phases from `plan.md`
- **Pro mode**: Work Packages from `tasks/planned/`

Display progress:

```text
STDD Implementation:
├─ Unit 1: {name} - ○ Pending
├─ Unit 2: {name} - ○ Pending
└─ Unit 3: {name} - ○ Pending
```

## Step 3: Per-Unit STDD Cycle

For each unit, execute the 5-stage STDD cycle:

### Stage 1: Define Spec

Extract deliverables and acceptance criteria from `plan.md` or work package.
Transform into a Zero-Ambiguity technical spec:

- **Purpose**: What this unit delivers
- **Input**: Existing code, files, APIs to work with
- **Output Schema**: Expected files, types, API shapes
- **Constraints**: Technology, patterns, conventions
- **Prohibitions**: What must NOT be done
- **Error Cases**: Edge cases and expected behavior

**Rules:**

- Every criterion must be verifiable as O/X (pass/fail)
- No subjective language ("good", "clean", "appropriate")
- Mark unknowns explicitly

Save to `$FEATURE_DIR/stdd/unit-{N}-spec.md`.

Present to user and ask for approval before proceeding.

### Stage 2: Define Tests (Test-First)

Based on the confirmed spec, write test criteria **before** implementation:

**Mechanical Tests:**

- Syntax check (parseable?)
- Lint/Format check (coding rules?)
- Type check (type errors?)

**Execution Tests:**

- Unit tests (individual function/module behavior)
- Integration tests (component interaction)
- E2E tests (full flow, if needed)

**Schema Tests:**

- API response format matches spec?
- Data types correct?
- Error response format matches spec?

Assign each test an ID: T1, T2, T3...

Save to `$FEATURE_DIR/stdd/unit-{N}-tests.md`.

Present to user for confirmation.

### Stage 3: Execute

Implement the unit deliverables following the spec and targeting all tests.

- In **multi** mode: Send [SPEC] + [TEST-CRITERIA] to coder agent
- In **single** mode: Switch to Coder mindset — implement based on spec only, ignore test implementation details

Commit with message:

- Normal mode: `[Phase {N}] {name}`
- Pro mode: `[WP##] {name}`

### Stage 4: Test & Refactor Loop

Run all tests from Stage 2. Report results:

```text
[STDD Test Report - Unit {N}, Loop #{L}]

PASSED:
- T1: {description} ✅
- T3: {description} ✅

FAILED:
- T2: {description} ❌
  Expected: {expected value}
  Actual: {actual value}
  Action: {specific fix instruction}

SUMMARY: {passed}/{total} passed.
```

**Loop behavior:**

- **All pass** → Proceed to Stage 5
- **Failures exist** → Feed error log back to coder → fix → retest
- **Same error 2x consecutive** → Escalate to user
- **Max loops reached** → Stop and report current state

**Regression detection:**

If the same test repeatedly fails but code follows spec, suggest regression:

```text
[STDD Regression - Loop #{L}]

Test/spec mismatch suspected.

Evidence: {specific evidence}

Options:
(A) Regress to Stage 2 - Fix tests to match spec
(B) Regress to Stage 1 - Revise spec itself
(C) Ignore and continue loop
```

Save each loop to `$FEATURE_DIR/stdd/unit-{N}-loop-{L}.md`.

### Stage 5: Unit Approval

Present results:

```text
[STDD Unit {N} Complete: {name}]

Tests: {passed}/{total} passed
Loops: {L}
Files changed: {list}

Approve this unit? (Y/N)
```

- **Y**: Mark unit done, proceed to next
- **N**: User feedback → return to appropriate stage

Generate walkthrough at `$FEATURE_DIR/walkthrough-phase-{N}.md` (Normal)
or `$FEATURE_DIR/walkthrough.md` (Pro).

## Step 4: All Units Complete

```text
✓ All units implemented via STDD.

Summary:
  Unit 1: {name} — {tests} tests, {loops} loops ✓
  Unit 2: {name} — {tests} tests, {loops} loops ✓
  ...

Total: {total_tests} tests passed, {total_loops} loops

Next: /spec-mix.merge
```

## Multi-Agent Setup (when `multi` selected)

Create team `stdd-development` with 4 agents:

**stdd-spec-analyst:**

- Transforms requirements into Zero-Ambiguity specs
- Asks clarifying questions (max 3)
- Produces spec.md + test scenario drafts
- References: `docs/stdd/learnings/spec-analyst.md`

**stdd-coder:**

- Implements code strictly per spec
- Checks tester's test code first
- Does NOT add features not in spec
- Minimal-scope fixes on error logs
- References: `docs/stdd/learnings/coder.md`

**stdd-tester:**

- Writes test code before implementation (Test-First)
- Judges output by spec only, ignoring coder's intent
- Reports in standard Error Log format
- References: `docs/stdd/learnings/tester.md`

**stdd-loop-driver:**

- Routes error logs from tester to coder
- Tracks loop count and safety limits
- Detects test/spec mismatches → proposes regression
- Escalates on repeated failures
- References: `docs/stdd/learnings/loop-driver.md`
