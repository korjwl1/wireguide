---
description: Create feature specification from natural language description
scripts:
  sh: scripts/bash/create-new-feature.sh --json "{ARGS}"
  ps: scripts/powershell/create-new-feature.ps1 -Json "{ARGS}"
---

## User Input

```text
$ARGUMENTS
```

## Execution Flow

### 1. Generate Branch Name

From feature description, create 2-4 word short name:
- "Add user authentication" → `user-auth`
- "Fix payment timeout" → `fix-payment-timeout`

### 2. Create Feature Branch

```bash
git fetch --all --prune

# Find highest existing number for this short-name
# Check: remote branches, local branches, specs/ directories

# Run script with next available number
{SCRIPT} --number N --short-name "short-name" "Feature description"
```

Parse BRANCH_NAME and SPEC_FILE from JSON output.

### 3. Load Context

- Read `.spec-mix/active-mission/templates/spec-template.md` for structure
- Read `specs/constitution.md` if exists (for project principles)

### 4. Write Specification

Fill template sections:
- **Feature Overview**: What and why
- **User Stories**: As a [user], I want...
- **Functional Requirements**: Testable requirements
- **Success Criteria**: Measurable outcomes (no tech details)
- **Assumptions**: Documented defaults

**Rules**:
- Focus on WHAT, not HOW
- No implementation details (languages, APIs, frameworks)
- Max 3 `[NEEDS CLARIFICATION]` markers for critical unknowns

### 5. Mode-Specific Flow

Check mode: `cat .spec-mix/config.json | grep '"mode"'`

**Normal Mode**: Auto-present clarification questions
```
## Improve Your Spec (Optional)

Q1: {Question about scope}
Q2: {Question about behavior}
Q3: {Question about constraints}

| Choice | Action |
|--------|--------|
| Answer | Reply with answers |
| SKIP | Proceed to /spec-mix.plan |
```

**Pro Mode**: Report completion, suggest `/spec-mix.clarify` or `/spec-mix.plan`

### 6. Completion

```
✓ Specification created: {SPEC_FILE}

Next: /spec-mix.plan
```

## Quick Reference

| Section | Required | Notes |
|---------|----------|-------|
| Overview | Yes | What + Why |
| User Stories | Yes | User perspective |
| Requirements | Yes | Testable |
| Success Criteria | Yes | Measurable, no tech |
| Assumptions | If any | Document defaults |
