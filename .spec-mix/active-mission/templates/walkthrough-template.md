---
type: walkthrough
phase: [PHASE_NUMBER]
feature: [FEATURE_NAME]
created_at: [DATE]
commits: [COMMIT_COUNT]
status: [pending|accepted|rejected]
---

# Walkthrough: Phase [PHASE_NUMBER] - [PHASE_NAME]

**Generated**: [DATE/TIME]
**Feature**: [FEATURE_NAME]
**Commits in this phase**: [COMMIT_COUNT]

## Summary

[2-3 sentences describing what was accomplished in this phase]

## Files Changed

| Status | File | Description |
|--------|------|-------------|
| M | path/to/modified/file.ts | [Brief description of change] |
| A | path/to/new/file.ts | [Brief description of new file] |
| D | path/to/deleted/file.ts | [Why deleted] |

## Detailed Changes

### [file path 1]

**Purpose**: [Why this file was changed]

```diff
[Actual diff output - use: git diff HEAD~N -- path/to/file]
```

**Notes**: [Any important context about this change]

---

### [file path 2]

**Purpose**: [Why this file was changed]

```diff
[Actual diff output]
```

---

[Repeat for each significant file changed]

## Key Decisions

### Decision 1: [Title]
- **What**: [What was decided]
- **Why**: [Reasoning behind this decision]
- **Alternatives Considered**:
  - Option A: [Description] - Rejected because [reason]
  - Option B: [Description] - Rejected because [reason]

### Decision 2: [Title]
- **What**: [What was decided]
- **Why**: [Reasoning]

## Working Memory Notes

> **Context for Future Reference**
>
> This section serves as working memory - notes that will be helpful when revisiting this code later.

### Implementation Context
- [Important context about why things were done this way]
- [Business rules or requirements that influenced the implementation]

### Gotchas & Watch-outs
- [Things that might be confusing or easy to break]
- [Edge cases that were handled]
- [Known limitations]

### Related Files & Dependencies
- [Other files that depend on or are related to these changes]
- [External services or APIs involved]
- [Configuration that might need updating]

### Future Considerations
- [Things that might need to change in the future]
- [Technical debt introduced]
- [Potential improvements]

## Commits

| Hash | Message |
|------|---------|
| abc1234 | [Commit message 1] |
| def5678 | [Commit message 2] |

## Review Status

- [ ] Code reviewed
- [ ] Tests passing
- [ ] Documentation updated
- [ ] Ready for next phase

---

**Phase Status**: [PENDING | ACCEPTED | REJECTED]

*If rejected, feedback*:
> [Reviewer feedback here]
