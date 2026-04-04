---
task_id: [TASK_ID]
task_title: [TASK_TITLE]
reviewer: [REVIEWER_NAME]
review_date: [REVIEW_DATE]
decision: [APPROVED|CHANGES_REQUESTED]
---

# Review Feedback: [TASK_ID] - [TASK_TITLE]

**Reviewer**: [REVIEWER_NAME]
**Date**: [REVIEW_DATE]
**Decision**: **[APPROVED|CHANGES_REQUESTED]**

---

## Acceptance Criteria

Review against the acceptance criteria defined in the Work Package:

- [ ] Criterion 1: [DESCRIPTION]
- [ ] Criterion 2: [DESCRIPTION]
- [ ] Criterion 3: [DESCRIPTION]

**Overall**: [X/Y] criteria met

---

## Code Quality Assessment

### ✅ Strengths

- [Point 1: What was done well]
- [Point 2: Good practices observed]
- [Point 3: Quality highlights]

### Code Review Checklist

- [ ] **Functionality**: Works as specified
- [ ] **Code Quality**: Readable, maintainable, follows conventions
- [ ] **Constitution Compliance**: Adheres to project principles (if applicable)
- [ ] **Testing**: Adequate test coverage
- [ ] **Documentation**: Code comments and README updates
- [ ] **No Regressions**: Existing features still work
- [ ] **Security**: No obvious vulnerabilities
- [ ] **Performance**: No major performance issues

---

## Issues Found

### ❌ Issue 1: [ISSUE_TITLE]

**Severity**: [Critical|Major|Minor]
**Location**: `[file:line]` or `[section]`
**Description**: [Detailed description of the problem]
**Action Required**: [Specific steps to fix]

### ❌ Issue 2: [ISSUE_TITLE]

**Severity**: [Critical|Major|Minor]
**Location**: `[file:line]` or `[section]`
**Description**: [Detailed description of the problem]
**Action Required**: [Specific steps to fix]

---

## Next Steps

**If APPROVED**:
- Move task to `done` lane
- Update `tasks.md` with completion
- Proceed to next task or feature acceptance

**If CHANGES REQUESTED**:
- Move task back to `doing` lane
- Address all issues listed above
- Re-submit for review when ready

**Specific Actions**:
1. [Action item 1]
2. [Action item 2]
3. [Action item 3]

---

## Activity Log Entry

Add the following to the Work Package Activity Log:

### For APPROVED:

```markdown
- [REVIEW_DATE]: [REVIEW] APPROVED by [REVIEWER_NAME]
  - ✅ All acceptance criteria met ([X/Y])
  - ✅ Code quality meets standards
  - ✅ Tests passing
  - ✅ Documentation updated
  - ✅ No regressions found
```

### For CHANGES REQUESTED:

```markdown
- [REVIEW_DATE]: [REVIEW] CHANGES REQUESTED by [REVIEWER_NAME]
  - ❌ Issue 1: [Brief description]
    - Location: [file:line]
    - Action: [What needs fixing]
  - ❌ Issue 2: [Brief description]
    - Location: [file:line]
    - Action: [What needs fixing]
  - ✅ [Positive highlight]
  - Next steps: [Summary of required changes]
```

---

## Notes

[Any additional observations, suggestions, or context for the implementer]

---

**Template Version**: 1.0
**Last Updated**: 2025-11-18
