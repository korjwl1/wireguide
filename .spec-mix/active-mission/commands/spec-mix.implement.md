---
description: Execute implementation based on current mode (Normal or Pro)
---

## Mode Detection

Check mode from `.spec-mix/config.json`:

```bash
cat .spec-mix/config.json 2>/dev/null | grep '"mode"' || echo '"mode": "normal"'
```

## Mode-Specific Workflow

### If `mode: "normal"` (Default)

**Phase-based implementation with built-in review:**

1. Execute one phase at a time
2. Generate walkthrough after each phase
3. Present review → Accept/Reject
4. Proceed after acceptance
5. Final: Run `/spec-mix.merge`

**See**: `/spec-mix.implement-normal` for detailed workflow

---

### If `mode: "pro"`

**Work Package lane workflow:**

```
planned → doing → for_review → done
```

1. Select task from `planned`, move to `doing`
2. Implement with commits tagged `[WP##]`
3. Move completed task to `for_review`
4. Generate walkthrough
5. Next: `/spec-mix.review` → `/spec-mix.accept` → `/spec-mix.merge`

**See**: `/spec-mix.implement-pro` for detailed workflow

---

## Quick Reference

| Mode | Task Unit | Review | Commands After |
|------|-----------|--------|----------------|
| Normal | Phase | Built-in Accept/Reject | `/spec-mix.merge` |
| Pro | Work Package | `/spec-mix.review` | `/spec-mix.accept`, `/spec-mix.merge` |
