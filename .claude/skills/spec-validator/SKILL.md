---
name: spec-validator
description: Validates Spec-Driven Development artifacts for completeness, consistency, and quality. Use when checking specs, validating features, reviewing SDD artifacts, or ensuring spec quality before implementation.
allowed-tools: [Read, Glob, Grep, Bash]
---

# Spec Validator Skill

## Purpose

Automatically validates Spec-Driven Development (SDD) artifacts to ensure they are complete, consistent, and follow project conventions before implementation begins. This skill proactively identifies issues in specifications, plans, and task breakdowns.

## When to Activate

This skill activates when users ask questions like:

- "validate my spec" / "스펙 검증해줘"
- "check if my spec is complete" / "스펙 완전한지 확인해줘"
- "is my feature ready to implement" / "구현 준비됐어?"
- "review my SDD artifacts" / "SDD 아티팩트 리뷰해줘"
- "spec quality check" / "스펙 품질 체크"

## Validation Process

### 1. Identify Feature Directory

First, determine which feature to validate:

```bash
# Auto-detect from current git branch if possible
BRANCH=$(git branch --show-current 2>/dev/null)

# Or scan specs/ directory for features
ls -d specs/*/

```text
If multiple features or unclear context, ask the user which feature to validate.

### 2. Check File Existence

Verify that all required SDD artifacts exist:

**Required Files:**

- `specs/{feature}/spec.md` - Feature specification
- `specs/{feature}/plan.md` - Implementation plan
- `specs/{feature}/tasks.md` OR `specs/{feature}/tasks/` - Task breakdown

**Optional But Recommended:**

- `specs/constitution.md` - Project constitution
- `specs/{feature}/acceptance.md` - Acceptance criteria (for completed features)

**Report Missing Files:**

```text
❌ Missing: specs/001-user-auth/plan.md
✅ Found: specs/001-user-auth/spec.md
✅ Found: specs/001-user-auth/tasks.md

```text
### 3. Validate spec.md

Check that spec.md contains all essential sections:

**Required Sections:**

- Feature name/title
- Feature description or overview
- User stories or requirements
- Success criteria or acceptance criteria
- Out of scope (optional but recommended)

**Validation Checks:**

- [ ] Has a clear feature name (H1 heading)
- [ ] Describes WHAT the feature does (not HOW)
- [ ] Includes at least one user story
- [ ] Defines measurable success criteria
- [ ] User stories follow "As a... I want... So that..." format (if applicable)

**Quality Checks:**

- Is the spec focused on user value?
- Are success criteria specific and measurable?
- Is scope clearly defined?

### 4. Validate plan.md

Check that plan.md contains technical planning:

**Required Sections:**

- References to spec.md
- Technical approach or architecture
- Implementation phases or breakdown
- Dependencies (internal and external)
- Files to be modified/created

**Validation Checks:**

- [ ] References the feature spec
- [ ] Describes HOW to implement (not WHAT)
- [ ] Lists all dependencies
- [ ] Breaks down into logical phases
- [ ] Identifies specific files/modules to change

**Quality Checks:**

- Does the plan align with the spec's goals?
- Are technical decisions justified?
- Are risks or challenges identified?

### 5. Validate tasks.md or tasks/

Check task breakdown completeness:

**For tasks.md:**

- [ ] Organized by user story or phase
- [ ] Each task has a unique ID (WP01, WP02, T001, etc.)
- [ ] Tasks list specific files to modify
- [ ] Dependencies are marked
- [ ] Estimated effort included (optional)

**For tasks/ directory (kanban structure):**

- [ ] Has lane directories: `planned/`, `doing/`, `for_review/`, `done/`
- [ ] Work Package files use proper frontmatter
- [ ] Each WP has title, phase, dependencies
- [ ] Activity log present

**Quality Checks:**

- Are tasks granular enough (1-4 hours each)?
- Do tasks cover all aspects of the spec?
- Are dependencies realistic?

### 6. Constitution Compliance

If `specs/constitution.md` exists, check compliance:

**Validation:**

- Read constitution principles
- Check if spec/plan align with stated values
- Verify technical choices match governance rules
- Flag any potential conflicts

### 7. Cross-Reference Validation

Check consistency across artifacts:

**Spec ↔ Plan:**

- All user stories from spec addressed in plan
- Plan's technical approach supports spec's goals
- Success criteria achievable with planned implementation

**Plan ↔ Tasks:**

- All planned phases have corresponding tasks
- All dependencies from plan reflected in tasks
- File paths in tasks match plan's architecture

**Tasks ↔ Spec:**

- Tasks collectively fulfill all user stories
- No tasks out of scope from spec

### 8. Generate Validation Report

Provide a comprehensive validation report:

```markdown
# Validation Report: {feature-name}

## Summary
✅ Passed: 12/15 checks
⚠️  Warnings: 2
❌ Failed: 1

## File Existence
✅ spec.md found
✅ plan.md found
✅ tasks.md found
❌ constitution.md not found (project-level)

## Spec Quality
✅ Clear feature name: "User Authentication"
✅ 3 user stories defined
⚠️  Success criteria could be more specific
✅ Out of scope defined

## Plan Quality
✅ References spec.md
✅ Technical approach clear
✅ 4 implementation phases
⚠️  Missing dependency: Redis (mentioned in spec but not in plan dependencies)
✅ 8 files identified for modification

## Task Breakdown
✅ 12 work packages created
✅ All tasks have IDs and titles
✅ Dependencies marked
✅ Covers all user stories

## Cross-Reference Checks
✅ All user stories have tasks
⚠️  Plan mentions "password hashing" but no task for bcrypt integration

## Recommendations

1. Add specific metrics to success criteria (e.g., "Login time < 2s")
2. Add Redis to plan dependencies section
3. Create task for bcrypt library integration
4. Consider creating project constitution.md

## Overall Assessment
**Status: READY WITH MINOR IMPROVEMENTS**

The feature spec is well-structured and implementation-ready. Address the 2 warnings to ensure smoother implementation.

```text
## Output Language

- Detect user's language from their question
- If asked in Korean, respond in Korean
- If asked in English, respond in English
- Code blocks and technical terms remain in English

## Error Handling

If validation cannot be performed:

1. Explain what's missing or blocking validation
2. Suggest next steps (e.g., "Run `/spec-mix.specify` to create spec.md")
3. Offer to validate partial artifacts if some exist

## Example Usage

**User:** "validate my spec"

**Claude (using this skill):**

1. Detects current feature from git branch or asks user
2. Checks file existence
3. Validates each artifact's content
4. Generates comprehensive validation report
5. Provides actionable recommendations

## Integration with SDD Workflow

This skill complements slash commands:

- After `/spec-mix.specify`: Validate spec.md quality
- After `/spec-mix.plan`: Validate plan-spec alignment
- After `/spec-mix.tasks`: Validate task completeness
- Before `/spec-mix.implement`: Final readiness check

## Notes

- This skill is **read-only** - it validates but does not modify files
- Validation is contextual - different standards for different project types
- Warnings are suggestions, not blockers
- Use before starting implementation to catch issues early
