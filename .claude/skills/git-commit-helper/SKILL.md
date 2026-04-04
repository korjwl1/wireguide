---
name: git-commit-helper
description: Generates meaningful git commit messages for Spec-Driven Development workflows. Use when creating commits, suggesting commit messages, or helping with task-based version control. Automatically links commits to work packages.
allowed-tools: [Bash, Read, Grep, Glob]
---

# Git Commit Helper Skill

## Purpose

Automatically generates well-structured commit messages that follow Spec-Kit conventions and link commits to Work Packages (WP). This ensures consistent version control practices and enables automatic task history tracking in the dashboard.

## When to Activate

This skill activates when users ask questions like:

- "suggest a commit message" / "커밋 메시지 추천해줘"
- "what should I commit" / "뭐라고 커밋해야 해?"
- "help me commit this" / "커밋 도와줘"
- "generate commit message" / "커밋 메시지 생성해줘"
- "commit this task" / "이 작업 커밋해줘"

## Commit Message Generation Process

### 1. Analyze Git Status

Check current repository state:

```bash
# Get current branch
BRANCH=$(git branch --show-current)

# Check staged changes
git diff --cached --name-status

# Check unstaged changes
git diff --name-status

# Get list of modified files
git status --short

```text
**If no changes staged:**

- Inform user: "No changes staged for commit. Stage files with `git add` first."
- Optionally show unstaged changes and ask if they should be staged

### 2. Identify Current Work Package

Determine which task/WP the changes relate to:

### Method 1: From Branch Name

```bash
# Extract feature from branch (e.g., 001-user-auth)
FEATURE=$(echo $BRANCH | grep -oE '[0-9]{3}-[a-z-]+')

```text
### Method 2: From Recent Activity

```bash
# Find most recent WP file modified in tasks/doing/
find specs/*/tasks/doing/ -name "WP*.md" -type f -printf '%T+ %p\n' | sort -r | head -1

```text
### Method 3: Ask User
If unclear, ask: "Which Work Package (WP) are you working on? (e.g., WP01, WP02)"

### 3. Read Work Package Context

Once WP is identified, read the WP file to understand context:

```bash
# Example: Read WP01.md from doing lane
cat specs/{feature}/tasks/doing/WP01.md

```text
**Extract from WP file:**

- Task ID (from frontmatter `id:` or filename)
- Task title (from frontmatter `title:` or H1 heading)
- Task phase (from frontmatter `phase:`)
- Acceptance criteria (to understand what changes accomplish)

### 4. Analyze Changed Files

Understand what was modified:

```bash
# Get file change summary
git diff --cached --stat

# Get detailed changes
git diff --cached

```text
**Categorize Changes:**

- New files added (A)
- Files modified (M)
- Files deleted (D)
- Renamed files (R)

**Group by Type:**

- Source code (*.py, *.js, *.ts, etc.)
- Tests (test_*.py, *.test.js, etc.)
- Documentation (*.md, *.txt)
- Configuration (*.json, *.yaml, *.toml)
- Assets (*.css, *.png, etc.)

### 5. Generate Commit Message

Follow Spec-Kit commit message convention:

**Format:**

```text
[TASK_ID] Brief description (imperative mood, <50 chars)

- Detailed change 1
- Detailed change 2
- Detailed change 3

Files modified:

- path/to/file1.py
- path/to/file2.js

```text
**Best Practices:**

- **Subject Line:**
  - Start with `[WP01]` or task ID in brackets
  - Use imperative mood: "Add feature" not "Added feature"
  - Keep under 50 characters
  - Capitalize first word
  - No period at end

- **Body:**
  - Separate from subject with blank line
  - Use bullet points for multiple changes
  - Explain WHAT and WHY, not HOW
  - Reference related WPs if applicable
  - Keep lines under 72 characters

- **Task ID Pattern:**
  - Essential for automatic tracking: `[WP01]`, `[WP01.1]`, `[T005]`
  - The dashboard uses this to link commits to tasks
  - move-task.sh script auto-detects these commits

**Examples:**

### Example 1: Feature Implementation

```text
[WP01.1] Add HttpMethod enum to models

- Created src/models/enums.py with HttpMethod class
- Added GET, POST, PUT, DELETE, PATCH methods
- Added type hints and docstrings for all methods

Related to Phase 1.1: Core API models

```text
### Example 2: Bug Fix

```text
[WP03] Fix user authentication timeout issue

- Increased session timeout from 15min to 30min
- Added session refresh on user activity
- Updated auth middleware to handle expired sessions gracefully

Fixes acceptance criterion #2: "Sessions persist during active use"

```text
### Example 3: Refactoring

```text
[WP05.2] Refactor database connection pooling

- Extracted connection logic to db/pool.py
- Implemented connection pool with max 20 connections
- Added automatic retry on connection failure
- Migrated all models to use new pool

No functional changes, improves performance and maintainability

```text
### Example 4: Tests

```text
[WP02] Add unit tests for password validation

- Created tests/test_auth_validator.py
- Added 12 test cases covering edge cases
- Tests for min length, special chars, common passwords
- All tests passing (100% coverage on validator.py)

```text
### Example 5: Documentation

```text
[WP04] Update API documentation for v2 endpoints

- Added OpenAPI specs for /api/v2/users
- Updated README with authentication flow diagram
- Added code examples for Python and JavaScript clients

```text
### 6. Handle Special Cases

**Multiple WPs in One Commit:**

```text
[WP01][WP02] Implement login and signup endpoints

Changes for WP01 (Login):

- Created POST /api/login endpoint
- Added JWT token generation

Changes for WP02 (Signup):

- Created POST /api/signup endpoint
- Added email validation

```text
**No Active WP (General Maintenance):**

```text
chore: Update dependencies to latest versions

- Updated Flask from 2.0.1 to 2.3.0
- Updated pytest from 7.0 to 7.4
- All tests still passing

```text
**Emergency Hotfix:**

```text
hotfix: Fix critical security vulnerability in auth

- Patched SQL injection in login endpoint
- Added input sanitization
- Deployed immediately to production

Not linked to specific WP - emergency fix

```text
### 7. Present Commit Message to User

Show the generated message and ask for confirmation:

```text
I've generated this commit message based on your changes:

---
[WP01.1] Add HttpMethod enum to models

- Created src/models/enums.py with HttpMethod class
- Added GET, POST, PUT, DELETE, PATCH methods
- Added type hints and docstrings

Related to Phase 1.1: Core API models
---

Staged files:

- src/models/enums.py (new file)
- src/models/__init__.py (modified)

Would you like to:

1. Use this message as-is
2. Edit the message
3. See a different suggestion
4. Cancel

```text
### 8. Optional: Execute Commit

If user approves and requests execution:

```bash
git commit -m "[WP01.1] Add HttpMethod enum to models

- Created src/models/enums.py with HttpMethod class
- Added GET, POST, PUT, DELETE, PATCH methods
- Added type hints and docstrings

Related to Phase 1.1: Core API models"

```text
**Important:** Only execute git commit if explicitly requested by user. Default behavior is to suggest the message.

## Integration with Spec-Kit Workflow

This skill integrates with the SDD workflow:

**Automatic Task Tracking:**

- Commits with `[TASK_ID]` pattern are auto-detected by `move-task.sh`
- Git history appears in dashboard's "Git History" tab
- File changes are automatically logged in Work Package

**Workflow Stages:**

1. User implements task (WP01)
2. User asks: "suggest commit message"
3. Skill analyzes changes and generates message with `[WP01]`
4. User commits with suggested message
5. When WP01 moves to for_review, git history is automatically appended
6. Dashboard displays all commits for WP01

## Output Language

- Detect user's language from their question
- If asked in Korean, provide explanation in Korean
- Commit message itself stays in English (universal convention)
- File paths and technical terms remain in English

## Error Handling

**No staged changes:**

```text
No changes staged for commit.

You have 3 modified files:

- src/models/enums.py
- src/api/routes.py
- tests/test_models.py

Stage them with: git add <file>
Or stage all: git add -A

```text
**Cannot identify WP:**

```text
I couldn't automatically determine which Work Package you're working on.

Current branch: main (no feature branch detected)
Recent WP files in doing: None

Please specify the WP ID (e.g., WP01) or describe what this commit is for.

```text
**Too many unrelated changes:**

```text
⚠️  Warning: You have changes across 15 files spanning multiple features.

Consider splitting into multiple commits:

- Commit 1: API changes (5 files)
- Commit 2: Database migrations (3 files)
- Commit 3: Tests (7 files)

This makes the history clearer and easier to review.

```text
## Smart Features

**1. Conventional Commit Detection:**
Recognize conventional commit types and adapt:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance

**2. File Pattern Recognition:**
Automatically infer commit type from files:

- Only `*.md` files → `docs:`
- Only `test_*.py` files → `test:`
- Mix of source + tests → `feat:` or `fix:`

**3. Emoji Suggestions (Optional):**
If user prefers emojis in commits:

- ✨ feat: New feature
- 🐛 fix: Bug fix
- 📝 docs: Documentation
- ♻️  refactor: Refactoring
- ✅ test: Tests

## Example Interactions

**User:** "커밋 메시지 추천해줘"

**Claude (using this skill):**

1. Checks git status: 2 files staged
2. Identifies branch: `002-password-reset`
3. Finds WP: `specs/002-password-reset/tasks/doing/WP01.md`
4. Reads WP title: "Implement password reset email"
5. Analyzes changes: Added email template + email service
6. Generates:

```text
[WP01] Implement password reset email flow

- Added password_reset_email.html template
- Created EmailService class in services/email.py
- Integrated SendGrid API for email delivery
- Added environment variables for SMTP config

Fulfills acceptance criterion: "User receives reset link via email"

```text
**User:** "what should I commit for this bugfix?"

**Claude:**

1. Checks changes: 1 file modified (auth.py)
2. Asks: "Which WP is this bugfix for?"
3. User: "WP03"
4. Reads WP03: "Fix session timeout bug"
5. Generates commit message with `[WP03]` and bugfix description

## Notes

- This skill generates suggestions but does NOT auto-commit (unless explicitly requested)
- Commit messages follow spec-kit conventions for dashboard integration
- The `[TASK_ID]` pattern is critical for automatic task tracking
- Well-crafted commits improve team collaboration and project history
