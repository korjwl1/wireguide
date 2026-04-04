---
description: "Vertical Slice task list template - each WP is independently deployable"
---

# Tasks: [FEATURE NAME]

**Input**: Design documents from `/specs/[###-feature-name]/`
**Prerequisites**: plan.md (required), spec.md (required for user stories)

## Vertical Slice Approach

Each Work Package (WP) is a **complete vertical slice**:
- Contains all layers needed (UI → API → DB)
- Independently testable and deployable
- Delivers user-visible value
- Can be reviewed and merged separately

```
┌─────────────────────────────────────────────────────────────┐
│                    Feature: User Auth                        │
├──────────────┬──────────────┬──────────────┬───────────────┤
│    WP01      │    WP02      │    WP03      │    WP04       │
│   Login      │  Register    │  Password    │   Profile     │
│              │              │   Reset      │               │
├──────────────┼──────────────┼──────────────┼───────────────┤
│  UI Layer    │  UI Layer    │  UI Layer    │  UI Layer     │
│  API Layer   │  API Layer   │  API Layer   │  API Layer    │
│  DB Layer    │  DB Layer    │  DB Layer    │  DB Layer     │
│  Tests       │  Tests       │  Tests       │  Tests        │
├──────────────┼──────────────┼──────────────┼───────────────┤
│ ✓ Deployable │ ✓ Deployable │ ✓ Deployable │ ✓ Deployable  │
└──────────────┴──────────────┴──────────────┴───────────────┘
```

## Task Tracking

- **tasks.md** (this file): Overview with checkbox format
- **Work Package files**: `tasks/{planned,doing,for_review,done}/WPxx.md`
  - Detailed implementation notes
  - Dashboard kanban visualization
  - `/spec-mix.review` integration

---

## Phase 0: Foundation Slice

> **Purpose**: Minimal infrastructure that ALL other slices depend on
> **Goal**: Project skeleton that can run (even if it does nothing useful)

### WP00: Project Bootstrap (Foundation)

**Vertical Scope**: Project structure + build + run capability

| Layer | Deliverable |
|-------|-------------|
| Config | Project init, dependencies, environment setup |
| Infrastructure | Build scripts, CI config (if needed) |
| Verification | `npm start` / `python main.py` / equivalent runs without error |

**Tasks**:
- [ ] T001 Create project structure per implementation plan
- [ ] T002 Initialize with framework and dependencies
- [ ] T003 Setup basic configuration (env, linting, formatting)
- [ ] T004 Verify project runs (empty shell)

**Checkpoint**: Project skeleton runs → Ready for vertical slices

---

## Phase 1: Core Slices (MVP)

> **Purpose**: Minimum slices needed for MVP
> **Each WP is independently deployable**

### WP01: [Slice Name] - [User Story Title]

**Vertical Scope**: [What this slice delivers end-to-end]

| Layer | Deliverable |
|-------|-------------|
| UI | [Screen/Component] |
| API | [Endpoint(s)] |
| Data | [Model/Schema changes] |
| Test | [Test coverage] |

**Acceptance Criteria**:
- [ ] [User can do X]
- [ ] [System responds with Y]

**Tasks**:
- [ ] T005 [DB] Create schema/migration for [entity]
- [ ] T006 [API] Implement [endpoint] - `POST /api/[resource]`
- [ ] T007 [UI] Create [component/screen]
- [ ] T008 [Test] Add integration test for [flow]
- [ ] T009 [Verify] End-to-end manual test

**Deploy Check**: Can this be deployed independently? ✓ Yes

---

### WP02: [Slice Name] - [User Story Title]

**Vertical Scope**: [What this slice delivers end-to-end]

| Layer | Deliverable |
|-------|-------------|
| UI | [Screen/Component] |
| API | [Endpoint(s)] |
| Data | [Model/Schema changes] |
| Test | [Test coverage] |

**Acceptance Criteria**:
- [ ] [User can do X]
- [ ] [System responds with Y]

**Tasks**:
- [ ] T010 [DB] Create schema/migration for [entity]
- [ ] T011 [API] Implement [endpoint]
- [ ] T012 [UI] Create [component/screen]
- [ ] T013 [Test] Add integration test
- [ ] T014 [Verify] End-to-end manual test

**Deploy Check**: Can this be deployed independently? ✓ Yes

---

### WP03: [Slice Name] - [User Story Title]

**Vertical Scope**: [What this slice delivers end-to-end]

| Layer | Deliverable |
|-------|-------------|
| UI | [Screen/Component] |
| API | [Endpoint(s)] |
| Data | [Model/Schema changes] |
| Test | [Test coverage] |

**Tasks**:
- [ ] T015-T019 [Similar structure]

**Deploy Check**: ✓ Yes

---

## Phase 2: Enhancement Slices

> **Purpose**: Additional features after MVP
> **Each still independently deployable**

### WP04: [Enhancement Slice]

[Same vertical structure...]

---

## Phase 3: Polish Slice

### WP99: Cross-cutting Improvements

**Vertical Scope**: Non-functional improvements across all slices

| Area | Deliverable |
|------|-------------|
| Performance | [Optimizations] |
| Security | [Hardening] |
| Docs | [Documentation updates] |
| UX | [Polish items] |

**Tasks**:
- [ ] TXXX Performance optimization
- [ ] TXXX Security review and fixes
- [ ] TXXX Documentation updates
- [ ] TXXX UX polish

---

## Dependency Map

```
WP00 (Foundation)
 │
 ├──→ WP01 (Login) ──────→ Can deploy after WP00
 │
 ├──→ WP02 (Register) ───→ Can deploy after WP00 (parallel with WP01)
 │
 ├──→ WP03 (Password) ───→ Can deploy after WP00 (parallel)
 │
 └──→ WP04 (Profile) ────→ May depend on WP01 (login required)
      │
      └──→ WP99 (Polish) → After all core slices
```

## Execution Strategy

### Sequential (Solo Developer)
```
WP00 → WP01 → Deploy → WP02 → Deploy → WP03 → Deploy → WP04 → WP99
```

### Parallel (Team)
```
WP00 (together)
  ↓
WP01 (Dev A) ──→ Deploy
WP02 (Dev B) ──→ Deploy
WP03 (Dev C) ──→ Deploy
  ↓
WP04 (any) ───→ Deploy
  ↓
WP99 (together)
```

### MVP First
```
WP00 → WP01 → WP02 → STOP & VALIDATE → Deploy MVP
       (then continue with WP03, WP04...)
```

---

## Work Package File Format

Each WP can have a detailed file in `tasks/planned/WPxx.md`:

```markdown
---
id: WP01
title: User Login
status: planned
priority: P1
vertical_scope: login-flow
layers: [ui, api, db, test]
deployable: true
dependencies: [WP00]
---

# WP01: User Login

## Vertical Scope
Complete login flow from UI to database

## Layers
- **UI**: Login form component
- **API**: POST /api/auth/login
- **DB**: users table, sessions table
- **Test**: Login integration test

## Tasks
- [ ] Create users migration
- [ ] Implement login endpoint
- [ ] Create login form
- [ ] Add integration test

## Acceptance
- [ ] User can log in with email/password
- [ ] Invalid credentials show error
- [ ] Session persists across refresh
```

---

## Notes

- **Vertical Slice**: Each WP contains all layers needed for a feature
- **Independent Deploy**: Each completed WP can be deployed without others
- **Layer Labels**: [DB], [API], [UI], [Test] show which layer
- **Dependencies**: Only WP00 blocks others; rest are parallel-capable
- **Walkthrough**: Each WP completion generates walkthrough for working memory
