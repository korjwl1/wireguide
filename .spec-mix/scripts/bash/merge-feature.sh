#!/usr/bin/env bash
# Merge feature branch to main with various strategies
# Usage: merge-feature.sh --feature <name> [options]

set -e

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Default values
FEATURE_NAME=""
STRATEGY="merge"
PUSH=false
CLEANUP_WORKTREE=false
KEEP_BRANCH=false
DRY_RUN=false
NO_VERIFY=false
JSON_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --feature)
            FEATURE_NAME="$2"
            shift 2
            ;;
        --strategy)
            STRATEGY="$2"
            shift 2
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --cleanup-worktree)
            CLEANUP_WORKTREE=true
            shift
            ;;
        --keep-branch)
            KEEP_BRANCH=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-verify)
            NO_VERIFY=true
            shift
            ;;
        --json)
            JSON_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 --feature <name> [options]"
            echo ""
            echo "Options:"
            echo "  --feature <name>       Feature branch name (required)"
            echo "  --strategy <type>      Merge strategy: merge|squash|ff-only (default: merge)"
            echo "  --push                 Push to remote after merge"
            echo "  --cleanup-worktree     Remove worktree after merge"
            echo "  --keep-branch          Keep feature branch after merge"
            echo "  --dry-run              Preview without executing"
            echo "  --no-verify            Skip pre-merge verification"
            echo "  --json                 Output in JSON format"
            echo ""
            echo "Examples:"
            echo "  $0 --feature 001-user-auth"
            echo "  $0 --feature 001-user-auth --strategy squash --push"
            echo "  $0 --feature 001-user-auth --cleanup-worktree --push"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$FEATURE_NAME" ]]; then
    echo "Error: --feature is required" >&2
    exit 1
fi

# Validate strategy
VALID_STRATEGIES=("merge" "squash" "ff-only")
if [[ ! " ${VALID_STRATEGIES[@]} " =~ " ${STRATEGY} " ]]; then
    echo "Error: Invalid strategy: $STRATEGY" >&2
    echo "Valid strategies: ${VALID_STRATEGIES[*]}" >&2
    exit 1
fi

# Get repository root
REPO_ROOT=$(get_repo_root)
SPECS_DIR="$REPO_ROOT/specs"
FEATURE_SPEC_DIR=$(find_feature_dir_by_prefix "$REPO_ROOT" "$FEATURE_NAME")

# Check if git is available
if ! has_git; then
    echo "Error: Git is required for merge functionality" >&2
    exit 1
fi

# Pre-merge verification
if [[ "$NO_VERIFY" != "true" ]]; then
    # Check if acceptance exists
    if [[ -f "$FEATURE_SPEC_DIR/acceptance.md" ]]; then
        if ! grep -q "APPROVED" "$FEATURE_SPEC_DIR/acceptance.md" 2>/dev/null; then
            echo "Error: Feature not approved for merge" >&2
            echo "Run /spec-mix.accept first" >&2
            exit 1
        fi
    else
        echo "Warning: No acceptance.md found. Consider running /spec-mix.accept first" >&2
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        echo "Error: Working directory has uncommitted changes" >&2
        echo "Commit or stash your changes before merging" >&2
        exit 1
    fi
fi

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
MAIN_BRANCH="main"

# Check if main branch exists, fallback to master
if ! git show-ref --verify --quiet refs/heads/main 2>/dev/null; then
    if git show-ref --verify --quiet refs/heads/master 2>/dev/null; then
        MAIN_BRANCH="master"
    fi
fi

# Dry run mode
if [[ "$DRY_RUN" == "true" ]]; then
    COMMIT_COUNT=$(git rev-list --count ${MAIN_BRANCH}..${FEATURE_NAME} 2>/dev/null || echo "0")
    FILES_CHANGED=$(git diff --name-only ${MAIN_BRANCH}..${FEATURE_NAME} 2>/dev/null | wc -l)

    if [[ "$JSON_MODE" == "true" ]]; then
        echo "{\"dry_run\": true, \"feature\": \"$FEATURE_NAME\", \"strategy\": \"$STRATEGY\", \"commits\": $COMMIT_COUNT, \"files_changed\": $FILES_CHANGED}"
    else
        echo "🔍 Merge Preview: $FEATURE_NAME"
        echo ""
        echo "Strategy: $STRATEGY"
        echo "Current branch: $CURRENT_BRANCH"
        echo "Target branch: $FEATURE_NAME"
        echo "Main branch: $MAIN_BRANCH"
        echo ""
        echo "Changes to be merged:"
        echo "  Commits: $COMMIT_COUNT"
        echo "  Files changed: $FILES_CHANGED"
        echo ""
        echo "Actions that would be performed:"
        echo "  1. Switch to $MAIN_BRANCH branch"
        echo "  2. Pull latest changes"
        echo "  3. Merge $FEATURE_NAME using $STRATEGY strategy"
        [[ "$PUSH" == "true" ]] && echo "  4. Push to remote"
        [[ "$CLEANUP_WORKTREE" == "true" ]] && echo "  5. Cleanup worktree"
        [[ "$KEEP_BRANCH" != "true" ]] && echo "  6. Delete feature branch"
        echo ""
        echo "⚠️  This is a dry run. No changes made."
        echo "To execute, run without --dry-run flag."
    fi
    exit 0
fi

# Execute merge
echo "Starting merge process for $FEATURE_NAME..." >&2

# Stash any changes (safety)
if git diff-index --quiet HEAD -- 2>/dev/null; then
    : # No changes to stash
else
    git stash save "Pre-merge stash for $FEATURE_NAME" >&2
fi

# Switch to main branch
echo "Switching to $MAIN_BRANCH branch..." >&2
git checkout "$MAIN_BRANCH" >&2

# Pull latest changes
echo "Pulling latest changes from remote..." >&2
git pull origin "$MAIN_BRANCH" 2>/dev/null || echo "Warning: Could not pull from remote" >&2

# Perform merge based on strategy
echo "Merging $FEATURE_NAME using $STRATEGY strategy..." >&2

case "$STRATEGY" in
    merge)
        git merge "$FEATURE_NAME" --no-ff -m "Merge feature $FEATURE_NAME" >&2
        ;;
    squash)
        git merge "$FEATURE_NAME" --squash >&2
        # Extract feature description from spec.md
        FEATURE_DESC="$FEATURE_NAME"
        if [[ -f "$FEATURE_SPEC_DIR/spec.md" ]]; then
            FEATURE_DESC=$(grep -m 1 "^# " "$FEATURE_SPEC_DIR/spec.md" | sed 's/^# //' || echo "$FEATURE_NAME")
        fi
        git commit -m "feat: $FEATURE_DESC" >&2
        ;;
    ff-only)
        git merge "$FEATURE_NAME" --ff-only >&2
        ;;
esac

MERGE_SUCCESS=$?

if [[ $MERGE_SUCCESS -ne 0 ]]; then
    echo "Error: Merge failed" >&2
    echo "Resolve conflicts and run: git commit" >&2
    exit 1
fi

# Push to remote
if [[ "$PUSH" == "true" ]]; then
    echo "Pushing to remote..." >&2
    git push origin "$MAIN_BRANCH" >&2
fi

# Cleanup worktree
if [[ "$CLEANUP_WORKTREE" == "true" ]]; then
    WORKTREE_PATH="$REPO_ROOT/.worktrees/$FEATURE_NAME"
    if [[ -d "$WORKTREE_PATH" ]]; then
        echo "Cleaning up worktree..." >&2
        git worktree remove "$WORKTREE_PATH" --force 2>/dev/null || true
    fi
fi

# Delete feature branch
if [[ "$KEEP_BRANCH" != "true" ]]; then
    echo "Deleting feature branch..." >&2
    git branch -d "$FEATURE_NAME" 2>/dev/null || git branch -D "$FEATURE_NAME" 2>/dev/null || true

    # Also delete remote branch if it exists
    if [[ "$PUSH" == "true" ]]; then
        git push origin --delete "$FEATURE_NAME" 2>/dev/null || true
    fi
fi

# Get merge stats
COMMIT_COUNT=$(git log --oneline ${MAIN_BRANCH}~1..${MAIN_BRANCH} 2>/dev/null | wc -l)
FILES_CHANGED=$(git diff --name-only ${MAIN_BRANCH}~1..${MAIN_BRANCH} 2>/dev/null | wc -l)

# Output result
if [[ "$JSON_MODE" == "true" ]]; then
    echo "{\"status\": \"success\", \"feature\": \"$FEATURE_NAME\", \"strategy\": \"$STRATEGY\", \"branch\": \"$MAIN_BRANCH\", \"commits\": $COMMIT_COUNT, \"files_changed\": $FILES_CHANGED}"
else
    echo "" >&2
    echo "✅ Feature merged successfully!" >&2
    echo "" >&2
    echo "Feature: $FEATURE_NAME" >&2
    echo "Strategy: $STRATEGY" >&2
    echo "Branch: $MAIN_BRANCH" >&2
    echo "Commits: $COMMIT_COUNT" >&2
    echo "Files changed: $FILES_CHANGED" >&2
    echo "" >&2
    [[ "$CLEANUP_WORKTREE" == "true" ]] && echo "✅ Worktree cleaned up" >&2
    [[ "$KEEP_BRANCH" != "true" ]] && echo "✅ Feature branch deleted" >&2
    [[ "$PUSH" == "true" ]] && echo "✅ Changes pushed to remote" >&2
    echo "" >&2
    echo "Ready to start next feature!" >&2
fi
