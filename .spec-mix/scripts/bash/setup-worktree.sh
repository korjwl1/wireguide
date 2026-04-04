#!/usr/bin/env bash
# Setup git worktree for feature isolation
# Usage: setup-worktree.sh --feature <feature-name> [--cleanup]

set -e

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Default values
FEATURE_NAME=""
CLEANUP_MODE=false
JSON_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --feature)
            FEATURE_NAME="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP_MODE=true
            shift
            ;;
        --json)
            JSON_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 --feature <feature-name> [--cleanup] [--json]"
            echo ""
            echo "Options:"
            echo "  --feature <name>   Feature branch name (e.g., 001-user-auth)"
            echo "  --cleanup          Remove worktree and branch"
            echo "  --json             Output in JSON format"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --feature 001-user-auth"
            echo "  $0 --feature 001-user-auth --cleanup"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Validate feature name
if [[ -z "$FEATURE_NAME" ]]; then
    echo "Error: --feature is required" >&2
    exit 1
fi

# Get repository root
REPO_ROOT=$(get_repo_root)
WORKTREE_DIR="$REPO_ROOT/.worktrees/$FEATURE_NAME"

# Check if git is available
if ! has_git; then
    echo "Error: Git is required for worktree functionality" >&2
    exit 1
fi

# Cleanup mode
if [[ "$CLEANUP_MODE" == "true" ]]; then
    if [[ ! -d "$WORKTREE_DIR" ]]; then
        echo "Worktree does not exist: $WORKTREE_DIR" >&2
        exit 1
    fi

    echo "Cleaning up worktree: $FEATURE_NAME" >&2

    # Remove worktree
    git worktree remove "$WORKTREE_DIR" --force 2>/dev/null || true

    # Delete branch if it exists
    if git show-ref --verify --quiet refs/heads/"$FEATURE_NAME"; then
        git branch -D "$FEATURE_NAME" 2>/dev/null || true
    fi

    if [[ "$JSON_MODE" == "true" ]]; then
        echo "{\"status\": \"cleaned\", \"feature\": \"$FEATURE_NAME\"}"
    else
        echo "✅ Worktree cleaned up: $FEATURE_NAME"
    fi

    exit 0
fi

# Create mode
# Check if worktree already exists
if [[ -d "$WORKTREE_DIR" ]]; then
    if [[ "$JSON_MODE" == "true" ]]; then
        echo "{\"status\": \"exists\", \"feature\": \"$FEATURE_NAME\", \"path\": \"$WORKTREE_DIR\"}"
    else
        echo "Worktree already exists: $WORKTREE_DIR" >&2
        echo "To clean up: $0 --feature $FEATURE_NAME --cleanup" >&2
    fi
    exit 1
fi

# Create worktrees directory if it doesn't exist
mkdir -p "$REPO_ROOT/.worktrees"

# Check if branch exists
BRANCH_EXISTS=false
if git show-ref --verify --quiet refs/heads/"$FEATURE_NAME"; then
    BRANCH_EXISTS=true
fi

# Create worktree
echo "Creating worktree for feature: $FEATURE_NAME" >&2

if [[ "$BRANCH_EXISTS" == "true" ]]; then
    # Use existing branch
    git worktree add "$WORKTREE_DIR" "$FEATURE_NAME"
else
    # Create new branch from current HEAD
    git worktree add -b "$FEATURE_NAME" "$WORKTREE_DIR"
fi

# Output result
if [[ "$JSON_MODE" == "true" ]]; then
    echo "{\"status\": \"created\", \"feature\": \"$FEATURE_NAME\", \"path\": \"$WORKTREE_DIR\", \"branch_existed\": $BRANCH_EXISTS}"
else
    echo "" >&2
    echo "✅ Worktree created successfully!" >&2
    echo "" >&2
    echo "📂 Path: $WORKTREE_DIR" >&2
    echo "🌿 Branch: $FEATURE_NAME" >&2
    echo "" >&2
    echo "Next steps:" >&2
    echo "  cd $WORKTREE_DIR" >&2
    echo "  # Work on your feature" >&2
    echo "  # When done, use /spec-mix.merge to integrate" >&2
    echo "" >&2
fi
