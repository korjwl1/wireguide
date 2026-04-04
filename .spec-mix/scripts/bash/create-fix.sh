#!/usr/bin/env bash
# Create a fix branch and document for bug fixes
# Supports both feature-scoped fixes and hotfixes from main

set -e

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/common.sh" ]]; then
    source "$SCRIPT_DIR/common.sh"
fi

# Parse arguments
JSON_MODE=false
PRIORITY=""
PARENT_FEATURE=""
FIX_TYPE=""
FIX_NUMBER=""
ARGS=()

i=1
while [ $i -le $# ]; do
    arg="${!i}"
    case "$arg" in
        --json)
            JSON_MODE=true
            ;;
        --priority)
            if [ $((i + 1)) -gt $# ]; then
                echo 'Error: --priority requires a value (P0|P1|P2|P3)' >&2
                exit 1
            fi
            i=$((i + 1))
            PRIORITY="${!i}"
            ;;
        --parent)
            if [ $((i + 1)) -gt $# ]; then
                echo 'Error: --parent requires a feature ID' >&2
                exit 1
            fi
            i=$((i + 1))
            PARENT_FEATURE="${!i}"
            ;;
        --type)
            if [ $((i + 1)) -gt $# ]; then
                echo 'Error: --type requires a value (fix|hotfix)' >&2
                exit 1
            fi
            i=$((i + 1))
            FIX_TYPE="${!i}"
            ;;
        --number)
            if [ $((i + 1)) -gt $# ]; then
                echo 'Error: --number requires a value' >&2
                exit 1
            fi
            i=$((i + 1))
            FIX_NUMBER="${!i}"
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] <bug_description>"
            echo ""
            echo "Options:"
            echo "  --json              Output in JSON format"
            echo "  --priority <level>  Priority: P0|P1|P2|P3 (default: auto-detect)"
            echo "  --parent <feature>  Parent feature ID (default: auto-detect from branch)"
            echo "  --type <type>       Type: fix|hotfix (default: auto-detect)"
            echo "  --number <N>        Specify fix number manually"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 'Login timeout error when session expires'"
            echo "  $0 --priority P1 'Critical auth bypass vulnerability'"
            echo "  $0 --type hotfix 'Production database connection leak'"
            exit 0
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
    i=$((i + 1))
done

BUG_DESCRIPTION="${ARGS[*]}"
if [ -z "$BUG_DESCRIPTION" ]; then
    echo "Usage: $0 [OPTIONS] <bug_description>" >&2
    exit 1
fi

# Determine repository root
find_repo_root() {
    local dir="$1"
    while [ "$dir" != "/" ]; do
        if [ -d "$dir/.git" ] || [ -d "$dir/.spec-mix" ]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    return 1
}

if git rev-parse --show-toplevel >/dev/null 2>&1; then
    REPO_ROOT=$(git rev-parse --show-toplevel)
    HAS_GIT=true
else
    REPO_ROOT="$(find_repo_root "$SCRIPT_DIR")"
    if [ -z "$REPO_ROOT" ]; then
        echo "Error: Could not determine repository root." >&2
        exit 1
    fi
    HAS_GIT=false
fi

cd "$REPO_ROOT"
SPECS_DIR="$REPO_ROOT/specs"

# Detect current branch context
get_current_branch_local() {
    if [[ -n "${SPECIFY_FEATURE:-}" ]]; then
        echo "$SPECIFY_FEATURE"
        return
    fi
    if git rev-parse --abbrev-ref HEAD >/dev/null 2>&1; then
        git rev-parse --abbrev-ref HEAD
        return
    fi
    echo "main"
}

CURRENT_BRANCH=$(get_current_branch_local)

# Auto-detect fix type if not specified
if [ -z "$FIX_TYPE" ]; then
    if [[ "$CURRENT_BRANCH" =~ ^([0-9]{3})-(.+)$ ]]; then
        FIX_TYPE="fix"
        if [ -z "$PARENT_FEATURE" ]; then
            PARENT_FEATURE="$CURRENT_BRANCH"
        fi
    elif [[ "$CURRENT_BRANCH" == "main" || "$CURRENT_BRANCH" == "master" ]]; then
        FIX_TYPE="hotfix"
    else
        # Default to hotfix if we can't determine
        FIX_TYPE="hotfix"
    fi
fi

# Generate short name from bug description
generate_fix_short_name() {
    local description="$1"
    local stop_words="^(i|a|an|the|to|for|of|in|on|at|by|with|from|is|are|was|were|be|been|being|have|has|had|do|does|did|will|would|should|could|can|may|might|must|shall|this|that|these|those|my|your|our|their|want|need|add|get|set|fix|bug|issue|error|problem)$"

    local clean_name=$(echo "$description" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/ /g')
    local meaningful_words=()

    for word in $clean_name; do
        [ -z "$word" ] && continue
        if ! echo "$word" | grep -qiE "$stop_words"; then
            if [ ${#word} -ge 3 ]; then
                meaningful_words+=("$word")
            fi
        fi
    done

    if [ ${#meaningful_words[@]} -gt 0 ]; then
        local max_words=3
        local result=""
        local count=0
        for word in "${meaningful_words[@]}"; do
            if [ $count -ge $max_words ]; then break; fi
            if [ -n "$result" ]; then result="$result-"; fi
            result="$result$word"
            count=$((count + 1))
        done
        echo "$result"
    else
        echo "fix"
    fi
}

SHORT_NAME=$(generate_fix_short_name "$BUG_DESCRIPTION")

# Find next fix number
find_next_fix_number() {
    local fix_type="$1"
    local parent="$2"
    local max_num=0

    if [ "$fix_type" == "fix" ] && [ -n "$parent" ]; then
        # Check existing fix branches for this feature
        if [ "$HAS_GIT" = true ]; then
            local pattern="${parent}-fix-"
            local remote_nums=$(git ls-remote --heads origin 2>/dev/null | grep -E "refs/heads/${parent}-fix-[0-9]+$" | sed "s/.*-fix-\([0-9]*\)$/\1/" | sort -n)
            local local_nums=$(git branch 2>/dev/null | grep -E "^[* ]*${parent}-fix-[0-9]+$" | sed "s/.*-fix-\([0-9]*\)$/\1/" | sort -n)

            for num in $remote_nums $local_nums; do
                num=$((10#$num))
                if [ "$num" -gt "$max_num" ]; then max_num=$num; fi
            done
        fi

        # Check existing FIX files in the feature directory
        local fixes_dir="$SPECS_DIR/$parent/fixes"
        if [ -d "$fixes_dir" ]; then
            for file in "$fixes_dir"/FIX*.md; do
                [ -f "$file" ] || continue
                local filename=$(basename "$file" .md)
                local num=$(echo "$filename" | sed 's/FIX//' | sed 's/^0*//')
                num=$((10#${num:-0}))
                if [ "$num" -gt "$max_num" ]; then max_num=$num; fi
            done
        fi
    else
        # Check hotfix branches
        if [ "$HAS_GIT" = true ]; then
            local remote_nums=$(git ls-remote --heads origin 2>/dev/null | grep -E "refs/heads/hotfix-[0-9]+-" | sed 's/.*hotfix-\([0-9]*\)-.*/\1/' | sort -n)
            local local_nums=$(git branch 2>/dev/null | grep -E "^[* ]*hotfix-[0-9]+-" | sed 's/.*hotfix-\([0-9]*\)-.*/\1/' | sort -n)

            for num in $remote_nums $local_nums; do
                num=$((10#$num))
                if [ "$num" -gt "$max_num" ]; then max_num=$num; fi
            done
        fi

        # Check hotfix directory
        local hotfix_dir="$SPECS_DIR/hotfix"
        if [ -d "$hotfix_dir" ]; then
            for file in "$hotfix_dir"/HOTFIX-*.md; do
                [ -f "$file" ] || continue
                local filename=$(basename "$file" .md)
                local num=$(echo "$filename" | sed 's/HOTFIX-\([0-9]*\)-.*/\1/' | sed 's/^0*//')
                num=$((10#${num:-0}))
                if [ "$num" -gt "$max_num" ]; then max_num=$num; fi
            done
        fi
    fi

    echo $((max_num + 1))
}

if [ -z "$FIX_NUMBER" ]; then
    FIX_NUMBER=$(find_next_fix_number "$FIX_TYPE" "$PARENT_FEATURE")
fi

# Suggest priority based on keywords
suggest_priority() {
    local desc="$1"
    local desc_lower=$(echo "$desc" | tr '[:upper:]' '[:lower:]')

    # P0: Critical
    if echo "$desc_lower" | grep -qE "(security|crash|data.?loss|production|urgent|critical|emergency)"; then
        echo "P0"
        return
    fi

    # P1: High
    if echo "$desc_lower" | grep -qE "(broken|fails?|cannot|blocking|regression|severe)"; then
        echo "P1"
        return
    fi

    # P2: Medium (default)
    if echo "$desc_lower" | grep -qE "(incorrect|wrong|unexpected|issue|bug|error)"; then
        echo "P2"
        return
    fi

    # P3: Low
    if echo "$desc_lower" | grep -qE "(minor|cosmetic|typo|improvement|enhancement|polish)"; then
        echo "P3"
        return
    fi

    echo "P2"  # Default
}

if [ -z "$PRIORITY" ]; then
    PRIORITY=$(suggest_priority "$BUG_DESCRIPTION")
fi

# Search for related Work Packages across all specs
find_related_wps() {
    local description="$1"
    local keywords=$(echo "$description" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/ /g' | tr ' ' '\n' | grep -E '.{3,}' | head -5)
    local related=()

    if [ -d "$SPECS_DIR" ]; then
        for feature_dir in "$SPECS_DIR"/[0-9]*-*; do
            [ -d "$feature_dir" ] || continue
            local tasks_dir="$feature_dir/tasks"

            for lane in planned doing for_review done; do
                local lane_dir="$tasks_dir/$lane"
                [ -d "$lane_dir" ] || continue

                for wp_file in "$lane_dir"/WP*.md; do
                    [ -f "$wp_file" ] || continue
                    local content=$(cat "$wp_file" 2>/dev/null | tr '[:upper:]' '[:lower:]')

                    for keyword in $keywords; do
                        if echo "$content" | grep -q "$keyword"; then
                            local wp_id=$(basename "$wp_file" .md)
                            local feature_name=$(basename "$feature_dir")
                            # Avoid duplicates
                            local entry="$feature_name:$wp_id"
                            if [[ ! " ${related[*]} " =~ " ${entry} " ]]; then
                                related+=("$entry")
                            fi
                            break
                        fi
                    done
                done
            done
        done
    fi

    # Return first 5 related WPs
    printf '%s\n' "${related[@]}" | head -5 | tr '\n' ',' | sed 's/,$//'
}

RELATED_WPS=$(find_related_wps "$BUG_DESCRIPTION")

# Generate branch name and create directory
FIX_NUM=$(printf "%02d" "$FIX_NUMBER")
DATE_NOW=$(date +%Y-%m-%d)

if [ "$FIX_TYPE" == "fix" ]; then
    BRANCH_NAME="${PARENT_FEATURE}-fix-${FIX_NUM}"
    FIX_ID="FIX${FIX_NUM}"
    FIXES_DIR="$SPECS_DIR/$PARENT_FEATURE/fixes"
    FIX_FILE="$FIXES_DIR/${FIX_ID}.md"
else
    BRANCH_NAME="hotfix-${FIX_NUM}-${SHORT_NAME}"
    FIX_ID="HOTFIX-${FIX_NUM}-${SHORT_NAME}"
    FIXES_DIR="$SPECS_DIR/hotfix"
    FIX_FILE="$FIXES_DIR/${FIX_ID}.md"
fi

# Create branch
if [ "$HAS_GIT" = true ]; then
    git fetch --all --prune 2>/dev/null || true
    git checkout -b "$BRANCH_NAME" 2>/dev/null || {
        # Branch might already exist
        if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
            git checkout "$BRANCH_NAME"
        else
            echo "Error: Failed to create or checkout branch $BRANCH_NAME" >&2
            exit 1
        fi
    }
else
    >&2 echo "[fix] Warning: Git not detected; skipped branch creation for $BRANCH_NAME"
fi

# Create fixes directory and document
mkdir -p "$FIXES_DIR"

# Create fix document from template or inline
TEMPLATE="$REPO_ROOT/.spec-mix/templates/fix-template.md"

if [ -f "$TEMPLATE" ]; then
    cp "$TEMPLATE" "$FIX_FILE"
    # Replace placeholders
    sed -i.bak "s/\[FIX_ID\]/$FIX_ID/g" "$FIX_FILE"
    sed -i.bak "s/\[TITLE\]/$BUG_DESCRIPTION/g" "$FIX_FILE"
    sed -i.bak "s/\[DATE\]/$DATE_NOW/g" "$FIX_FILE"
    sed -i.bak "s/\[BRANCH_NAME\]/$BRANCH_NAME/g" "$FIX_FILE"
    sed -i.bak "s/\[FEATURE_ID\]/$PARENT_FEATURE/g" "$FIX_FILE"
    sed -i.bak "s/\[PRIORITY\]/$PRIORITY/g" "$FIX_FILE"
    rm -f "$FIX_FILE.bak"
else
    # Create inline minimal template
    cat > "$FIX_FILE" << EOF
---
id: $FIX_ID
type: $FIX_TYPE
priority: $PRIORITY
status: analyzing
parent_feature: $PARENT_FEATURE
related_wps: [$RELATED_WPS]
created_at: $DATE_NOW
fixed_at: null
branch: $BRANCH_NAME
---

# $FIX_ID: $BUG_DESCRIPTION

## Problem Statement

**Reported**: [How was this bug discovered?]
**Impact**: [Who is affected and how severely?]
**Symptoms**: [Observable behavior]

## Root Cause Analysis

**Hypothesis**: [What do you think is causing the issue?]
**Evidence**: [Code references, logs, reproduction steps]
**Related Code**:
- \`path/to/file:line\` - [Brief description]

## Related Context

**Work Packages**: $RELATED_WPS
**Features**: $PARENT_FEATURE

## Fix Plan

**Approach**: [1-2 sentence summary of fix approach]
**Changes Required**:
- [ ] \`path/to/file\` - [What to change]
- [ ] \`path/to/test\` - [Test to add/modify]

**Risk Assessment**: [Low|Medium|High - Brief justification]

## Verification

**Test Plan**:
- [ ] [Specific test case 1]
- [ ] [Specific test case 2]
- [ ] Regression check: [What else to verify]

**Done Criteria**:
- [ ] Bug no longer reproducible
- [ ] Tests added/updated
- [ ] No regressions introduced

## Activity Log

- $DATE_NOW: Fix created with priority $PRIORITY
EOF
fi

# Set environment variable
export SPECIFY_FEATURE="$BRANCH_NAME"

# Output results
if $JSON_MODE; then
    # Escape special characters for JSON
    ESCAPED_DESC=$(echo "$BUG_DESCRIPTION" | sed 's/"/\\"/g')
    ESCAPED_WPS=$(echo "$RELATED_WPS" | sed 's/"/\\"/g')

    printf '{"FIX_ID":"%s","FIX_TYPE":"%s","PARENT_FEATURE":"%s","BRANCH_NAME":"%s","FIX_FILE":"%s","RELATED_WPS":"%s","PRIORITY":"%s","STATUS":"analyzing"}\n' \
        "$FIX_ID" "$FIX_TYPE" "$PARENT_FEATURE" "$BRANCH_NAME" "$FIX_FILE" "$ESCAPED_WPS" "$PRIORITY"
else
    echo "============================================"
    echo "Fix Created Successfully"
    echo "============================================"
    echo "FIX_ID: $FIX_ID"
    echo "Type: $FIX_TYPE"
    echo "Priority: $PRIORITY"
    echo "Branch: $BRANCH_NAME"
    echo "Document: $FIX_FILE"
    [ -n "$PARENT_FEATURE" ] && echo "Parent Feature: $PARENT_FEATURE"
    [ -n "$RELATED_WPS" ] && echo "Related WPs: $RELATED_WPS"
    echo ""
    echo "Next steps:"
    echo "  1. Review and update the fix document"
    echo "  2. Analyze root cause"
    echo "  3. Implement fix"
    echo "  4. Create PR with: gh pr create"
fi
