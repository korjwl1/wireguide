#!/usr/bin/env bash
# Move task between lanes (planned → doing → for_review → done)
# Usage: move-task.sh <TASK_ID> <FROM_LANE> <TO_LANE> <FEATURE_DIR>

set -e

TASK_ID="$1"
FROM_LANE="$2"
TO_LANE="$3"
FEATURE_DIR="$4"

if [[ -z "$TASK_ID" || -z "$FROM_LANE" || -z "$TO_LANE" || -z "$FEATURE_DIR" ]]; then
    echo "Usage: $0 <TASK_ID> <FROM_LANE> <TO_LANE> <FEATURE_DIR>"
    echo ""
    echo "Lanes: planned, doing, for_review, done"
    echo ""
    echo "Example: $0 WP01 planned doing specs/001-feature"
    exit 1
fi

# Validate lanes
VALID_LANES=("planned" "doing" "for_review" "done")
if [[ ! " ${VALID_LANES[@]} " =~ " ${FROM_LANE} " ]]; then
    echo "Error: Invalid FROM_LANE: $FROM_LANE" >&2
    echo "Valid lanes: ${VALID_LANES[*]}" >&2
    exit 1
fi

if [[ ! " ${VALID_LANES[@]} " =~ " ${TO_LANE} " ]]; then
    echo "Error: Invalid TO_LANE: $TO_LANE" >&2
    echo "Valid lanes: ${VALID_LANES[*]}" >&2
    exit 1
fi

FROM_DIR="$FEATURE_DIR/tasks/$FROM_LANE"
TO_DIR="$FEATURE_DIR/tasks/$TO_LANE"
TASK_FILE="$TASK_ID.md"

# Create task directories if they don't exist
mkdir -p "$FROM_DIR" "$TO_DIR"

# Check if task exists
if [[ ! -f "$FROM_DIR/$TASK_FILE" ]]; then
    echo "Error: Task $TASK_FILE not found in $FROM_DIR" >&2
    exit 1
fi

# Move task
mv "$FROM_DIR/$TASK_FILE" "$TO_DIR/$TASK_FILE"

# Update frontmatter
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Update lane
if command -v sed &> /dev/null; then
    # macOS and Linux compatible sed
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/^lane: .*$/lane: $TO_LANE/" "$TO_DIR/$TASK_FILE"
    else
        sed -i "s/^lane: .*$/lane: $TO_LANE/" "$TO_DIR/$TASK_FILE"
    fi
fi

# Update timestamps based on lane
case "$TO_LANE" in
    doing)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/^started_at:.*$/started_at: $TIMESTAMP/" "$TO_DIR/$TASK_FILE"
        else
            sed -i "s/^started_at:.*$/started_at: $TIMESTAMP/" "$TO_DIR/$TASK_FILE"
        fi
        ;;
    done)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/^completed_at:.*$/completed_at: $TIMESTAMP/" "$TO_DIR/$TASK_FILE"
        else
            sed -i "s/^completed_at:.*$/completed_at: $TIMESTAMP/" "$TO_DIR/$TASK_FILE"
        fi
        ;;
esac

# Append activity log
echo "" >> "$TO_DIR/$TASK_FILE"
echo "- $TIMESTAMP: Moved from $FROM_LANE to $TO_LANE" >> "$TO_DIR/$TASK_FILE"

# Try to detect git commits for this task
if command -v git &> /dev/null && git rev-parse --git-dir > /dev/null 2>&1; then
    # Get commits that mention this task ID
    # Look for [TASK_ID] or [WP_ID] in commit messages
    COMMITS=$(git log --all --grep="\[$TASK_ID\]" --format="%h|%s|%cd" --date=iso-strict 2>/dev/null || echo "")

    if [[ -n "$COMMITS" ]]; then
        echo "" >> "$TO_DIR/$TASK_FILE"
        echo "# Auto-detected Git commits:" >> "$TO_DIR/$TASK_FILE"

        # Append each commit to activity log
        while IFS='|' read -r hash message commit_date; do
            if [[ -n "$hash" ]]; then
                echo "- $commit_date: [GIT] $hash - $message" >> "$TO_DIR/$TASK_FILE"
            fi
        done <<< "$COMMITS"

        # Collect unique modified files from these commits
        FILES=$(git log --all --grep="\[$TASK_ID\]" --name-only --format="" 2>/dev/null | sort -u || echo "")

        if [[ -n "$FILES" ]]; then
            # Convert to YAML array format
            FILES_YAML=""
            while IFS= read -r file; do
                if [[ -n "$file" ]]; then
                    FILES_YAML="${FILES_YAML}  - ${file}\n"
                fi
            done <<< "$FILES"

            # Update files_modified frontmatter field
            if [[ -n "$FILES_YAML" ]]; then
                # Replace empty array with actual files
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    # On macOS, we need a more complex approach due to sed limitations with multiline
                    # For now, just add a comment
                    echo "" >> "$TO_DIR/$TASK_FILE"
                    echo "# Modified files (from git):" >> "$TO_DIR/$TASK_FILE"
                    echo -e "$FILES_YAML" | sed 's/^/# /' >> "$TO_DIR/$TASK_FILE"
                else
                    sed -i "s/^files_modified: \[\]$/files_modified:\n$FILES_YAML/" "$TO_DIR/$TASK_FILE"
                fi
            fi
        fi

        COMMIT_COUNT=$(echo "$COMMITS" | wc -l | tr -d ' ')
        echo "📦 Detected $COMMIT_COUNT git commit(s) for task $TASK_ID"
    fi
fi

echo "✅ Task $TASK_ID moved: $FROM_LANE → $TO_LANE"
echo "📝 File: $TO_DIR/$TASK_FILE"
