
#!/bin/bash

# Common functions for SheepVibes scripts

# Get repository owner and name from git remote
get_repo_info() {
    local repo_slug
    
    # Use environment variables if provided, otherwise detect from git remote
    if [ -n "${GITHUB_REPO_OWNER:-}" ] && [ -n "${GITHUB_REPO_NAME:-}" ]; then
        REPO_OWNER="$GITHUB_REPO_OWNER"
        REPO_NAME="$GITHUB_REPO_NAME"
    else
        REPO_SLUG=$(git remote get-url origin 2>/dev/null | sed -e 's/.*github.com[:\/]//' -e 's/\.git$//')
        if [ -n "$REPO_SLUG" ]; then
            REPO_OWNER=$(echo "$REPO_SLUG" | cut -d'/' -f1)
            REPO_NAME=$(echo "$REPO_SLUG" | cut -d'/' -f2)
        else
            printf "Error: Could not determine repository owner and name from git remote.\n" >&2
            exit 1
        fi
    fi
    REPO="${REPO_OWNER}/${REPO_NAME}"
    export REPO_OWNER REPO_NAME REPO
}

