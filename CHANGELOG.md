# Timestamped Changelog maintained by agents when working on this repository

## 2025-11-02

- **Fix: Code review fixes for PR review tracker**
  - Fixed critical subshell bug in check_for_no_remaining_issues function
  - Fixed exit code handling for no open PR scenario (now returns code 2 as documented)
  - Fixed usage function formatting and consistency with heredoc
  - Updated documentation to match actual polling behavior (5 polls × 120s = 10 minutes total)
  - Verified all fixes with comprehensive testing

- **Fix: Implemented proper microagent workflow executor**
  - Fixed workflow continuation logic that was stopping prematurely
  - Implemented strict state machine workflow from pr-review-tracker.md
  - Added execute-workflow.sh script for continuous workflow management
  - Workflow now properly processes TODO comments, pushes changes, and triggers reviews
  - Detected and processed 7 new actionable comments from latest review cycle

- **Refactor: Enhanced PR Review Tracker Microagent with strict state machine**
  - Fixed polling logic to match requirements (120s initial wait, then 120s intervals)
  - Added Google Code Assist daily quota limit detection
  - Implemented strict state machine workflow to prevent review spamming
  - Enhanced comment tracking and validation before triggering new reviews
  - Updated documentation with clear workflow rules and state transitions

## 2025-10-08

- **Documentation: Added code review cycle guidelines**
  - Created comprehensive guide for maintaining PR descriptions across review cycles
  - Added template structure for multi-cycle PR descriptions
  - Documented best practices for preserving context and incremental updates
  - Updated TODO.md to track completion

- **Migration: Upgrade project to Python 3.14**
  - Updated GitHub workflow run-tests.yml to use Python 3.14
  - Updated Containerfile to use Python 3.14-slim base image
  - Updated documentation to reflect Python 3.14 migration
## 2025-10-07

- **Feat(frontend): Move unread counter to left of edit and close buttons**
  - Added edit button (✎) to feed widgets alongside existing delete button
  - Created button container to group edit, delete buttons and unread counter
  - Repositioned unread counter from title area to left of buttons in button container
  - Updated CSS styling for new button container layout with flexbox
  - Added placeholder handleEditFeed function for future implementation

- **Fix: Fix critical error handling bugs and complete code review feedback**
  - **Fixed `handleMarkItemRead`**: Removed unnecessary success check since `fetchData` throws on error - the UI was not updating items as read
  - **Fixed `handleDeleteTab`**: Removed unnecessary success check since `fetchData` throws on error - the UI was not updating after tab deletion
- **Improved `API_BASE_URL` detection**: Now uses `window.location.hostname` instead of `window.location.origin.includes('localhost')` for more robust localhost detection
- **Removed dead code**: Eliminated unreachable error handling in `handleRefreshAllFeeds`
- **Added radix parameter**: Used `parseInt(feedIdInput.value, 10)` to prevent unexpected octal parsing behavior

## 2025-10-06

- **Feat: Make each widget's feed URL editable**
  - Added PUT endpoint `/api/feeds/<feed_id>` for updating feed URLs and properties
  - Added edit button (✎) to each feed widget in the frontend
  - Implemented modal dialog for editing feed URLs with validation
  - Added comprehensive tests for the new functionality
  - Feed name and site link are automatically updated when URL is changed
- **Fix: Addressed all Gemini Code Assist review comments for PR #100**
  - Fixed backend performance issue by replacing redundant `fetch_and_update_feed` call with direct `process_feed_entries` to avoid duplicate network requests
- Updated frontend API configuration to use relative paths for production deployment
- Fixed frontend error handling syntax and improved user experience in edit modal

## 2025-07-26

- **Fix(feed_service): Use entry link as GUID to prevent UNIQUE constraint errors**
  - The MIT Technology Review feed was failing to update because it was providing the same GUID for multiple different articles. This was causing a UNIQUE constraint failure in the database.
  - This change modifies the `feed_service` to always use the entry's link as the GUID. The link is a reliable and unique identifier for each article, which will prevent this issue from happening in the future.
