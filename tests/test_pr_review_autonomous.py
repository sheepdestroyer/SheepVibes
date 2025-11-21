import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import os
import json
from datetime import datetime, timedelta
from openhands.microagents.workflows.pr_review import PRReviewWorkflow

class TestPRReviewAutonomous(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.repo = "test/repo"
        self.pr_number = 123
        self.token = "dummy_token"

        # Mock GitHubClient
        self.github_patcher = patch('openhands.microagents.workflows.pr_review.GitHubClient')
        self.MockGitHubClient = self.github_patcher.start()
        self.mock_github = self.MockGitHubClient.return_value
        self.mock_github.get_pr_comments.return_value = []
        self.mock_github.dummy_mode = False

        # Mock git.Repo
        self.git_patcher = patch('openhands.microagents.workflows.pr_review.git.Repo')
        self.MockRepo = self.git_patcher.start()
        self.mock_repo = self.MockRepo.return_value
        self.mock_repo.git.apply = MagicMock()

        # Mock WorkflowExecutor
        self.executor_patcher = patch('openhands.microagents.workflows.pr_review.WorkflowExecutor')
        self.MockExecutor = self.executor_patcher.start()

        self.workflow = PRReviewWorkflow(self.repo, self.pr_number, self.token)
        self.workflow.github = self.mock_github # Ensure usage of our mock
        self.workflow.git_repo = self.mock_repo

    def tearDown(self):
        self.github_patcher.stop()
        self.git_patcher.stop()
        self.executor_patcher.stop()
        if os.path.exists(f".processed_comments_{self.pr_number}.json"):
            os.remove(f".processed_comments_{self.pr_number}.json")

    def test_check_google_status_none(self):
        self.assertEqual(self.workflow._check_google_status([]), "None")

    def test_check_google_status_commented(self):
        comments = [
            {'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'Found issues', 'created_at': '2023-01-01T00:00:00Z'}
        ]
        self.assertEqual(self.workflow._check_google_status(comments), "Commented")

    def test_check_google_status_complete(self):
        comments = [
            {'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'Found issues', 'created_at': '2023-01-01T00:00:00Z'},
            {'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'LGTM', 'created_at': '2023-01-02T00:00:00Z'}
        ]
        self.assertEqual(self.workflow._check_google_status(comments), "Complete")

    def test_check_google_status_complete_bug_fix(self):
        # Verify that if LGTM is followed by new issues, it is NOT Complete (it should take the last one)
        comments = [
            {'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'LGTM', 'created_at': '2023-01-01T00:00:00Z'},
            {'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'Found new issues', 'created_at': '2023-01-02T00:00:00Z'}
        ]
        self.assertEqual(self.workflow._check_google_status(comments), "Commented")

    def test_check_google_status_rate_limit(self):
        comments = [
            {'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'You have reached your daily quota limit', 'created_at': '2023-01-01T00:00:00Z'}
        ]
        self.assertEqual(self.workflow._check_google_status(comments), "RateLimited")

    def test_extract_patches(self):
        text = "Here is a fix:\n```diff\n--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-foo\n+bar\n```\nEnd of fix."
        patches = self.workflow._extract_patches(text)
        self.assertEqual(len(patches), 1)
        self.assertIn("-foo", patches[0])

    @patch('openhands.microagents.workflows.pr_review.tempfile.NamedTemporaryFile')
    @patch('openhands.microagents.workflows.pr_review.os.remove')
    @patch('openhands.microagents.workflows.pr_review.os.path.exists')
    def test_apply_patch(self, mock_exists, mock_remove, mock_tempfile):
        mock_exists.return_value = True

        mock_file = MagicMock()
        mock_file.name = "/tmp/random.patch"
        mock_tempfile.return_value.__enter__.return_value = mock_file

        result = self.workflow._apply_patch("diff content")

        self.assertTrue(result)
        self.assertTrue(mock_file.write.called)
        self.mock_repo.git.apply.assert_called_with("/tmp/random.patch")
        mock_remove.assert_called_with("/tmp/random.patch")

    @patch('openhands.microagents.workflows.pr_review.asyncio.sleep')
    async def test_run_autonomous_loop_complete(self, mock_sleep):
        # Mock comments to return Complete immediately
        self.mock_github.get_pr_comments.return_value = [
            {'id': 1, 'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'LGTM', 'created_at': '2023-01-01T00:00:00Z'}
        ]

        result = await self.workflow.run_autonomous_loop(max_cycles=1)
        self.assertEqual(result['status'], "Complete")

    @patch('openhands.microagents.workflows.pr_review.asyncio.sleep')
    async def test_run_autonomous_loop_apply_fix(self, mock_sleep):
        # Mock comments with actionable fix
        self.mock_github.get_pr_comments.return_value = [
            {'id': 1, 'user': {'login': 'gemini-code-assist[bot]'}, 'body': 'Fix this:\n```diff\n+ code\n```', 'created_at': '2023-01-01T00:00:00Z'}
        ]

        # Mock _apply_patch to succeed
        with patch.object(self.workflow, '_apply_patch', return_value=True):
             # Mock _commit_and_push
             with patch.object(self.workflow, '_commit_and_push') as mock_commit:
                 # Mock _trigger_google_review
                with patch.object(self.workflow, '_trigger_google_review') as mock_trigger:
                    await self.workflow.run_autonomous_loop(max_cycles=1)

                    mock_trigger.assert_called_once()
                    mock_commit.assert_called_once()
                    # Verify comments file created
                    self.assertTrue(os.path.exists(f".processed_comments_{self.pr_number}.json"))
