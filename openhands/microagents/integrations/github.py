import requests
from typing import List

class GitHubClient:
    """A client for interacting with the GitHub API."""

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.base_url = "https://api.github.com"

    def get_pr(self, repo: str, pr_number: int) -> dict:
        """Gets PR data from the GitHub API."""
        if self.token == "dummy_token":
            return {
                "title": "Test PR",
                "body": "This is a test PR.",
                "base": {"ref": "main"},
                "head": {"sha": "test_sha"}
            }
        url = f"{self.base_url}/repos/{repo}/pulls/{pr_number}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def post_pr_comment(self, repo: str, pr_number: int, comment: str):
        """Posts a comment on a PR."""
        if self.token == "dummy_token":
            print(f"Posting comment to PR {pr_number} in {repo}:\\n{comment}")
            return
        url = f"{self.base_url}/repos/{repo}/issues/{pr_number}/comments"
        data = {"body": comment}
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()

    def add_labels(self, repo: str, pr_number: int, labels: List[str]):
        """Adds labels to a PR."""
        if self.token == "dummy_token":
            print(f"Adding labels {labels} to PR {pr_number} in {repo}")
            return
        url = f"{self.base_url}/repos/{repo}/issues/{pr_number}/labels"
        data = {"labels": labels}
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()

    def approve_pr(self, repo: str, pr_number: int):
        """Approves a PR."""
        if self.token == "dummy_token":
            print(f"Approving PR {pr_number} in {repo}")
            return
        url = f"{self.base_url}/repos/{repo}/pulls/{pr_number}/reviews"
        data = {"event": "APPROVE"}
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()

    def request_changes(self, repo: str, pr_number: int, comment: str):
        """Requests changes on a PR."""
        if self.token == "dummy_token":
            print(f"Requesting changes on PR {pr_number} in {repo} with comment: {comment}")
            return
        url = f"{self.base_url}/repos/{repo}/pulls/{pr_number}/reviews"
        data = {"body": comment, "event": "REQUEST_CHANGES"}
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
