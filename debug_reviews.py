import subprocess
import sys

from github import Github

try:
    res = subprocess.run(
        ["gh", "auth", "token"], capture_output=True, text=True, check=True
    )
    token = res.stdout.strip()
except Exception as e:
    print(f"Error getting token: {e}")
    sys.exit(1)

g = Github(token)
repo = g.get_repo("sheepdestroyer/SheepVibes")
pr = repo.get_pull(233)

print(f"Fetching reviews for PR #{pr.number}...")
reviews = pr.get_reviews()

for review in reviews:
    print(f"ID: {review.id}")
    print(f"User: {review.user.login}")
    print(f"State: {review.state}")
    print(f"Submitted: {review.submitted_at}")
    print("Body:")
    print(review.body)
    print("-" * 50)
