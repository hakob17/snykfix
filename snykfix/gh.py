"""GitHub via the gh CLI. All state lives in GitHub (branch names, PRs, releases), so runs are idempotent."""
import json
import re
import subprocess


def sh(*args: str, cwd: str | None = None, check: bool = True) -> str:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=check).stdout.strip()


def clone(repo: str, dest: str) -> None:
    sh("gh", "repo", "clone", repo, dest, "--", "--depth", "50")


def find_pr(repo: str, branch: str) -> dict | None:
    out = sh("gh", "pr", "list", "--repo", repo, "--head", branch, "--state", "all", "--limit", "1",
             "--json", "number,state,url,mergedAt")
    prs = json.loads(out or "[]")
    return prs[0] if prs else None


def release_after(repo: str, merged_at: str) -> str | None:
    """Version of the first release published after the fix PR merged ('v1.2.3' / 'pkg@1.2.3' -> '1.2.3')."""
    out = sh("gh", "api", f"repos/{repo}/releases?per_page=30", "--jq",
             f'[.[] | select(.draft|not) | select(.published_at > "{merged_at}")] | sort_by(.published_at) | '
             f'.[0].tag_name // empty')
    if not out:
        return None
    return re.sub(r"^.*@|^v", "", out)


def has_changes(repo_dir: str) -> bool:
    return bool(sh("git", "status", "--porcelain", cwd=repo_dir))


def commit(repo_dir: str, branch: str, message: str) -> None:
    # Commit before the verification scan so restore/scan artifacts never end up in the PR.
    sh("git", "checkout", "-B", branch, cwd=repo_dir)
    sh("git", "add", "-A", cwd=repo_dir)
    sh("git", "-c", "user.name=snykfix-bot", "-c", "user.email=snykfix-bot@users.noreply.github.com",
       "commit", "-m", message, cwd=repo_dir)


def push(repo_dir: str, branch: str) -> None:
    sh("git", "push", "-u", "origin", branch, "--force-with-lease", cwd=repo_dir)


def create_pr(repo: str, repo_dir: str, branch: str, title: str, body: str, draft: bool) -> str:
    args = ["gh", "pr", "create", "--repo", repo, "--head", branch, "--title", title, "--body", body]
    return sh(*args, *(["--draft"] if draft else []), cwd=repo_dir)
