"""
Service for handling GitHub operations
"""
import os
from github import Github
from typing import Dict, List, Any


class GitHubService:
    """Handle GitHub API operations"""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        self.client = Github(self.token) if self.token else None

    def get_pull_request(self, owner: str, repo: str, pr_number: int) -> Dict:
        """
        Get pull request data from GitHub API

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            Dictionary containing PR data
        """
        try:
            repo_name = f"{owner}/{repo}"
            repository = self.client.get_repo(repo_name)
            pr = repository.get_pull(pr_number)
            
            return {
                "number": pr.number,
                "title": pr.title,
                "body": pr.body,
                "state": pr.state,
                "user": {"login": pr.user.login},
                "base": {
                    "repo": {
                        "full_name": repo_name
                    }
                }
            }
        except Exception as e:
            raise Exception(f"Error getting pull request: {str(e)}")

    def get_pr_diff(self, pr_data: Dict) -> Dict[str, Any]:
        """
        Get the diff for a pull request

        Args:
            pr_data: Pull request data from webhook

        Returns:
            Dictionary containing PR diff information
        """
        try:
            repo_name = pr_data["base"]["repo"]["full_name"]
            pr_number = pr_data["number"]

            repo = self.client.get_repo(repo_name)
            pr = repo.get_pull(pr_number)

            # Get files changed
            files = pr.get_files()

            diff_data = {
                "pr_number": pr_number,
                "title": pr.title,
                "description": pr.body,
                "author": pr.user.login,
                "repository": repo_name,
                "files": [],
            }

            for file in files:
                diff_data["files"].append(
                    {
                        "filename": file.filename,
                        "status": file.status,
                        "additions": file.additions,
                        "deletions": file.deletions,
                        "changes": file.changes,
                        "patch": file.patch if hasattr(file, "patch") else None,
                        "language": self._detect_language(file.filename),
                    }
                )

            return diff_data

        except Exception as e:
            raise Exception(f"Error getting PR diff: {str(e)}")

    def post_review_comments(self, pr_data: Dict, review_result: Dict) -> None:
        """
        Post review comments to a pull request as an issue comment
        Requires 'issues: write' permission in the workflow

        Args:
            pr_data: Pull request data from webhook
            review_result: Analysis results from LLM
        """
        try:
            repo_name = pr_data["base"]["repo"]["full_name"]
            pr_number = pr_data["number"]

            repo = self.client.get_repo(repo_name)
            
            # Create review comment body with inline comments included
            comment_body = self._format_review_comment(review_result, include_inline=True)

            # Post as issue comment using the issue number (PRs are also issues)
            # This method is more reliable than pr.create_issue_comment()
            issue = repo.get_issue(pr_number)
            issue.create_comment(comment_body)

        except Exception as e:
            error_msg = str(e)
            # Provide helpful error message for 403 errors
            if "403" in error_msg or "Resource not accessible by integration" in error_msg:
                raise Exception(
                    f"Permission denied (403): Unable to post comment on PR #{pr_number}.\n"
                    f"This usually means the workflow is missing required permissions.\n"
                    f"Please add this to your workflow file under the job:\n\n"
                    f"  permissions:\n"
                    f"    issues: write\n"
                    f"    pull-requests: read\n\n"
                    f"Original error: {error_msg}"
                )
            raise Exception(f"Error posting review comments: {error_msg}")

    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename"""
        extensions = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".swift": "swift",
            ".kt": "kotlin",
            ".rs": "rust",
        }

        ext = os.path.splitext(filename)[1].lower()
        return extensions.get(ext, "unknown")

    def _format_review_comment(self, review_result: Dict, include_inline: bool = False) -> str:
        """Format the review result into a markdown comment"""
        comment = "## 🤖 Automated Code Review\n\n"

        if review_result.get("summary"):
            comment += f"### Summary\n{review_result['summary']}\n\n"

        if review_result.get("issues"):
            comment += "### Issues Found\n\n"
            for issue in review_result["issues"]:
                severity = issue.get("severity", "info").upper()
                emoji = (
                    "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
                )
                comment += f"{emoji} **{severity}**: {issue.get('message')}\n"
            comment += "\n"

        # Include file-specific issues if available
        if include_inline and review_result.get("file_issues"):
            comment += "### File-Specific Issues\n\n"
            for file_issue in review_result.get("file_issues", []):
                if file_issue.get("file") and file_issue.get("line"):
                    comment += f"**`{file_issue['file']}`** (line {file_issue['line']}): {file_issue.get('message', '')}\n"
            comment += "\n"

        if review_result.get("suggestions"):
            comment += "### Suggestions\n\n"
            for suggestion in review_result["suggestions"]:
                comment += f"- {suggestion}\n"
            comment += "\n"

        comment += (
            "\n---\n*This review was generated automatically by the PR Reviewer Bot*"
        )

        return comment

    def _create_inline_comments(self, review_result: Dict) -> List[Dict]:
        """Create inline comments for specific lines"""
        comments = []

        for issue in review_result.get("file_issues", []):
            if issue.get("line") and issue.get("file"):
                comments.append(
                    {
                        "path": issue["file"],
                        "line": issue["line"],
                        "body": issue["message"],
                    }
                )

        return comments
