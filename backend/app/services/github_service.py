"""
Service for handling GitHub operations
"""
import os
import requests
from github import Github
from typing import Dict, List, Any


class GitHubService:
    """Handle GitHub API operations"""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        self.client = Github(self.token) if self.token else None
        
    def _check_token_permissions(self, repo_name: str) -> Dict[str, Any]:
        """
        Check what permissions the token has
        Returns a dict with permission info for debugging
        """
        try:
            owner, repo = repo_name.split("/")
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "PR-Reviewer-Action"
            }
            
            # Check repository access
            response = requests.get(api_url, headers=headers, timeout=10)
            return {
                "repo_access": response.status_code == 200,
                "repo_status": response.status_code,
                "token_present": bool(self.token),
                "token_preview": f"{self.token[:10]}..." if self.token and len(self.token) > 10 else "None"
            }
        except Exception:
            return {"error": "Could not check permissions"}

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
            print(f"🔍 Fetching PR #{pr_number} from {repo_name}...")
            repository = self.client.get_repo(repo_name)
            pr = repository.get_pull(pr_number)
            
            pr_data = {
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
            
            print(f"✅ Retrieved PR #{pr_data['number']}: {pr_data['title']}")
            return pr_data
        except Exception as e:
            print(f"❌ Error fetching PR #{pr_number}: {str(e)}")
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
            
            print(f"📝 Preparing to post review comment...")
            print(f"   Repository: {repo_name}")
            print(f"   PR Number: {pr_number}")
            
            # Verify PR number matches what we expect
            actual_pr_number = pr_data.get("number", pr_number)
            if actual_pr_number != pr_number:
                print(f"⚠️  Warning: PR number mismatch. Using {actual_pr_number} from PR data (expected {pr_number})")
                pr_number = actual_pr_number  # Use the actual PR number from the data

            # Create review comment body with inline comments included
            comment_body = self._format_review_comment(review_result, include_inline=True)
            print(f"   Comment length: {len(comment_body)} characters")
            print(f"   Comment preview (first 200 chars): {comment_body[:200]}...")
            
            if not comment_body or len(comment_body.strip()) == 0:
                raise Exception("Comment body is empty! Cannot post empty comment.")

            # Try using REST API directly first (more reliable for permissions)
            try:
                owner, repo = repo_name.split("/")
                api_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
                print(f"   API URL: {api_url}")
                
                headers = {
                    "Authorization": f"token {self.token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "PR-Reviewer-Action"
                }
                
                response = requests.post(
                    api_url,
                    json={"body": comment_body},
                    headers=headers,
                    timeout=30
                )
                
                # Handle success status codes (201 Created is standard, but 200 OK might also occur)
                if response.status_code in [200, 201]:
                    try:
                        response_data = response.json()
                        comment_url = response_data.get("html_url", "N/A")
                        comment_id = response_data.get("id", "N/A")
                        print(f"✅ Comment posted successfully!")
                        print(f"   Status code: {response.status_code}")
                        print(f"   Comment ID: {comment_id}")
                        print(f"   Comment URL: {comment_url}")
                        print(f"   PR #{pr_number} in {repo_name}")
                        print(f"   View PR: https://github.com/{repo_name}/pull/{pr_number}")
                        
                        # Verify the comment was actually created by fetching it back
                        if comment_id and comment_id != "N/A":
                            verify_url = f"https://api.github.com/repos/{owner}/{repo}/issues/comments/{comment_id}"
                            verify_response = requests.get(verify_url, headers=headers, timeout=10)
                            if verify_response.status_code == 200:
                                verify_data = verify_response.json()
                                verified_pr_number = verify_data.get("issue_url", "").split("/")[-1]
                                print(f"   ✅ Verified: Comment exists and is accessible")
                                print(f"   Verified on issue/PR: #{verified_pr_number}")
                                if str(verified_pr_number) != str(pr_number):
                                    print(f"   ⚠️  WARNING: Comment was posted to issue #{verified_pr_number}, not PR #{pr_number}!")
                            else:
                                print(f"   ⚠️  Warning: Could not verify comment (status {verify_response.status_code})")
                                print(f"   Response: {verify_response.text[:200]}")
                        
                        return  # Success!
                    except Exception as parse_error:
                        print(f"⚠️  Comment created but couldn't parse response: {parse_error}")
                        print(f"   Response status: {response.status_code}")
                        print(f"   Response text: {response.text[:500]}")
                        return  # Still consider it success if status was 200/201
                elif response.status_code == 403:
                    error_data = response.json() if response.text else {}
                    error_msg = error_data.get("message", "Forbidden")
                    raise Exception(
                        f"Permission denied (403): Unable to post comment on PR #{pr_number}.\n"
                        f"Repository: {repo_name}\n"
                        f"This usually means the workflow is missing required permissions.\n\n"
                        f"SOLUTION: Add this to your workflow file under the job:\n\n"
                        f"  permissions:\n"
                        f"    issues: write\n"
                        f"    pull-requests: read\n\n"
                        f"If the PR is from a fork, you may need to use a Personal Access Token (PAT)\n"
                        f"instead of GITHUB_TOKEN. See ACTION_README.md for details.\n\n"
                        f"GitHub API error: {error_msg}"
                    )
                else:
                    # Log the error and try PyGithub as fallback
                    print(f"⚠️  REST API returned status {response.status_code}")
                    print(f"   Response: {response.text[:500]}")
                    print(f"   Attempting fallback to PyGithub...")
                    # Don't raise here, let it fall through to PyGithub fallback
                    raise requests.RequestException(f"REST API returned {response.status_code}: {response.text}")
                    
            except (requests.RequestException, Exception) as rest_error:
                # Fallback to PyGithub if REST API fails
                error_msg = str(rest_error)
                print(f"⚠️  REST API failed: {error_msg}")
                print(f"   Attempting fallback to PyGithub...")
                try:
                    repo = self.client.get_repo(repo_name)
                    issue = repo.get_issue(pr_number)
                    print(f"   Creating comment via PyGithub on issue #{pr_number}...")
                    comment = issue.create_comment(comment_body)
                    print(f"✅ Comment posted successfully via PyGithub!")
                    print(f"   Comment ID: {comment.id}")
                    print(f"   Comment URL: {comment.html_url}")
                    print(f"   PR #{pr_number} in {repo_name}")
                    print(f"   View PR: https://github.com/{repo_name}/pull/{pr_number}")
                    return
                except Exception as pygithub_error:
                    # If both fail, raise a comprehensive error
                    print(f"❌ Both REST API and PyGithub failed!")
                    print(f"   REST API error: {error_msg}")
                    print(f"   PyGithub error: {str(pygithub_error)}")
                    raise Exception(
                        f"Failed to post comment using both methods.\n"
                        f"REST API error: {error_msg}\n"
                        f"PyGithub error: {str(pygithub_error)}"
                    )

        except Exception as e:
            error_msg = str(e)
            # Provide helpful error message for 403 errors
            if "403" in error_msg or "Resource not accessible by integration" in error_msg or "Permission denied" in error_msg:
                # Error message already includes helpful info, just re-raise
                raise
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
