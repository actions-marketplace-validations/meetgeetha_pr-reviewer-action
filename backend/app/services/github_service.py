"""
Service for handling GitHub operations
"""
import os
import requests
from github import Github
from typing import Dict, List, Any, Tuple, Optional
import re


class GitHubService:
    """Handle GitHub API operations"""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        self.client = Github(self.token) if self.token else None
    
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

    def post_review_comments(self, pr_data: Dict, review_result: Dict, use_inline: bool = True) -> None:
        """
        Post review comments to a pull request
        
        Args:
            pr_data: Pull request data from webhook
            review_result: Analysis results from LLM
            use_inline: If True, post as inline review comments. If False, post as issue comment
                       Inline comments require 'pull-requests: write' permission
                       Issue comments require 'issues: write' permission
        """
        try:
            repo_name = pr_data["base"]["repo"]["full_name"]
            pr_number = pr_data["number"]
            
            print(f"📝 Preparing to post review comment...")
            print(f"   Repository: {repo_name}")
            print(f"   PR Number: {pr_number}")
            print(f"   Mode: {'Inline comments' if use_inline else 'General comment'}")
            
            # Verify PR number matches what we expect
            actual_pr_number = pr_data.get("number", pr_number)
            if actual_pr_number != pr_number:
                print(f"⚠️  Warning: PR number mismatch. Using {actual_pr_number} from PR data (expected {pr_number})")
                pr_number = actual_pr_number  # Use the actual PR number from the data

            # Try inline comments first (preferred method)
            if use_inline:
                try:
                    self.post_inline_review_comments(pr_data, review_result)
                    return  # Success!
                except Exception as inline_error:
                    error_msg = str(inline_error)
                    if "403" in error_msg or "Permission denied" in error_msg:
                        print(f"⚠️  Inline comments failed due to permissions: {error_msg}")
                        print(f"   Falling back to general comment...")
                        # Fall through to issue comment below
                    else:
                        print(f"⚠️  Inline comments failed: {error_msg}")
                        print(f"   Falling back to general comment...")
                        # Fall through to issue comment below

            # Fallback to issue comment
            print(f"   Using issue comment fallback...")

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

    def _parse_diff_ranges(self, diff_data: Dict[str, Any]) -> Dict[str, List[tuple]]:
        """
        Parse PR diff to find valid line ranges for comments.
        Returns a dict mapping filename -> list of (start_line, end_line) tuples
        """
        valid_ranges = {}
        
        for file in diff_data.get("files", []):
            filename = file.get("filename")
            patch = file.get("patch", "")
            if not filename or not patch:
                continue
                
            ranges = []
            # Parse hunks: @@ -original,count +new,count @@
            # We only care about the new line numbers (the one with +)
            # Regex captures start_line and optional count
            hunk_headers = re.finditer(r'@@\s*-[0-9,]+\s*\+(\d+)(?:,(\d+))?\s*@@', patch)
            
            for match in hunk_headers:
                start_line = int(match.group(1))
                # If count is missing, it defaults to 1
                count = int(match.group(2)) if match.group(2) else 1
                
                # The valid range covers these lines
                end_line = start_line + count - 1
                ranges.append((start_line, end_line))
                
            if ranges:
                valid_ranges[filename] = ranges
                
        return valid_ranges

    def post_inline_review_comments(self, pr_data: Dict, review_result: Dict) -> None:
        """
        Post inline review comments using GitHub's PR Review API
        This creates actual line-level comments on the PR code changes
        Requires 'pull-requests: write' permission in the workflow

        Args:
            pr_data: Pull request data from webhook
            review_result: Analysis results from LLM
        """
        try:
            repo_name = pr_data["base"]["repo"]["full_name"]
            pr_number = pr_data["number"]
            
            print(f"📝 Preparing to post inline review comments...")
            print(f"   Repository: {repo_name}")
            print(f"   PR Number: {pr_number}")
            
            # 1. Fetch Diff Data to validate lines
            valid_ranges = {}
            try:
                diff_data = self.get_pr_diff(pr_data)
                valid_ranges = self._parse_diff_ranges(diff_data)
                print(f"   Valid line ranges loaded for {len(valid_ranges)} files")
            except Exception as e:
                print(f"⚠️ Warning: Could not parse diff for line validation: {e}")
                print("   Will try to post comments but they might fail if lines are outside diff.")

            # 2. Create inline comments (split into valid and skipped)
            inline_comments, skipped_comments = self._create_inline_comments(review_result, valid_ranges)
            
            # Debug: Show what we have in review_result
            print(f"   Debug: file_issues count: {len(review_result.get('file_issues', []))}")
            print(f"   Debug: general issues count: {len(review_result.get('issues', []))}")
            
            if not inline_comments and not skipped_comments:
                print("⚠️  No inline comments to post")
            
            print(f"   Found {len(inline_comments)} valid inline comments to post")
            print(f"   Skipped {len(skipped_comments)} comments (outside diff context) - moving to summary")
            
            for i, comment in enumerate(inline_comments):
                print(f"   Comment {i+1}: {comment['path']} line {comment['line']}")

            # 3. Create review body with summary (including skipped comments)
            review_body = self._create_review_summary(review_result, skipped_comments)
            
            owner, repo = repo_name.split("/")
            api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
            
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "PR-Reviewer-Action"
            }
            
            review_data = {
                "body": review_body,
                "event": "COMMENT",  # Options: APPROVE, REQUEST_CHANGES, COMMENT
                "comments": inline_comments
            }
            
            print(f"   API URL: {api_url}")
            print(f"   Review body length: {len(review_body)} characters")
            
            response = requests.post(
                api_url,
                json=review_data,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                response_data = response.json()
                review_id = response_data.get("id", "N/A")
                review_url = response_data.get("html_url", "N/A")
                print(f"✅ Inline review posted successfully!")
                print(f"   Review ID: {review_id}")
                print(f"   Review URL: {review_url}")
                print(f"   PR #{pr_number} in {repo_name}")
                print(f"   View PR: https://github.com/{repo_name}/pull/{pr_number}")
                
            elif response.status_code == 422:
                # Validation error - often means line numbers are invalid
                error_data = response.json() if response.text else {}
                error_msg = error_data.get("message", "Unprocessable Entity")
                print(f"❌ GitHub API validation error (422): {error_msg}")
                # Try to extract which comment failed
                errors = error_data.get("errors", [])
                for error in errors:
                    print(f"   Error detail: {error}")
                
                raise Exception(f"GitHub API validation error: {error_msg}")
                
            elif response.status_code == 403:
                error_data = response.json() if response.text else {}
                error_msg = error_data.get("message", "Forbidden")
                raise Exception(
                    f"Permission denied (403): Unable to post inline review on PR #{pr_number}.\n"
                    f"GitHub API error: {error_msg}"
                )
            else:
                error_text = response.text[:500]
                print(f"❌ Failed to post inline review")
                print(f"   Status code: {response.status_code}")
                # If we have 0 valid comments but some skipped, we might have sent an empty comments list
                # which is allowed, but maybe validation failed on body?
                raise Exception(f"Failed to post inline review: HTTP {response.status_code} - {error_text}")
                
        except Exception as e:
            error_msg = str(e)
            if "403" in error_msg or "Resource not accessible by integration" in error_msg or "Permission denied" in error_msg:
                raise
            raise Exception(f"Error posting inline review comments: {error_msg}")
    
    def _create_review_summary(self, review_result: Dict, skipped_comments: List[Dict] = None) -> str:
        """
        Create a concise review summary for the PR review body
        """
        summary = "## 🤖 AI Code Review\n\n"
        
        # Overall summary
        if review_result.get("summary"):
            summary += f"{review_result['summary']}\n\n"
        
        # Quick stats
        issues_count = len(review_result.get("issues", []))
        file_issues_count = len(review_result.get("file_issues", []))
        suggestions_count = len(review_result.get("suggestions", []))
        
        if issues_count > 0 or file_issues_count > 0 or suggestions_count > 0:
            summary += "### 📊 Review Summary\n\n"
            if issues_count > 0:
                summary += f"- 🐛 **{issues_count}** general issues found\n"
            if file_issues_count > 0:
                summary += f"- 📍 **{file_issues_count}** line-specific comments below\n"
            if suggestions_count > 0:
                summary += f"- 💡 **{suggestions_count}** suggestions for improvement\n"
            summary += "\n"
        
        # Overall score
        score = review_result.get("overall_score", 0)
        if score > 0:
            if score >= 85:
                emoji = "✅"
                status = "Great job!"
            elif score >= 70:
                emoji = "🟡"
                status = "Good work with room for improvement"
            else:
                emoji = "🔴"
                status = "Needs attention"
            
            summary += f"### {emoji} Overall Score: {score}/100\n{status}\n\n"
        
        # skipped comments section
        if skipped_comments:
            summary += "### ⚠️ Comments on Unchanged Lines & Context\n\n"
            summary += "The following issues were found but could not be posted inline because they are outside the PR diff context:\n\n"
            
            for comment in skipped_comments:
                path = comment.get("path", "unknown")
                line = comment.get("line", "?")
                body = comment.get("body", "").replace("\n", " ") 
                # truncate body if too long
                if len(body) > 100:
                    body = body[:100] + "..."
                
                summary += f"**`{path}`:{line}**\n"
                summary += f"> {body}\n\n"

        summary += "*📍 Check the inline comments below for specific feedback on individual lines.*"
        
        return summary

    def _create_inline_comments(self, review_result: Dict, valid_ranges: Dict[str, List[tuple]]) -> Tuple[List[Dict], List[Dict]]:
        """
        Create inline comments for specific lines from review results.
        Returns: (valid_comments, skipped_comments)
        """
        valid_comments = []
        skipped_comments = []

        # Combine all possible line-oriented issues
        all_issues = []
        # 1. Explicit file issues
        all_issues.extend(review_result.get("file_issues", []))
        # 2. General issues that have file/line data
        all_issues.extend([i for i in review_result.get("issues", []) if i.get("line") and i.get("file")])

        # Track uniqueness to prevent duplicates
        processed_locations = set()

        for issue in all_issues:
            file_path = issue.get("file")
            line_str = issue.get("line")
            message = issue.get("message", "")
            
            if not file_path or not line_str:
                continue

            try:
                line_num = int(line_str)
            except (ValueError, TypeError):
                continue

            # Avoid duplicates
            location_key = f"{file_path}:{line_num}"
            if location_key in processed_locations:
                continue
            processed_locations.add(location_key)

            # Build comment content
            severity = issue.get("severity", "info").upper()
            emoji = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
            comment_body = f"{emoji} **{severity}**: {message}"
            
            if issue.get("suggestion"):
                comment_body += f"\n\n💡 **Suggestion**: {issue['suggestion']}"
            if issue.get("category"):
                comment_body += f"\n\n🏷️ **Category**: {issue['category']}"

            comment_data = {
                "path": file_path,
                "body": comment_body,
                "line": line_num
            }

            # VALIDATION LOGIC
            is_valid = False
            # If we have validation data, check it
            if valid_ranges:
                ranges = valid_ranges.get(file_path, [])
                # Check if line_num is in any of the ranges
                for start, end in ranges:
                    if start <= line_num <= end:
                        is_valid = True
                        break
            else:
                # If we failed to get ranges (e.g. diff fetch error), we have two choices:
                # 1. Be optimistic and try to post everything (risks 422 error)
                # 2. Be safe and skip everything (moves to summary)
                # We'll choose Option 2 for safety if we strictly failed fast,
                # BUT if valid_ranges is empty because the dict was empty (no changes?),
                # then it's definitely invalid.
                # However, if valid_ranges dict is EMPTY but we have files, it implies no valid ranges found.
                is_valid = False 

            if is_valid:
                valid_comments.append(comment_data)
            else:
                skipped_comments.append(comment_data)

        return valid_comments, skipped_comments
    
    def _format_review_comment(self, review_result: Dict, include_inline: bool = False) -> str:
        """Format the review result into a markdown comment"""
        comment = "## 🤖 Automated Code Review\n\n"

        if review_result.get("summary"):
            comment += f"### Summary\n{review_result['summary']}\n\n"

        # Overall score
        score = review_result.get("overall_score", 0)
        if score > 0:
            if score >= 85:
                emoji = "✅"
                status = "Great job!"
            elif score >= 70:
                emoji = "🟡"
                status = "Good work with room for improvement"
            else:
                emoji = "🔴"
                status = "Needs attention"
            comment += f"### {emoji} Overall Score: {score}/100\n{status}\n\n"

        # General issues
        if review_result.get("issues"):
            comment += "### Issues Found\n\n"
            for issue in review_result["issues"]:
                severity = issue.get("severity", "info").upper()
                emoji = (
                    "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
                )
                comment += f"{emoji} **{severity}**: {issue.get('message')}\n"
                if issue.get("file"):
                    comment += f"   - Location: `{issue.get('file')}"
                    if issue.get("line"):
                        comment += f":{issue.get('line')}"
                    comment += "`\n"
                if issue.get("suggestion"):
                    comment += f"   - 💡 Suggestion: {issue.get('suggestion')}\n"
            comment += "\n"

        # File-specific issues (if not using inline comments)
        if not include_inline and review_result.get("file_issues"):
            comment += "### File-Specific Issues\n\n"
            for issue in review_result["file_issues"]:
                severity = issue.get("severity", "info").upper()
                emoji = (
                    "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
                )
                file_path = issue.get("file", "unknown")
                line = issue.get("line", "?")
                comment += f"{emoji} **{severity}** in `{file_path}:{line}`\n"
                comment += f"   {issue.get('message')}\n"
                if issue.get("suggestion"):
                    comment += f"   💡 Suggestion: {issue.get('suggestion')}\n"
            comment += "\n"

        # Suggestions
        if review_result.get("suggestions"):
            comment += "### Suggestions\n\n"
            for suggestion in review_result["suggestions"]:
                comment += f"- {suggestion}\n"
            comment += "\n"

        comment += (
            "\n---\n*This review was generated automatically by the PR Reviewer Bot*"
        )

        return comment
