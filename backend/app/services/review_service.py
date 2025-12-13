"""Service layer for orchestrating code reviews."""

from typing import Dict, Any, List, Optional
from datetime import datetime

from app.services.llm_service import LLMService
from app import mongo


class ReviewService:
    """Handle code review operations"""

    def __init__(self, rag_service=None):
        self._llm_service: LLMService | None = None
        self._rag_service = rag_service

    @property
    def llm_service(self) -> LLMService:
        """Lazily initialize the LLM service to avoid unnecessary startup work."""
        if self._llm_service is None:
            self._llm_service = LLMService(rag_service=self._rag_service)
        return self._llm_service

    @llm_service.setter
    def llm_service(self, value: LLMService) -> None:
        """Allow tests to inject a mocked LLM service instance."""
        self._llm_service = value

    @property
    def rag_service(self):
        """Get RAG service instance"""
        return self._rag_service

    @rag_service.setter
    def rag_service(self, value) -> None:
        """Set RAG service and update LLM service"""
        self._rag_service = value
        if self._llm_service:
            self._llm_service.rag_service = value

    def analyze_code(self, diff_data: Dict) -> Dict[str, Any]:
        """
        Analyze code changes using LLM

        Args:
            diff_data: Dictionary containing PR/MR diff information

        Returns:
            Dictionary containing review results
        """
        try:
            review_result = {
                "pr_number": diff_data.get("pr_number", diff_data.get("mr_number")),
                "repository": diff_data.get("repository"),
                "timestamp": datetime.utcnow(),
                "summary": "",
                "issues": [],
                "suggestions": [],
                "file_issues": [],
                "overall_score": 0,
            }

            # Analyze each file
            for file_data in diff_data.get("files", []):
                file_analysis = self._analyze_file(file_data)

                if file_analysis.get("issues"):
                    review_result["issues"].extend(file_analysis["issues"])

                if file_analysis.get("suggestions"):
                    review_result["suggestions"].extend(file_analysis["suggestions"])

                if file_analysis.get("file_issues"):
                    review_result["file_issues"].extend(file_analysis["file_issues"])

            # Generate overall summary
            review_result["summary"] = self._generate_summary(review_result, diff_data)

            # Calculate overall score (0-100)
            review_result["overall_score"] = self._calculate_score(review_result)

            # Save review to database
            self._save_review(review_result)

            return review_result

        except Exception as e:
            raise Exception(f"Error analyzing code: {str(e)}")

    def analyze_code_snippet(self, code: str, language: str) -> Dict[str, Any]:
        """
        Analyze a code snippet

        Args:
            code: Code snippet to analyze
            language: Programming language

        Returns:
            Dictionary containing analysis results
        """
        try:
            file_data = {
                "filename": f"snippet.{language}",
                "patch": code,
                "language": language,
            }

            analysis = self._analyze_file(file_data)

            review_record = {
                "pr_number": None,
                "repository": "manual-snippet",
                "timestamp": datetime.utcnow(),
                "summary": "",
                "issues": analysis.get("issues", []),
                "suggestions": analysis.get("suggestions", []),
                "file_issues": analysis.get("file_issues", []),
                "overall_score": self._calculate_score(analysis),
                "source": "manual_snippet",
                "metadata": {
                    "language": language,
                    "filename": file_data["filename"],
                },
            }

            diff_context = {
                "title": f"Manual snippet review ({file_data['filename']})",
                "description": code[:200],
                "files": [file_data],
            }

            review_record["summary"] = self._generate_summary(
                review_record, diff_context
            )

            self._save_review(review_record)

            return self._serialize_review(review_record)

        except Exception as e:
            raise Exception(f"Error analyzing code snippet: {str(e)}")

    def _analyze_file(self, file_data: Dict) -> Dict[str, Any]:
        """Analyze a single file using LLM"""
        filename = file_data.get("filename")
        patch = file_data.get("patch") or file_data.get("diff")
        language = file_data.get("language")

        if not patch:
            return {}

        # Use LLM to analyze the code
        analysis = self.llm_service.analyze_code_changes(
            code=patch, filename=filename, language=language
        )

        # Debug: Show what LLM returned
        print(f"   Debug LLM analysis for {filename}: {len(analysis.get('issues', []))} total issues")
        
        # Separate issues with line numbers from general issues
        general_issues = []
        file_issues = []
        
        for i, issue in enumerate(analysis.get("issues", [])):
            has_line = bool(issue.get("line"))
            has_file = bool(issue.get("file"))
            print(f"   Debug issue {i+1}: line={issue.get('line')}, file={issue.get('file')}, has_line={has_line}, has_file={has_file}")
            
            if issue.get("line") and issue.get("file"):
                # This is a line-specific issue
                file_issues.append(issue)
                print(f"   -> Added to file_issues")
            else:
                # Try to infer line numbers from diff context for critical issues
                if issue.get("severity") in ["high", "critical"] and not issue.get("line"):
                    inferred_line = self._try_infer_line_from_patch(patch, issue.get("message", ""))
                    if inferred_line:
                        issue["line"] = inferred_line
                        issue["file"] = filename
                        file_issues.append(issue)
                        print(f"   -> Inferred line {inferred_line}, added to file_issues")
                        continue
                
                # This is a general issue for the file
                general_issues.append(issue)
                print(f"   -> Added to general_issues")
        
        print(f"   Debug result: {len(general_issues)} general, {len(file_issues)} file-specific issues")
        
        # Aggressive fallback: If no file_issues but have general issues, try to convert them
        if len(file_issues) == 0 and len(general_issues) > 0:
            print("   No file_issues found, attempting to convert general issues to file_issues")
            promoted_issues = []
            remaining_general = []
            
            for issue in general_issues:
                # Try to infer line number for high/medium severity issues
                if issue.get("severity") in ["high", "medium"]:
                    inferred_line = self._try_infer_line_from_patch(patch, issue.get("message", ""))
                    if inferred_line:
                        issue["line"] = inferred_line
                        issue["file"] = filename
                        promoted_issues.append(issue)
                        print(f"   -> Promoted general issue to file_issue at line {inferred_line}")
                        continue
                
                remaining_general.append(issue)
            
            # Update the lists
            general_issues = remaining_general
            file_issues = promoted_issues
            print(f"   After promotion: {len(general_issues)} general, {len(file_issues)} file-specific issues")
        
        return {
            "issues": general_issues,
            "file_issues": file_issues,
            "suggestions": analysis.get("suggestions", [])
        }

    def _generate_summary(self, review_result: Dict, diff_data: Dict) -> str:
        """Generate overall review summary using LLM"""
        context = {
            "title": diff_data.get("title"),
            "description": diff_data.get("description"),
            "files_changed": len(diff_data.get("files", [])),
            "total_issues": len(review_result.get("issues", [])),
            "total_suggestions": len(review_result.get("suggestions", [])),
        }

        return self.llm_service.generate_summary(context, review_result)

    def _try_infer_line_from_patch(self, patch: str, issue_message: str) -> Optional[int]:
        """
        Try to infer line number from patch context for critical issues
        This is a fallback when LLM doesn't provide line numbers
        Returns a line number that should exist in the new version of the file
        """
        if not patch or not issue_message:
            return None
        
        print(f"   Analyzing patch for issue '{issue_message[:50]}...'")
        print(f"   Patch sample: {patch[:200]}...")
        
        import re
        
        # Look for @@ -X,Y +A,B @@ headers to find line numbers
        hunk_matches = re.findall(r'@@\s*-\d+(?:,\d+)?\s*\+(\d+)(?:,\d+)?\s*@@', patch)
        if not hunk_matches:
            return None
        
        try:
            # Get all hunks and their starting line numbers
            lines = patch.split('\n')
            current_new_line = None
            added_lines = []
            
            for line in lines:
                # Track hunk headers
                hunk_match = re.match(r'@@\s*-\d+(?:,\d+)?\s*\+(\d+)(?:,\d+)?\s*@@', line)
                if hunk_match:
                    current_new_line = int(hunk_match.group(1))
                    continue
                
                if current_new_line is not None:
                    if line.startswith('+') and not line.startswith('+++'):
                        # This is an added line
                        added_lines.append(current_new_line)
                        current_new_line += 1
                    elif line.startswith('-'):
                        # Deleted line - don't increment new line counter
                        continue
                    elif line.startswith(' '):
                        # Context line - increment new line counter
                        current_new_line += 1
            
            # Return the first added line if we have any
            if added_lines:
                print(f"   Found {len(added_lines)} added lines: {added_lines[:5]}...")
                # Return middle line if we have multiple, otherwise first
                if len(added_lines) > 2:
                    return added_lines[len(added_lines) // 2]
                return added_lines[0]
            
            # If no added lines found, try to return a reasonable line number
            if hunk_matches:
                return int(hunk_matches[0])
            
            return None
            
        except (ValueError, IndexError) as e:
            print(f"   Error inferring line number: {e}")
            return None

    def _calculate_score(self, review_result: Dict) -> int:
        """Calculate overall code quality score"""
        issues = review_result.get("issues", [])

        # Start with perfect score
        score = 100

        # Deduct points based on severity
        for issue in issues:
            severity = issue.get("severity", "low").lower()
            if severity == "high":
                score -= 15
            elif severity == "medium":
                score -= 10
            else:
                score -= 5

        # Ensure score is between 0 and 100
        return max(0, min(100, score))

    def _save_review(self, review_data: Dict) -> None:
        """Save review to database and add to RAG knowledge base"""
        try:
            if hasattr(mongo, "db") and mongo.db is not None:
                mongo.db.reviews.insert_one(review_data)
                
                # Add to RAG knowledge base for future context
                if self._rag_service:
                    try:
                        self._rag_service.add_review_to_knowledge_base(review_data)
                    except Exception as e:
                        print(f"Warning: Could not add to RAG knowledge base: {str(e)}")
        except (AttributeError, RuntimeError) as e:
            print(f"Warning: MongoDB not available: {str(e)}")
        except Exception as e:
            print(f"Warning: Could not save review to database: {str(e)}")

    def get_all_reviews(self, limit: int = 50) -> List[Dict]:
        """Get all reviews from database"""
        try:
            # Check if mongo is initialized and has a database connection
            if hasattr(mongo, "db") and mongo.db is not None:
                reviews = mongo.db.reviews.find().sort("timestamp", -1).limit(limit)
                return [self._serialize_review(r) for r in reviews]
            return []
        except (AttributeError, RuntimeError) as e:
            # Handle case where mongo is not initialized or no app context
            print(f"Warning: MongoDB not available: {str(e)}")
            return []
        except Exception as e:
            # Return empty list instead of raising exception when DB is not available
            print(f"Warning: Could not retrieve reviews: {str(e)}")
            return []

    def get_review_by_id(self, review_id: str) -> Dict:
        """Get a specific review by ID"""
        try:
            if hasattr(mongo, "db") and mongo.db is not None:
                from bson.objectid import ObjectId

                review = mongo.db.reviews.find_one({"_id": ObjectId(review_id)})
                return self._serialize_review(review) if review else None
            return None
        except (AttributeError, RuntimeError) as e:
            # Handle case where mongo is not initialized or no app context
            print(f"Warning: MongoDB not available: {str(e)}")
            return None
        except Exception as e:
            print(f"Warning: Could not retrieve review: {str(e)}")
            return None

    def _serialize_review(self, review: Dict) -> Dict:
        """Convert MongoDB document to JSON-serializable dict"""
        if review:
            review["_id"] = str(review["_id"])
            if "timestamp" in review:
                review["timestamp"] = review["timestamp"].isoformat()
        return review
