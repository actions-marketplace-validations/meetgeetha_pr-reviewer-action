# Troubleshooting Guide

## 403 Forbidden Error

If you're getting a `403 "Resource is not accessible by integration"` error, this means the GitHub token doesn't have the permission to post comments.

### Solution 1: Add Permissions to Your Workflow

**This is the most common fix!** Make sure your workflow file (`.github/workflows/pr-review.yml` or similar) includes the `permissions` block:

```yaml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:                    # ← THIS IS REQUIRED!
      issues: write                 # ← Allows posting comments
      pull-requests: read           # ← Allows reading PR data
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: AI PR Review
        uses: devopsgeetha/pr-reviewer-action@main
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

> **Branch selection**:
> - Stable workflow: `devopsgeetha/pr-reviewer-action@main`
> - Agentic workflow: `devopsgeetha/pr-reviewer-action@agentic_ai_v2`
>   (swap the branch reference everywhere the action appears in your workflow)

**Important**: The `permissions` block must be under the `job` (not under `steps`).

### Solution 2: Check Repository Settings

1. Go to your repository on GitHub
2. Click **Settings** → **Actions** → **General**
3. Scroll to **Workflow permissions**
4. Make sure **Read and write permissions** is selected (not "Read repository contents and packages permissions only")

### Solution 3: Forks Need Special Handling

If the PR is from a **fork** (not from the same repository), `GITHUB_TOKEN` has very limited permissions and cannot write to the base repository.

**Option A: Use a Personal Access Token (PAT)**

1. Create a Personal Access Token (PAT) with `repo` scope:
   - Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Generate new token with `repo` scope
   - Copy the token

2. Add it as a repository secret:
   - Go to your repository → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `PAT_TOKEN`
   - Value: Your PAT
   - Click "Add secret"

3. Update your workflow to use the PAT:
   ```yaml
   - name: AI PR Review
     uses: devopsgeetha/pr-reviewer-action@main
     with:
       openai_api_key: ${{ secrets.OPENAI_API_KEY }}
       github_token: ${{ secrets.PAT_TOKEN }}  # Use PAT instead
   ```

**Option B: Only run on non-fork PRs**

Add a condition to skip fork PRs:
```yaml
jobs:
  review:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    permissions:
      issues: write
      pull-requests: read
    # ... rest of workflow
```

### Solution 4: Verify Your Workflow File

Make sure you're editing the **correct workflow file**. The workflow file should be in:
- `.github/workflows/` directory
- Any `.yml` or `.yaml` file in that directory

Check that:
1. The file exists and is committed to your repository
2. The file has the correct YAML syntax (use a YAML validator)
3. The `permissions` block is at the job level (not step level)

### Common Mistakes

❌ **Wrong**: Permissions under steps
```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      permissions:  # ← WRONG LOCATION
        issues: write
```

✅ **Correct**: Permissions under job
```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:  # ← CORRECT LOCATION
      issues: write
      pull-requests: read
    steps:
      # ...
```

### Still Not Working?

1. **Check the action logs**: Look at the GitHub Actions run logs to see the exact error message
2. **Verify token is set**: The error message should show if the token is present
3. **Test with a simple workflow**: Create a minimal workflow to test permissions
4. **Check organization settings**: If this is an organization repository, check if there are organization-level restrictions on Actions

### Example Minimal Working Workflow

Here's a complete, working example:

```yaml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      issues: write
      pull-requests: read
    steps:
      - name: AI PR Review
        uses: devopsgeetha/pr-reviewer-action@main
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

> Need the agentic workflow? Replace `@main` with `@agentic_ai_v2` in the snippet above.

Save this as `.github/workflows/pr-review.yml` in your repository root.


