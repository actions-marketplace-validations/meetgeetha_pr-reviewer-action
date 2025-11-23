# AI PR Reviewer - GitHub Action

Automated code review using GPT-4 with RAG-enhanced context for smarter, more consistent reviews.

## Features

- 🤖 **AI-Powered Reviews**: Uses GPT-4 for intelligent code analysis
- 🧠 **RAG Enhancement**: Learns from past reviews and best practices
- 🔍 **Comprehensive Analysis**: Checks for bugs, security, performance, and style
- 📊 **Detailed Feedback**: Provides actionable suggestions with severity levels
- ⚡ **Fast**: ~70ms overhead with local embeddings

## Usage

Add to your repository's `.github/workflows/pr-review.yml`:

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
        uses: yourusername/pr-reviewer-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

## Setup

1. Get an OpenAI API key from https://platform.openai.com/api-keys
2. Add it to your repository secrets as `OPENAI_API_KEY`
3. Add the workflow file above (make sure to include the `permissions` block!)
4. Create a PR and watch the magic happen! ✨

**Important**: The `permissions` block is required for the action to post comments on PRs. Without it, you'll get a 403 "Resource not accessible by integration" error.

## Troubleshooting

### 403 Forbidden Error

If you're getting a 403 error when the action tries to post comments:

1. **Check your workflow file has permissions**: Make sure your workflow includes the `permissions` block as shown in the example above.

2. **Verify the permissions are correct**: The job needs:
   ```yaml
   permissions:
     issues: write
     pull-requests: read
   ```

3. **Fork PRs**: If the PR is from a fork, `GITHUB_TOKEN` has limited permissions. You may need to use a Personal Access Token (PAT) with `repo` scope instead:
   ```yaml
   - name: AI PR Review
     uses: yourusername/pr-reviewer-action@v1
     with:
       openai_api_key: ${{ secrets.OPENAI_API_KEY }}
       github_token: ${{ secrets.PAT_TOKEN }}  # Use PAT instead of GITHUB_TOKEN
   ```

4. **Repository settings**: Check that your repository allows GitHub Actions to write to issues/comments in Settings → Actions → General → Workflow permissions.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `openai_api_key` | Yes | - | OpenAI API key for GPT-4 |
| `github_token` | No | `${{ github.token }}` | GitHub token for API access |
| `openai_model` | No | `gpt-4-turbo-preview` | OpenAI model to use |

## Example Review Output

The action will post a comment on your PR with:

- **Overall Score**: Code quality rating
- **Issues Found**: Categorized by severity (high/medium/low)
- **Suggestions**: Actionable improvements
- **AI Summary**: High-level review insights

## Self-Hosting

Want to run your own instance? You can build and run the Docker container locally:

```bash
docker build -f Dockerfile.action -t pr-reviewer-action .
docker run -e OPENAI_API_KEY=your-key -e GITHUB_TOKEN=your-token pr-reviewer-action
```

## License

MIT
