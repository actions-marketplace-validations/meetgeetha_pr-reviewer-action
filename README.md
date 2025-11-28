# AI PR Reviewer - GitHub Action

<div align="center">

![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Ready-blue?logo=github-actions)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.11-blue?logo=python)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4-orange)

**Automated code review using GPT-4 with RAG-enhanced context for smarter, more consistent reviews.**

[Features](#-features) • [Quick Start](#-quick-start) • [Usage](#-usage) • [Configuration](#-configuration) • [How It Works](#-how-it-works) • [Development](#-development)

</div>

---

## 🤖 Features

- **AI-Powered Reviews**: Uses GPT-4 for intelligent code analysis and suggestions
- **RAG Enhancement**: Learns from past reviews and best practices using Retrieval-Augmented Generation
- **Comprehensive Analysis**: Checks for bugs, security vulnerabilities, performance issues, and code style
- **Detailed Feedback**: Provides actionable suggestions with severity levels (High/Medium/Low)
- **Fast Performance**: ~70ms overhead with local embeddings for RAG context
- **Multi-Language Support**: Works with Python, JavaScript, TypeScript, Java, Go, Rust, and more
- **GitHub & GitLab**: Supports both GitHub and GitLab platforms
- **Customizable**: Configurable review depth and model selection

## 🚀 Quick Start

### 1. Get Your OpenAI API Key

1. Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. Create a new API key
3. Copy the key (starts with `sk-`)

### 2. Add the Workflow

Create `.github/workflows/pr-review.yml` in your repository:

```yaml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - name: Checkout PR code
        uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          fetch-depth: 0
      
      - name: AI PR Review
        uses: meetgeetha/pr-reviewer-action@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_model: gpt-4-turbo-preview

```

### 3. Add Your API Key to Secrets

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `OPENAI_API_KEY`
4. Value: Your OpenAI API key
5. Click **Add secret**

### 4. Create a Pull Request

That's it! The action will automatically review your PR and post comments with detailed feedback.

**Note**: The `permissions` block in the workflow is required for the action to post comments. Without it, you'll get a 403 "Resource not accessible by integration" error.

## 📖 Usage

The action runs automatically on pull requests. Make sure to include the required permissions:

```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      issues: write
      pull-requests: read
    steps:
      - uses: meetgeetha/pr-reviewer-action@main
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}  # Optional, defaults to GITHUB_TOKEN
          openai_model: gpt-4-turbo-preview          # Optional, choose your model
```

### Supported Models

- `gpt-4-turbo-preview` (default) - Best quality, recommended
- `gpt-4` - High quality, slower
- `gpt-3.5-turbo` - Faster, lower cost, good for simple reviews

## ⚙️ Configuration

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `openai_api_key` | ✅ Yes | - | Your OpenAI API key |
| `github_token` | ❌ No | `${{ github.token }}` | GitHub token for API access |
| `openai_model` | ❌ No | `gpt-4-turbo-preview` | OpenAI model to use |

### Workflow Triggers

The action runs on these pull request events:
- `opened` - When a PR is first created
- `synchronize` - When new commits are pushed
- `reopened` - When a closed PR is reopened

## 🔍 How It Works

### Review Process

1. **PR Detection**: Action triggers on pull request events
2. **Code Analysis**: Fetches PR diff and analyzes changed files
3. **RAG Context**: Retrieves relevant best practices and past review patterns
4. **AI Review**: GPT-4 analyzes code with context-aware suggestions
5. **Comment Posting**: Posts detailed review comments on the PR

### RAG (Retrieval-Augmented Generation)

The action uses RAG to enhance reviews with:
- **Best Practices**: Pre-seeded knowledge base with coding best practices
- **Context Awareness**: Retrieves relevant patterns based on code changes
- **Consistency**: Learns from past reviews to maintain consistent feedback

### Review Categories

The action checks for:

- 🐛 **Bugs**: Logic errors, edge cases, potential runtime issues
- 🔒 **Security**: Vulnerabilities, injection risks, authentication issues
- ⚡ **Performance**: Optimization opportunities, inefficient patterns
- 📝 **Code Style**: Formatting, naming conventions, code organization
- 🏗️ **Architecture**: Design patterns, code structure, maintainability
- 📚 **Documentation**: Missing comments, unclear code, API documentation

## 📊 Example Review Output

The action posts a comprehensive review comment on your PR:

```markdown
## 🤖 Automated Code Review

### Summary
This PR introduces a new authentication module with JWT support. 
Overall code quality is good, but there are a few security concerns 
that should be addressed.

### Issues Found

🔴 **HIGH**: JWT secret is hardcoded in the code
   - Location: `auth/jwt_handler.py:42`
   - Risk: Security vulnerability
   - Suggestion: Move to environment variables

🟡 **MEDIUM**: Missing input validation for user credentials
   - Location: `auth/login.py:15`
   - Suggestion: Add validation for email format and password strength

🔵 **LOW**: Function could be simplified
   - Location: `auth/utils.py:78`
   - Suggestion: Extract repeated logic into helper function

### Suggestions
- Consider using rate limiting for login endpoints
- Add unit tests for authentication flow
- Document JWT token expiration policy

---
*This review was generated automatically by the PR Reviewer Bot*
```

## 🏗️ Architecture

### Components

- **Action Entrypoint** (`action-entrypoint.sh`): Main execution script
- **GitHub Service**: Handles GitHub API interactions
- **Review Service**: Core review logic and analysis
- **RAG Service**: Retrieval-augmented generation for context
- **LLM Service**: OpenAI API integration
- **Docker Container**: Isolated execution environment

### Technology Stack

- **Python 3.11**: Core language
- **OpenAI GPT-4**: AI model for code analysis
- **ChromaDB**: Vector database for RAG
- **LangChain**: LLM orchestration framework
- **PyGithub**: GitHub API client
- **Docker**: Containerization

## 🛠️ Development

### Prerequisites

- Python 3.11+
- Docker
- OpenAI API key
- GitHub token

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/meetgeetha/pr-reviewer-action.git
   cd pr-reviewer-action
   ```

2. **Set up environment**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Initialize RAG knowledge base**
   ```bash
   python init_rag.py
   ```

5. **Run tests**
   ```bash
   pytest tests/
   ```

### Testing with Act

For local testing of the GitHub Action:

```bash
# Install act: https://github.com/nektos/act#installation
# Windows: winget install nektos.act
# Mac: brew install act
# Linux: See act installation guide

act pull_request -W .github/workflows/test-action.yml \
  -s OPENAI_API_KEY=your-key \
  -s GITHUB_TOKEN=your-token
```

**Note**: For Windows users, use WSL for best compatibility. The action runs in a Docker container, so Docker must be running.

### Building the Docker Image

```bash
docker build -f Dockerfile.action -t pr-reviewer-action .
```

## 📁 Project Structure

```
pr-reviewer-action/
├── action.yml                 # Action metadata
├── action-entrypoint.sh       # Entrypoint script
├── Dockerfile.action          # Docker image definition
├── backend/                   # Backend application
│   ├── app/
│   │   ├── services/         # Core services
│   │   │   ├── github_service.py
│   │   │   ├── review_service.py
│   │   │   ├── rag_service.py
│   │   │   └── llm_service.py
│   │   └── api/             # API routes
│   ├── config/              # Configuration
│   ├── data/                # RAG knowledge base
│   └── tests/               # Test suite
├── .github/
│   └── workflows/
│       └── test-action.yml  # Test workflow
└── README.md               # This file
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [OpenAI GPT-4](https://openai.com/)
- Uses [LangChain](https://www.langchain.com/) for LLM orchestration
- Powered by [ChromaDB](https://www.trychroma.com/) for vector storage
- Inspired by the need for better automated code reviews

## 📚 Additional Resources

- [Action README](./ACTION_README.md) - Quick reference for action usage
- [OpenAI Documentation](https://platform.openai.com/docs)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/meetgeetha/pr-reviewer-action/issues)
- **Discussions**: [GitHub Discussions](https://github.com/meetgeetha/pr-reviewer-action/discussions)

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

---

<div align="center">

**Made with ❤️ by [Geethakrishnan Balasubramanian](https://github.com/meetgeetha)**

[Report Bug](https://github.com/meetgeetha/pr-reviewer-action/issues) • [Request Feature](https://github.com/meetgeetha/pr-reviewer-action/issues)

</div>
