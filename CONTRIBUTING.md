# Contributing to toVerify

Thank you for your interest in contributing!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/utkarsh/toVerify.git
cd toVerify

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
pytest --cov=toVerify  # with coverage
```

## Code Style

This project uses [ruff](https://github.com/astral-sh/ruff) for linting:

```bash
ruff check src/
ruff format src/
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting
5. Commit with conventional commit messages (`feat:`, `fix:`, `docs:`, etc.)
6. Push and open a PR

## Reporting Issues

Please include:
- Linux distribution and version
- Python version
- strace version
- Steps to reproduce
- Expected vs actual behavior
