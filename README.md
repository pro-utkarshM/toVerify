# toVerify - Trust, but Verify Your Commands

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-41%20passed-brightgreen.svg)]()

A simple, powerful tool to ensure that a command-line program does exactly what you expect—and nothing more.

## Features

- **Profile Mode**: Capture a command's syscalls, file access, and network activity
- **Verify Mode**: Enforce behavior profiles in real-time, terminate on violation
- **Learning Mode**: Run N times and merge for stable profiles (reduces false positives)
- **Diff Profiles**: Compare two profiles and see exactly what changed
- **Profile Inheritance**: Use `extends:` to inherit from base profiles
- **Validation**: Check profile syntax without running commands
- **Verbosity Control**: `--verbose` for debugging, `--quiet` for scripts

## Installation

```bash
# From source
git clone https://github.com/utkarsh/toVerify.git
cd toVerify
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

### Prerequisites

- Linux (uses `strace`)
- Python 3.8+
- `strace` installed (`sudo apt install strace`)

## Quick Start

### 1. Profile a Command

```bash
# Single run profiling
toVerify --profile "ls -l /tmp" -o ls_tmp.yaml

# Learning mode: run 5 times, merge for stability
toVerify --profile "ls -l /tmp" -o ls_tmp.yaml --learn 5
```

### 2. Verify a Command

```bash
# Strict verification (terminates on first violation)
toVerify --verify ls_tmp.yaml -c "ls -l /tmp"

# Dry-run mode (report all violations without terminating)
toVerify --verify ls_tmp.yaml -c "ls -l /tmp" --dry-run
```

### 3. Manage Profiles

```bash
# Validate profile syntax
toVerify --validate ls_tmp.yaml -v

# Compare two profiles
toVerify --diff old_profile.yaml new_profile.yaml
```

## Profile Format

```yaml
command: "ls -l /tmp"
allowed_syscalls:
  - execve
  - openat
  - read
  - write
  - close
file_access:
  read:
    - /etc/ld.so.*
    - /lib/x86_64-linux-gnu/*
    - /tmp
  write:
    - /dev/stdout
network:
  allowed: false
```

### Profile Inheritance

Create a base profile and extend it:

```yaml
# base-linux.yaml
allowed_syscalls:
  - execve
  - brk
  - mmap
  - close
file_access:
  read:
    - /etc/ld.so.*
  write: []
network:
  allowed: false
```

```yaml
# my-app.yaml
extends: base-linux.yaml
allowed_syscalls:
  - openat
  - read
file_access:
  read:
    - /my/app/config
```

## CLI Reference

```
toVerify [OPTIONS]

Modes (mutually exclusive):
  --profile CMD          Profile a command and capture behavior
  --verify PROFILE       Verify a command against a profile
  --validate PROFILE     Check profile syntax
  --diff PROF1 PROF2    Compare two profiles

Options:
  -o, --output-file FILE  Output file for profile (required with --profile)
  -c, --command CMD       Command to verify (required with --verify)
  -l, --learn N           Run N times and merge profiles
  -t, --timeout SECONDS   Execution timeout (default: 300)
  --dry-run               Report all violations without terminating
  -v, --verbose           Show detailed syscall information
  -q, --quiet             Suppress output except errors
```

## How It Works

```
┌─────────────────┐     ┌──────────────────────────┐
│ Command to Run  │ ──▶ │      toVerify            │
│ (e.g., ls -l)   │     │  Profiler / Verifier     │
└─────────────────┘     └──────────────────────────┘
                               │           ▲
                               │           │ Reads Profile
                               ▼           │
┌─────────────────┐     ┌──────────────────────────┐
│     strace      │ ──▶ │   Behavior Profile       │
│ (System Calls)  │     │   (profile.yaml)         │
└─────────────────┘     └──────────────────────────┘
```

1. `strace` intercepts syscalls from the command
2. In **Profile Mode**: syscalls are recorded into a YAML profile
3. In **Verify Mode**: syscalls are compared against the profile in real-time

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=toVerify

# Lint code
ruff check src/
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.