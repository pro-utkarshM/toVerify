# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-14

### Added
- **Learning mode** (`--learn N`): Run command N times and merge profiles for stability
- **Profile inheritance** (`extends:`): Profiles can inherit from parent profiles
- **Validation command** (`--validate`): Check profile syntax without running commands
- **Diff command** (`--diff`): Compare two profiles and show differences
- **Dry-run mode** (`--dry-run`): Report all violations without terminating
- **Verbosity flags** (`--verbose`, `--quiet`): Control output detail level
- Extended syscall coverage: 24 new syscalls including `accept4`, `openat2`, `faccessat2`
- Comprehensive unit tests for core and parser modules (41 tests)

### Changed
- Restructured repository to use `src/` layout
- Moved tests to root `tests/` directory
- Updated `pyproject.toml` with modern Python packaging standards

### Fixed
- Improved error handling for missing strace and invalid profiles
- Added timeout support to prevent hanging on long-running commands

## [0.1.0] - 2026-01-13

### Added
- Initial implementation of profile and verify modes
- Real-time strace monitoring with process termination on violation
- YAML-based behavior profiles
- Basic strace parser for syscalls, file access, and network detection
