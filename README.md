# toVerify - Trust, but Verify Your Commands

A simple, powerful tool to ensure that a command-line program does exactly what you expect it to do—and nothing more.

## The Problem

On a modern operating system, you trust dozens of programs every day, from `ls` and `grep` to complex toolchains and third-party utilities. But how can you be certain they are only performing the actions they're supposed to?

- Is that data processing script also making network connections?
- Is a build tool reading files outside the project directory?
- Has a trusted utility been compromised to do something malicious in the background?

Without deep inspection, you can't be sure. `toVerify` is designed to solve this problem by creating a behavioral "fingerprint" for a command and then ensuring the command never deviates from it.

## The Solution

`toVerify` uses the powerful `strace` utility on Linux to monitor a program's system calls—the fundamental way a program interacts with the operating system. It provides two modes of operation:

1.  **Profile Mode:** `toVerify` runs a command and records all of its system calls, file interactions, and network activity into a clear, human-readable **behavior profile** (a YAML file).
2.  **Verify Mode:** `toVerify` runs a command against a pre-existing profile. If the command attempts any action that is not explicitly allowed in the profile, `toVerify` will immediately flag the deviation and terminate the process.

This allows you to create a "contract" for any command and enforce it every time it runs.

## Core Concepts

-   **Behavior Profile:** A YAML file that defines the "allowed" behavior of a command. This includes the set of permitted system calls, files that can be read or written to, and whether network access is allowed.
-   **Profiling:** The process of running a command to generate its initial behavior profile. This profile captures the command's actions during a known-good run.
-   **Verification:** The process of running a command against its profile. Any action outside the profile's defined scope is considered a violation.

## Architecture

`toVerify` is built on a simple yet powerful architecture:

```
  +------------------+     +--------------------------------+
  | Command to Run   | --> | toVerify (Profiler/Verifier)   |
  | (e.g., "ls -l")  |     +--------------------------------+
  +------------------+       |           ^
                             |           | (Reads Profile)
                             v           |
  +------------------+     +--------------------------------+
  | strace           | --> | Behavior Profile (profile.yaml)|
  | (System Calls)   |     +--------------------------------+
  +------------------+
```

1.  **The Verifier** is the core engine that wraps the execution of the target command.
2.  It uses **`strace`** to intercept and inspect system calls made by the command in real-time.
3.  In **Profile Mode**, it generates a **Behavior Profile** from the `strace` output.
4.  In **Verify Mode**, it compares the live system calls against the rules in an existing **Behavior Profile**.

## Usage

*(This is a conceptual example of how the tool would work.)*

### 1. Profile a Command

First, create a behavior profile for a command you trust. Let's profile `ls -l /tmp`.

```bash
# Run in profile mode to create ls_tmp.yaml
toVerify --profile "ls -l /tmp" --output-file ls_tmp.yaml
```

This will execute the command and create a new file, `ls_tmp.yaml`, containing the observed behavior. You should inspect this file and can tighten the rules manually if needed.

**Example `ls_tmp.yaml`:**
```yaml
# Behavior profile for command: ls -l /tmp
command: "ls -l /tmp"
allowed_syscalls:
  - "execve"
  - "access"
  - "openat"
  - "read"
  - "write"
  - "close"
  - "brk"
  - "mmap"
file_access:
  read:
    - "/etc/ld.so.cache"
    - "/lib/x86_64-linux-gnu/libc.so.6"
    - "/tmp"
  write:
    - "/dev/stdout"
network:
  allowed: false
```

### 2. Verify a Command

Now, you can run the command in verify mode. `toVerify` will ensure its behavior matches the profile.

```bash
# Run in verify mode
toVerify --verify ls_tmp.yaml --command "ls -l /tmp"

# If the command runs as expected, it will execute silently.
```

If the command deviates, `toVerify` will stop it and report the error. For example, if a compromised version of `ls` tried to open a network socket:

```bash
$ toVerify --verify ls_tmp.yaml --command "ls -l /tmp"

CRITICAL: Deviation detected for command "ls -l /tmp"!
Violation: System call "socket" is not allowed by profile "ls_tmp.yaml".
Terminating process.
```

## Getting Started

This project is in the conceptual phase. The next steps are to begin implementation of the profiler and verifier.

### Prerequisites

-   A Linux environment
-   `strace` installed
-   A programming language for implementation (e.g., Python, Go, or Rust would be excellent choices)

## Contributing

This is the beginning of the project, and contributions are welcome. The immediate focus is on building the core profiler and verifier functionality.