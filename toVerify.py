#!/usr/bin/env python3
import argparse
import subprocess
import sys
import yaml

def run_command_with_strace(command):
    """Executes a command under strace and returns the stderr."""
    # Use ["sh", "-c", command] to correctly trace compound commands.
    strace_command = ["strace", "-o", "/dev/stderr", "-f", "sh", "-c", command]
    print(f"Executing: {' '.join(strace_command)}")
    
    # We capture stderr because that's where strace writes its output.
    result = subprocess.run(strace_command, capture_output=True, text=True)
    return result.stderr

def parse_strace_output(strace_output):
    """
    Parses strace output using regular expressions to be more robust.
    """
    import re

    # Regex to capture the syscall name from a line like:
    # 12345 syscall_name(arg1, arg2) = 0
    # It avoids matching lines without parentheses, like signal deliveries.
    syscall_regex = re.compile(r'^\d+\s+([a-zA-Z0-9_]+)\(.*')

    # Regex to find file paths in arguments, typically the first quoted string.
    # e.g., openat(AT_FDCWD, "/path/to/file", O_RDONLY) = 3
    path_regex = re.compile(r'\((?P<quote>[""])(?P<path>.*?)(?P=quote)')

    syscalls = set()
    read_files = set()
    write_files = set()

    # Syscalls that are known to read from a path argument.
    read_syscalls = {"access", "openat", "stat", "lstat", "readlink", "execve"}
    # Syscalls that are known to write, but need flag checking.
    write_syscalls = {"openat", "renameat", "symlinkat"}


    for line in strace_output.strip().split('\n'):
        syscall_match = syscall_regex.match(line)
        if not syscall_match:
            continue

        syscall_name = syscall_match.group(1)
        syscalls.add(syscall_name)

        path_match = path_regex.search(line)
        if not path_match:
            continue

        path = path_match.group("path")

        # Determine if it's a read or write operation
        if syscall_name in read_syscalls:
            # For openat, we need to check flags to be more precise
            if syscall_name == "openat":
                if "O_WRONLY" in line:
                    write_files.add(path)
                elif "O_RDWR" in line:
                    read_files.add(path)
                    write_files.add(path)
                else: # Default to read for O_RDONLY or no flags specified
                    read_files.add(path)
            else:
                read_files.add(path)

        if syscall_name in write_syscalls:
             if "O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line:
                write_files.add(path)

    return {
        "allowed_syscalls": sorted(list(syscalls)),
        "file_access": {
            "read": sorted(list(read_files)),
            "write": sorted(list(write_files)),
        },
        "network": {
            "allowed": False # Default to false, can be updated based on syscalls like socket, connect
        }
    }


def do_profile(command, output_file):
    """Profiles a command and saves the behavior to a YAML file."""
    print(f"Profiling command: \"{command}\"")
    
    strace_output = run_command_with_strace(command)
    
    if not strace_output:
        print("Error: No output from strace. Command might have failed.", file=sys.stderr)
        sys.exit(1)

    profile_data = parse_strace_output(strace_output)
    profile_data['command'] = command

    print(f"Saving profile to {output_file}...")
    with open(output_file, 'w') as f:
        yaml.dump(profile_data, f, default_flow_style=False, sort_keys=False)
    
    print("Profiling complete.")

import fnmatch


def do_verify(profile_file, command):
    """Verifies a command against a profile."""
    print(f"Verifying command: \"{command}\" against profile: {profile_file}")
    
    # 1. Load the profile
    try:
        with open(profile_file, 'r') as f:
            expected_profile = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Profile file not found at {profile_file}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Could not parse YAML profile {profile_file}: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Run the command with strace
    strace_output = run_command_with_strace(command)
    
    if not strace_output:
        print("Error: No output from strace. Command might have failed.", file=sys.stderr)
        sys.exit(1)

    # 3. Parse the new execution's behavior
    observed_profile = parse_strace_output(strace_output)

    # 4. Compare and report deviations
    deviations = []
    
    # Check syscalls
    observed_syscalls = set(observed_profile["allowed_syscalls"])
    allowed_syscalls = set(expected_profile["allowed_syscalls"])
    disallowed_syscalls = observed_syscalls - allowed_syscalls
    if disallowed_syscalls:
        deviations.append(("Disallowed system calls executed", sorted(list(disallowed_syscalls))))

    # Check file access with glob support
    def check_file_access(observed_paths, allowed_patterns):
        forbidden = []
        for path in observed_paths:
            if not any(fnmatch.fnmatch(path, pattern) for pattern in allowed_patterns):
                forbidden.append(path)
        return forbidden

    forbidden_reads = check_file_access(
        observed_profile["file_access"]["read"],
        expected_profile["file_access"]["read"]
    )
    if forbidden_reads:
        deviations.append(("Forbidden files read", sorted(forbidden_reads)))

    forbidden_writes = check_file_access(
        observed_profile["file_access"]["write"],
        expected_profile["file_access"]["write"]
    )
    if forbidden_writes:
        deviations.append(("Forbidden files written to", sorted(forbidden_writes)))


    if deviations:
        print("\n--- VERIFICATION FAILED ---", file=sys.stderr)
        print(f"Command \"{command}\" deviated from profile \"{profile_file}\"\n", file=sys.stderr)
        for category, items in deviations:
            print(f"  - {category}:", file=sys.stderr)
            for item in items:
                print(f"    - {item}", file=sys.stderr)
        print("\n---------------------------", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n--- VERIFICATION SUCCESSFUL ---")
        print(f"Command \"{command}\" adheres to profile \"{profile_file}\".")
        print("-------------------------------")


def main():
    parser = argparse.ArgumentParser(
        description="A tool to profile and verify command execution behavior using strace."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--profile", metavar="CMD", help="Profile the given command.")
    group.add_argument("--verify", metavar="PROFILE_FILE", help="Verify a command against a profile.")

    parser.add_argument("--output-file", metavar="FILE", help="File to save the profile to (used with --profile).")
    parser.add_argument("--command", metavar="CMD", help="The command to run for verification (used with --verify).")

    args = parser.parse_args()

    if args.profile:
        if not args.output_file:
            parser.error("--output-file is required when using --profile.")
        do_profile(args.profile, args.output_file)
    elif args.verify:
        if not args.command:
            parser.error("--command is required when using --verify.")
        do_verify(args.verify, args.command)

if __name__ == "__main__":
    main()
