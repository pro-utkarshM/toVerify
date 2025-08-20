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
    A simple parser for strace output to extract syscalls and file access.
    This is a basic implementation and can be improved.
    """
    syscalls = set()
    read_files = set()
    write_files = set()

    for line in strace_output.strip().split('\n'):
        try:
            # The syscall name is the word immediately before the first "("
            syscall_name_part = line.split('(', 1)[0]
            # This part might contain a PID and other info, so we take the last word.
            syscall_name = syscall_name_part.strip().split()[-1]
            syscalls.add(syscall_name)

            # Heuristic for file paths
            if '("' in line:
                path = line.split('"')[1]
                
                # Check for read-related flags/syscalls
                if syscall_name in ["read", "access", "openat", "stat", "lstat"]:
                    read_files.add(path)
                elif "O_RDONLY" in line or "O_RDWR" in line:
                    read_files.add(path)

                # Check for write-related flags/syscalls
                if syscall_name in ["write", "openat"]:
                    if "O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line:
                        write_files.add(path)

        except IndexError:
            # Line format might not be as expected, skip for now.
            pass

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
        deviations.append(f"Disallowed system calls executed: {sorted(list(disallowed_syscalls))}")

    # Check file reads
    observed_reads = set(observed_profile["file_access"]["read"])
    allowed_reads = set(expected_profile["file_access"]["read"])
    forbidden_reads = observed_reads - allowed_reads
    if forbidden_reads:
        deviations.append(f"Forbidden files read: {sorted(list(forbidden_reads))}")

    # Check file writes
    observed_writes = set(observed_profile["file_access"]["write"])
    allowed_writes = set(expected_profile["file_access"]["write"])
    forbidden_writes = observed_writes - allowed_writes
    if forbidden_writes:
        deviations.append(f"Forbidden files written to: {sorted(list(forbidden_writes))}")

    if deviations:
        print("\n--- VERIFICATION FAILED ---", file=sys.stderr)
        print(f"Command \"{command}\" deviated from profile \"{profile_file}\"\n", file=sys.stderr)
        for dev in deviations:
            print(f"- {dev}", file=sys.stderr)
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
