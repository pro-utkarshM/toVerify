import subprocess
import sys
import yaml
import fnmatch
import os
import signal

from .parser import parse_strace_output, parse_strace_line

def do_profile(command, output_file):
    """Profiles a command and saves the behavior to a YAML file."""
    print(f"Profiling command: \"{command}\"")
    
    # Use ["sh", "-c", command] to correctly trace compound commands.
    # -f follows forks, crucial for shell scripts.
    strace_command = ["strace", "-f", "sh", "-c", command]
    
    # We capture stderr because that's where strace writes its output.
    result = subprocess.run(strace_command, capture_output=True, text=True, check=False)
    strace_output = result.stderr
    
    if not strace_output:
        print("Error: No output from strace. Command might have failed or produced no syscalls.", file=sys.stderr)
        if result.stdout:
            print(f"Stdout:\n{result.stdout}", file=sys.stderr)
        if result.stderr:
             print(f"Stderr:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    profile_data = parse_strace_output(strace_output)
    profile_data['command'] = command

    print(f"Saving profile to {output_file}...")
    with open(output_file, 'w') as f:
        yaml.dump(profile_data, f, default_flow_style=False, sort_keys=False)
    
    print("Profiling complete.")


def check_violation(details, profile):
    """Checks a single parsed line for violations against the profile."""
    if not details:
        return None

    # 1. Check syscall
    if details["syscall"] not in profile["allowed_syscalls"]:
        return f"Disallowed system call: {details['syscall']}"
        
    # 2. Check network access
    if details["is_network"] and not profile["network"]["allowed"]:
        return f"Disallowed network activity: syscall {details['syscall']}"
        
    # 3. Check file access
    if details["path"]:
        path = details["path"]
        # Check reads
        if details["is_read"]:
            allowed_reads = profile["file_access"]["read"]
            if not any(fnmatch.fnmatch(path, pattern) for pattern in allowed_reads):
                return f"Forbidden file read: {path}"
        # Check writes
        if details["is_write"]:
            allowed_writes = profile["file_access"]["write"]
            if not any(fnmatch.fnmatch(path, pattern) for pattern in allowed_writes):
                return f"Forbidden file write: {path}"

    return None

def do_verify(profile_file, command):
    """Verifies a command against a profile in real-time."""
    print(f"Verifying command: \"{command}\" against profile: {profile_file}")
    
    # 1. Load the profile
    try:
        with open(profile_file, 'r') as f:
            profile = yaml.safe_load(f)
            # Convert to sets for faster lookups
            profile["allowed_syscalls"] = set(profile["allowed_syscalls"])
    except FileNotFoundError:
        print(f"Error: Profile file not found at {profile_file}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Could not parse YAML profile {profile_file}: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Start the command with strace as a subprocess
    # We use -f to follow forks. preexec_fn=os.setsid creates a new process
    # group, which lets us kill the command and all its children reliably.
    strace_cmd = ["strace", "-f", "sh", "-c", command]
    
    # Redirect command's stdout/stderr to our own so user sees the output
    proc = subprocess.Popen(
        strace_cmd, 
        stderr=subprocess.PIPE, 
        text=True, 
        preexec_fn=os.setsid
    )

    print(f"Monitoring process group with PGID: {proc.pid}")

    # 3. Process strace output line by line
    try:
        for line in iter(proc.stderr.readline, ''):
            parsed_details = parse_strace_line(line)
            violation = check_violation(parsed_details, profile)
            
            if violation:
                print("\n--- VERIFICATION FAILED ---", file=sys.stderr)
                print(f"CRITICAL: Deviation detected for command \"{command}\"!", file=sys.stderr)
                print(f"Violation: {violation}", file=sys.stderr)
                print(f"Offending line: {line.strip()}", file=sys.stderr)
                print("Terminating process group...", file=sys.stderr)
                
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait()
                sys.exit(1)

    except KeyboardInterrupt:
        print("\nInterrupted by user. Terminating process.", file=sys.stderr)
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()
        sys.exit(1)

    proc.stderr.close()
    return_code = proc.wait()

    if return_code == 0:
        print("\n--- VERIFICATION SUCCESSFUL ---")
        print(f"Command \"{command}\" adheres to profile \"{profile_file}\".")
    else:
        print(f"\n--- COMMAND FINISHED WITH NON-ZERO EXIT CODE: {return_code} ---")
        # Exit with the same code so scripts can detect failure
        sys.exit(return_code)