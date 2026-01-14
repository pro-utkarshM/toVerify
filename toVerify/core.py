import subprocess
import sys
import yaml
import fnmatch
import os
import signal
import shutil

from .parser import parse_strace_output, parse_strace_line

# Default timeout for profiling commands (in seconds)
DEFAULT_TIMEOUT = 300  # 5 minutes


class StraceNotFoundError(Exception):
    """Raised when strace is not found on the system."""
    pass


class ProfileError(Exception):
    """Raised when there's an issue with the behavior profile."""
    pass


def _ensure_strace_available():
    """Check if strace is available on the system."""
    if shutil.which("strace") is None:
        raise StraceNotFoundError(
            "strace not found. Please install it:\n"
            "  Ubuntu/Debian: sudo apt install strace\n"
            "  Fedora/RHEL:   sudo dnf install strace\n"
            "  Arch:          sudo pacman -S strace"
        )


def _validate_profile_structure(profile, profile_file):
    """Validate that a profile has all required fields."""
    required_fields = ["allowed_syscalls", "file_access", "network"]
    for field in required_fields:
        if field not in profile:
            raise ProfileError(f"Profile '{profile_file}' missing required field: {field}")
    
    if "read" not in profile.get("file_access", {}):
        raise ProfileError(f"Profile '{profile_file}' missing 'file_access.read' field")
    if "write" not in profile.get("file_access", {}):
        raise ProfileError(f"Profile '{profile_file}' missing 'file_access.write' field")
    if "allowed" not in profile.get("network", {}):
        raise ProfileError(f"Profile '{profile_file}' missing 'network.allowed' field")


def do_profile(command, output_file, timeout=None, verbosity=1):
    """Profiles a command and saves the behavior to a YAML file.
    
    Args:
        command: The shell command to profile
        output_file: Path to save the YAML profile
        timeout: Maximum seconds to run (default: DEFAULT_TIMEOUT)
        verbosity: Output level (0=quiet, 1=normal, 2=verbose)
    
    Raises:
        StraceNotFoundError: If strace is not installed
    """
    _ensure_strace_available()
    
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    
    if verbosity >= 1:
        print(f"Profiling command: \"{command}\"")
    if verbosity >= 2:
        print(f"Timeout: {timeout} seconds")
    
    # Use ["sh", "-c", command] to correctly trace compound commands.
    # -f follows forks, crucial for shell scripts.
    strace_command = ["strace", "-f", "sh", "-c", command]
    
    try:
        # We capture stderr because that's where strace writes its output.
        result = subprocess.run(
            strace_command, 
            capture_output=True, 
            text=True, 
            check=False,
            timeout=timeout
        )
        strace_output = result.stderr
    except subprocess.TimeoutExpired:
        print(f"Error: Command timed out after {timeout} seconds.", file=sys.stderr)
        print("Use --timeout to increase the limit.", file=sys.stderr)
        sys.exit(1)
    
    if not strace_output:
        print("Error: No output from strace. Command might have failed or produced no syscalls.", file=sys.stderr)
        if result.stdout:
            print(f"Stdout:\n{result.stdout}", file=sys.stderr)
        if result.stderr:
             print(f"Stderr:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    profile_data = parse_strace_output(strace_output)
    profile_data['command'] = command
    
    if verbosity >= 2:
        print(f"Captured {len(profile_data['allowed_syscalls'])} unique syscalls")
        print(f"Read files: {len(profile_data['file_access']['read'])}")
        print(f"Write files: {len(profile_data['file_access']['write'])}")

    if verbosity >= 1:
        print(f"Saving profile to {output_file}...")
    
    with open(output_file, 'w') as f:
        yaml.dump(profile_data, f, default_flow_style=False, sort_keys=False)
    
    if verbosity >= 1:
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

def do_verify(profile_file, command, verbosity=1):
    """Verifies a command against a profile in real-time.
    
    Args:
        profile_file: Path to the YAML behavior profile
        command: The shell command to verify
        verbosity: Output level (0=quiet, 1=normal, 2=verbose)
    
    Raises:
        StraceNotFoundError: If strace is not installed
        ProfileError: If the profile is invalid
    """
    _ensure_strace_available()
    
    if verbosity >= 1:
        print(f"Verifying command: \"{command}\" against profile: {profile_file}")
    
    # 1. Load the profile
    try:
        with open(profile_file, 'r') as f:
            profile = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Profile file not found at {profile_file}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Could not parse YAML profile {profile_file}: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Validate profile structure
    try:
        _validate_profile_structure(profile, profile_file)
    except ProfileError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Convert to sets for faster lookups
    profile["allowed_syscalls"] = set(profile["allowed_syscalls"])
    
    if verbosity >= 2:
        print(f"Profile loaded: {len(profile['allowed_syscalls'])} allowed syscalls")
        print(f"Network access: {'allowed' if profile['network']['allowed'] else 'blocked'}")

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

    if verbosity >= 2:
        print(f"Monitoring process group with PGID: {proc.pid}")

    # 3. Process strace output line by line
    syscall_count = 0
    try:
        for line in iter(proc.stderr.readline, ''):
            parsed_details = parse_strace_line(line)
            
            if parsed_details and verbosity >= 2:
                syscall_count += 1
                print(f"  [{syscall_count}] {parsed_details['syscall']}", end="")
                if parsed_details['path']:
                    print(f" -> {parsed_details['path']}", end="")
                print()
            
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
        if verbosity >= 1:
            print("\n--- VERIFICATION SUCCESSFUL ---")
            print(f"Command \"{command}\" adheres to profile \"{profile_file}\".")
        if verbosity >= 2:
            print(f"Total syscalls checked: {syscall_count}")
    else:
        if verbosity >= 1:
            print(f"\n--- COMMAND FINISHED WITH NON-ZERO EXIT CODE: {return_code} ---")
        # Exit with the same code so scripts can detect failure
        sys.exit(return_code)