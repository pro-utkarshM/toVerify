"""Profile management utilities for toVerify."""

import yaml
import sys

from .core import ProfileError


REQUIRED_FIELDS = ["allowed_syscalls", "file_access", "network"]
REQUIRED_FILE_ACCESS_FIELDS = ["read", "write"]


def load_profile(filepath):
    """Load and validate a profile from a YAML file.
    
    Args:
        filepath: Path to the YAML profile file
        
    Returns:
        The validated profile dictionary
        
    Raises:
        ProfileError: If the profile is invalid
        FileNotFoundError: If the file doesn't exist
    """
    try:
        with open(filepath, 'r') as f:
            profile = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ProfileError(f"Could not parse YAML: {e}")
    
    validate_profile(profile, filepath)
    return profile


def validate_profile(profile, filepath="<profile>"):
    """Validate that a profile has all required fields and correct types.
    
    Args:
        profile: The profile dictionary to validate
        filepath: Path to the profile (for error messages)
        
    Raises:
        ProfileError: If the profile is invalid
    """
    if profile is None:
        raise ProfileError(f"Profile '{filepath}' is empty or invalid YAML")
    
    # Check required top-level fields
    for field in REQUIRED_FIELDS:
        if field not in profile:
            raise ProfileError(f"Profile '{filepath}' missing required field: {field}")
    
    # Validate allowed_syscalls
    if not isinstance(profile["allowed_syscalls"], list):
        raise ProfileError(f"Profile '{filepath}': 'allowed_syscalls' must be a list")
    
    # Validate file_access
    file_access = profile.get("file_access", {})
    if not isinstance(file_access, dict):
        raise ProfileError(f"Profile '{filepath}': 'file_access' must be a dictionary")
    
    for field in REQUIRED_FILE_ACCESS_FIELDS:
        if field not in file_access:
            raise ProfileError(f"Profile '{filepath}' missing 'file_access.{field}' field")
        if not isinstance(file_access[field], list):
            raise ProfileError(f"Profile '{filepath}': 'file_access.{field}' must be a list")
    
    # Validate network
    network = profile.get("network", {})
    if not isinstance(network, dict):
        raise ProfileError(f"Profile '{filepath}': 'network' must be a dictionary")
    
    if "allowed" not in network:
        raise ProfileError(f"Profile '{filepath}' missing 'network.allowed' field")
    
    if not isinstance(network["allowed"], bool):
        raise ProfileError(f"Profile '{filepath}': 'network.allowed' must be a boolean")


def get_profile_summary(profile):
    """Get a human-readable summary of the profile.
    
    Args:
        profile: The profile dictionary
        
    Returns:
        A string summary of the profile
    """
    lines = []
    lines.append(f"Command: {profile.get('command', '<not specified>')}")
    lines.append(f"Allowed syscalls: {len(profile.get('allowed_syscalls', []))}")
    
    file_access = profile.get('file_access', {})
    lines.append(f"Read patterns: {len(file_access.get('read', []))}")
    lines.append(f"Write patterns: {len(file_access.get('write', []))}")
    
    network = profile.get('network', {})
    lines.append(f"Network access: {'allowed' if network.get('allowed') else 'blocked'}")
    
    return '\n'.join(lines)


def do_validate(profile_file, verbosity=1):
    """Validate a profile file and report any issues.
    
    Args:
        profile_file: Path to the profile to validate
        verbosity: Output level (0=quiet, 1=normal, 2=verbose)
        
    Returns:
        True if valid, exits with error if invalid
    """
    if verbosity >= 1:
        print(f"Validating profile: {profile_file}")
    
    try:
        profile = load_profile(profile_file)
    except FileNotFoundError:
        print(f"Error: Profile file not found: {profile_file}", file=sys.stderr)
        sys.exit(1)
    except ProfileError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    if verbosity >= 1:
        print("Profile is valid!")
    
    if verbosity >= 2:
        print("\nProfile summary:")
        print(get_profile_summary(profile))
    
    return True


def diff_profiles(profile1, profile2):
    """Compare two profiles and return the differences.
    
    Args:
        profile1: First profile dictionary
        profile2: Second profile dictionary
        
    Returns:
        Dictionary containing:
        - syscalls_added: syscalls in profile2 but not profile1
        - syscalls_removed: syscalls in profile1 but not profile2
        - read_added: read patterns added
        - read_removed: read patterns removed
        - write_added: write patterns added
        - write_removed: write patterns removed
        - network_changed: True if network.allowed differs
    """
    syscalls1 = set(profile1.get("allowed_syscalls", []))
    syscalls2 = set(profile2.get("allowed_syscalls", []))
    
    file1 = profile1.get("file_access", {})
    file2 = profile2.get("file_access", {})
    
    read1 = set(file1.get("read", []))
    read2 = set(file2.get("read", []))
    write1 = set(file1.get("write", []))
    write2 = set(file2.get("write", []))
    
    net1 = profile1.get("network", {}).get("allowed", False)
    net2 = profile2.get("network", {}).get("allowed", False)
    
    return {
        "syscalls_added": sorted(syscalls2 - syscalls1),
        "syscalls_removed": sorted(syscalls1 - syscalls2),
        "read_added": sorted(read2 - read1),
        "read_removed": sorted(read1 - read2),
        "write_added": sorted(write2 - write1),
        "write_removed": sorted(write1 - write2),
        "network_changed": net1 != net2,
        "network_old": net1,
        "network_new": net2
    }


def do_diff(profile_file1, profile_file2, verbosity=1):
    """Compare two profiles and display the differences.
    
    Args:
        profile_file1: Path to first profile
        profile_file2: Path to second profile
        verbosity: Output level (0=quiet, 1=normal, 2=verbose)
    """
    if verbosity >= 1:
        print(f"Comparing profiles:")
        print(f"  Base:   {profile_file1}")
        print(f"  Target: {profile_file2}")
    
    try:
        profile1 = load_profile(profile_file1)
        profile2 = load_profile(profile_file2)
    except FileNotFoundError as e:
        print(f"Error: Profile not found: {e}", file=sys.stderr)
        sys.exit(1)
    except ProfileError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    diff = diff_profiles(profile1, profile2)
    
    has_changes = False
    
    # Syscall changes
    if diff["syscalls_added"]:
        has_changes = True
        print(f"\n+ Syscalls added ({len(diff['syscalls_added'])}):")
        for s in diff["syscalls_added"]:
            print(f"    + {s}")
    
    if diff["syscalls_removed"]:
        has_changes = True
        print(f"\n- Syscalls removed ({len(diff['syscalls_removed'])}):")
        for s in diff["syscalls_removed"]:
            print(f"    - {s}")
    
    # Read pattern changes
    if diff["read_added"]:
        has_changes = True
        print(f"\n+ Read patterns added ({len(diff['read_added'])}):")
        for p in diff["read_added"]:
            print(f"    + {p}")
    
    if diff["read_removed"]:
        has_changes = True
        print(f"\n- Read patterns removed ({len(diff['read_removed'])}):")
        for p in diff["read_removed"]:
            print(f"    - {p}")
    
    # Write pattern changes
    if diff["write_added"]:
        has_changes = True
        print(f"\n+ Write patterns added ({len(diff['write_added'])}):")
        for p in diff["write_added"]:
            print(f"    + {p}")
    
    if diff["write_removed"]:
        has_changes = True
        print(f"\n- Write patterns removed ({len(diff['write_removed'])}):")
        for p in diff["write_removed"]:
            print(f"    - {p}")
    
    # Network changes
    if diff["network_changed"]:
        has_changes = True
        old = "allowed" if diff["network_old"] else "blocked"
        new = "allowed" if diff["network_new"] else "blocked"
        print(f"\n! Network access changed: {old} -> {new}")
    
    if not has_changes:
        print("\nProfiles are identical.")
    else:
        print("\n---")
        total = (len(diff["syscalls_added"]) + len(diff["syscalls_removed"]) +
                 len(diff["read_added"]) + len(diff["read_removed"]) +
                 len(diff["write_added"]) + len(diff["write_removed"]) +
                 (1 if diff["network_changed"] else 0))
        print(f"Total changes: {total}")
