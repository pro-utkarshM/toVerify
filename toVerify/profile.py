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
