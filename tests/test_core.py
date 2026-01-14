"""Unit tests for toVerify.core module."""

import pytest
from toVerify.core import check_violation, _validate_profile_structure, ProfileError


# A minimal valid profile for testing
def create_test_profile(
    syscalls=None,
    read_paths=None,
    write_paths=None,
    network_allowed=False
):
    """Helper to create a test profile."""
    return {
        "allowed_syscalls": set(syscalls or ["openat", "read", "write", "close"]),
        "file_access": {
            "read": read_paths or ["/etc/*", "/lib/*"],
            "write": write_paths or ["/tmp/*"],
        },
        "network": {
            "allowed": network_allowed
        }
    }


class TestCheckViolation:
    """Tests for the check_violation function."""
    
    def test_returns_none_for_none_details(self):
        """Should return None when details is None (non-syscall line)."""
        profile = create_test_profile()
        assert check_violation(None, profile) is None
    
    def test_allowed_syscall_passes(self):
        """Should return None for an allowed syscall."""
        profile = create_test_profile(syscalls=["openat", "read"])
        details = {
            "syscall": "openat",
            "is_network": False,
            "path": None,
            "is_read": False,
            "is_write": False
        }
        assert check_violation(details, profile) is None
    
    def test_disallowed_syscall_fails(self):
        """Should return violation message for disallowed syscall."""
        profile = create_test_profile(syscalls=["openat", "read"])
        details = {
            "syscall": "socket",
            "is_network": True,
            "path": None,
            "is_read": False,
            "is_write": False
        }
        result = check_violation(details, profile)
        assert result is not None
        assert "socket" in result
        assert "Disallowed system call" in result
    
    def test_network_blocked_when_not_allowed(self):
        """Should block network syscalls when network.allowed is False."""
        profile = create_test_profile(
            syscalls=["socket", "connect"],
            network_allowed=False
        )
        details = {
            "syscall": "socket",
            "is_network": True,
            "path": None,
            "is_read": False,
            "is_write": False
        }
        result = check_violation(details, profile)
        assert result is not None
        assert "network" in result.lower()
    
    def test_network_allowed_when_permitted(self):
        """Should allow network syscalls when network.allowed is True."""
        profile = create_test_profile(
            syscalls=["socket", "connect"],
            network_allowed=True
        )
        details = {
            "syscall": "socket",
            "is_network": True,
            "path": None,
            "is_read": False,
            "is_write": False
        }
        assert check_violation(details, profile) is None
    
    def test_allowed_file_read_passes(self):
        """Should allow file reads that match patterns."""
        profile = create_test_profile(
            syscalls=["openat"],
            read_paths=["/etc/*", "/lib/*"]
        )
        details = {
            "syscall": "openat",
            "is_network": False,
            "path": "/etc/passwd",
            "is_read": True,
            "is_write": False
        }
        assert check_violation(details, profile) is None
    
    def test_forbidden_file_read_fails(self):
        """Should block file reads that don't match patterns."""
        profile = create_test_profile(
            syscalls=["openat"],
            read_paths=["/etc/*"]
        )
        details = {
            "syscall": "openat",
            "is_network": False,
            "path": "/home/user/secret",
            "is_read": True,
            "is_write": False
        }
        result = check_violation(details, profile)
        assert result is not None
        assert "Forbidden file read" in result
        assert "/home/user/secret" in result
    
    def test_allowed_file_write_passes(self):
        """Should allow file writes that match patterns."""
        profile = create_test_profile(
            syscalls=["openat"],
            write_paths=["/tmp/*"]
        )
        details = {
            "syscall": "openat",
            "is_network": False,
            "path": "/tmp/output.txt",
            "is_read": False,
            "is_write": True
        }
        assert check_violation(details, profile) is None
    
    def test_forbidden_file_write_fails(self):
        """Should block file writes that don't match patterns."""
        profile = create_test_profile(
            syscalls=["openat"],
            write_paths=["/tmp/*"]
        )
        details = {
            "syscall": "openat",
            "is_network": False,
            "path": "/etc/passwd",
            "is_read": False,
            "is_write": True
        }
        result = check_violation(details, profile)
        assert result is not None
        assert "Forbidden file write" in result


class TestValidateProfileStructure:
    """Tests for the _validate_profile_structure function."""
    
    def test_valid_profile_passes(self):
        """Should not raise for a valid profile."""
        profile = {
            "allowed_syscalls": ["read", "write"],
            "file_access": {"read": [], "write": []},
            "network": {"allowed": False}
        }
        # Should not raise
        _validate_profile_structure(profile, "test.yaml")
    
    def test_missing_allowed_syscalls_fails(self):
        """Should raise ProfileError when allowed_syscalls is missing."""
        profile = {
            "file_access": {"read": [], "write": []},
            "network": {"allowed": False}
        }
        with pytest.raises(ProfileError) as exc_info:
            _validate_profile_structure(profile, "test.yaml")
        assert "allowed_syscalls" in str(exc_info.value)
    
    def test_missing_file_access_fails(self):
        """Should raise ProfileError when file_access is missing."""
        profile = {
            "allowed_syscalls": ["read"],
            "network": {"allowed": False}
        }
        with pytest.raises(ProfileError) as exc_info:
            _validate_profile_structure(profile, "test.yaml")
        assert "file_access" in str(exc_info.value)
    
    def test_missing_network_fails(self):
        """Should raise ProfileError when network is missing."""
        profile = {
            "allowed_syscalls": ["read"],
            "file_access": {"read": [], "write": []}
        }
        with pytest.raises(ProfileError) as exc_info:
            _validate_profile_structure(profile, "test.yaml")
        assert "network" in str(exc_info.value)
    
    def test_missing_file_access_read_fails(self):
        """Should raise ProfileError when file_access.read is missing."""
        profile = {
            "allowed_syscalls": ["read"],
            "file_access": {"write": []},
            "network": {"allowed": False}
        }
        with pytest.raises(ProfileError) as exc_info:
            _validate_profile_structure(profile, "test.yaml")
        assert "file_access.read" in str(exc_info.value)
    
    def test_missing_network_allowed_fails(self):
        """Should raise ProfileError when network.allowed is missing."""
        profile = {
            "allowed_syscalls": ["read"],
            "file_access": {"read": [], "write": []},
            "network": {}
        }
        with pytest.raises(ProfileError) as exc_info:
            _validate_profile_structure(profile, "test.yaml")
        assert "network.allowed" in str(exc_info.value)
