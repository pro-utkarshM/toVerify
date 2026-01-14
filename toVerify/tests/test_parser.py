"""Unit tests for toVerify.parser module."""

import pytest
from toVerify.parser import parse_strace_line, parse_strace_output


class TestParseSyscalls:
    """Tests for basic syscall parsing."""
    
    # Original test cases
    def test_openat_read(self):
        line = 'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3'
        result = parse_strace_line(line)
        assert result == {
            "syscall": "openat", "is_network": False, "path": "/etc/ld.so.cache",
            "is_read": True, "is_write": False
        }
    
    def test_write_syscall_no_path(self):
        line = 'write(1, "hello", 5) = 5'
        result = parse_strace_line(line)
        assert result["syscall"] == "write"
        assert result["path"] is None  # write syscall itself doesn't take a path arg
    
    def test_socket_is_network(self):
        line = 'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3'
        result = parse_strace_line(line)
        assert result["syscall"] == "socket"
        assert result["is_network"] is True
    
    def test_mkdirat_is_write(self):
        line = 'mkdirat(AT_FDCWD, "/tmp/testdir", 0777) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "mkdirat"
        assert result["path"] == "/tmp/testdir"
        assert result["is_write"] is True
    
    def test_execve_with_pid(self):
        line = '[pid  1234] execve("/bin/ls", ["ls"], 0x7ffc1234) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "execve"
        assert result["path"] == "/bin/ls"
        assert result["is_read"] is True


class TestNewSyscalls:
    """Tests for newly added syscalls."""
    
    # Network syscalls
    def test_accept4_is_network(self):
        line = 'accept4(3, {sa_family=AF_INET, ...}, [16], SOCK_CLOEXEC) = 4'
        result = parse_strace_line(line)
        assert result["syscall"] == "accept4"
        assert result["is_network"] is True
    
    def test_listen_is_network(self):
        line = 'listen(3, 128) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "listen"
        assert result["is_network"] is True
    
    def test_getpeername_is_network(self):
        line = 'getpeername(3, {sa_family=AF_INET, ...}, [16]) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "getpeername"
        assert result["is_network"] is True
    
    def test_setsockopt_is_network(self):
        line = 'setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "setsockopt"
        assert result["is_network"] is True
    
    # Path syscalls
    def test_newfstatat_is_read(self):
        line = 'newfstatat(AT_FDCWD, "/etc/passwd", {st_mode=S_IFREG|0644, ...}, 0) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "newfstatat"
        assert result["path"] == "/etc/passwd"
        assert result["is_read"] is True
    
    def test_faccessat_is_read(self):
        line = 'faccessat(AT_FDCWD, "/usr/bin/ls", X_OK) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "faccessat"
        assert result["path"] == "/usr/bin/ls"
        assert result["is_read"] is True
    
    def test_faccessat2_is_read(self):
        line = 'faccessat2(AT_FDCWD, "/usr/bin/ls", R_OK, AT_EACCESS) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "faccessat2"
        assert result["path"] == "/usr/bin/ls"
        assert result["is_read"] is True
    
    def test_readlinkat_is_read(self):
        line = 'readlinkat(AT_FDCWD, "/proc/self/exe", "/usr/bin/python", 4095) = 15'
        result = parse_strace_line(line)
        assert result["syscall"] == "readlinkat"
        assert result["path"] == "/proc/self/exe"
        assert result["is_read"] is True
    
    def test_fchmodat_is_write(self):
        line = 'fchmodat(AT_FDCWD, "/tmp/file", 0644, 0) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "fchmodat"
        assert result["path"] == "/tmp/file"
        assert result["is_write"] is True
    
    def test_renameat2_is_write(self):
        line = 'renameat2(AT_FDCWD, "/tmp/old", AT_FDCWD, "/tmp/new", RENAME_NOREPLACE) = 0'
        result = parse_strace_line(line)
        assert result["syscall"] == "renameat2"
        assert result["path"] == "/tmp/old"
        assert result["is_write"] is True
    
    def test_openat2_read(self):
        line = 'openat2(AT_FDCWD, "/etc/hosts", {flags=O_RDONLY, ...}, 24) = 3'
        result = parse_strace_line(line)
        assert result["syscall"] == "openat2"
        assert result["path"] == "/etc/hosts"
        assert result["is_read"] is True


class TestEdgeCases:
    """Tests for edge cases and malformed lines."""
    
    def test_signal_line_returns_none(self):
        line = '--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, ...} ---'
        assert parse_strace_line(line) is None
    
    def test_exit_line_returns_none(self):
        line = '+++ exited with 0 +++'
        assert parse_strace_line(line) is None
    
    def test_unfinished_line_returns_none(self):
        line = 'read(3,  <unfinished ...>'
        assert parse_strace_line(line) is None
    
    def test_resumed_line_returns_none(self):
        line = '<... read resumed> "data", 4096) = 4096'
        # This won't match because it starts with <
        assert parse_strace_line(line) is None
    
    def test_abstract_socket_ignored(self):
        """Abstract socket paths (starting with @) should be ignored."""
        line = 'connect(3, {sa_family=AF_UNIX, sun_path="@/tmp/.X11-unix/X0"}, 22) = 0'
        result = parse_strace_line(line)
        # connect is not in PATH_SYSCALLS, so it won't extract path anyway
        assert result["path"] is None
    
    def test_unicode_path(self):
        """Paths with unicode characters should be handled."""
        line = 'openat(AT_FDCWD, "/tmp/файл", O_RDONLY) = 3'
        result = parse_strace_line(line)
        assert result["path"] == "/tmp/файл"


class TestParseFullOutput:
    """Tests for parse_strace_output function."""
    
    def test_parses_multiple_lines(self):
        strace_output = """
execve("/bin/ls", ["ls"], 0x7ffc) = 0
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3
socket(AF_INET, SOCK_STREAM, 0) = 4
mkdirat(AT_FDCWD, "/tmp/testdir", 0777) = 0
+++ exited with 0 +++
"""
        result = parse_strace_output(strace_output)
        
        # Check syscalls collected
        assert "execve" in result["allowed_syscalls"]
        assert "openat" in result["allowed_syscalls"]
        assert "socket" in result["allowed_syscalls"]
        assert "mkdirat" in result["allowed_syscalls"]
        
        # Check network detected
        assert result["network"]["allowed"] is True
        
        # Check file access
        assert "/bin/ls" in result["file_access"]["read"]
        assert "/etc/ld.so.cache" in result["file_access"]["read"]
        assert "/tmp/testdir" in result["file_access"]["write"]
    
    def test_network_false_when_no_network_syscalls(self):
        strace_output = """
openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
read(3, "root:x:0:0:", 4096) = 1024
close(3) = 0
"""
        result = parse_strace_output(strace_output)
        assert result["network"]["allowed"] is False


# Legacy parametrized tests for backwards compatibility
TEST_CASES = {
    'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3': {
        "syscall": "openat", "is_network": False, "path": "/etc/ld.so.cache",
        "is_read": True, "is_write": False
    },
    'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3': {
        "syscall": "socket", "is_network": True, "path": None,
        "is_read": False, "is_write": False
    },
}

@pytest.mark.parametrize("line,expected", TEST_CASES.items())
def test_parse_strace_line_parametrized(line, expected):
    assert parse_strace_line(line) == expected