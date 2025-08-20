import pytest
from toVerify.parser import parse_strace_line

# A dictionary of test cases: strace_line -> expected_dict
TEST_CASES = {
    'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3': {
        "syscall": "openat", "is_network": False, "path": "/etc/ld.so.cache",
        "is_read": True, "is_write": False
    },
    'write(1, "hello", 5) = 5': {
        "syscall": "write", "is_network": False, "path": None,
        "is_read": False, "is_write": False # write syscall itself doesn't take a path arg
    },
    'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3': {
        "syscall": "socket", "is_network": True, "path": None,
        "is_read": False, "is_write": False
    },
    'mkdirat(AT_FDCWD, "/tmp/testdir", 0777) = 0': {
        "syscall": "mkdirat", "is_network": False, "path": "/tmp/testdir",
        "is_read": False, "is_write": True
    },
    '[pid  1234] execve("/bin/ls", ["ls"], 0x7ffc1234) = 0': {
        "syscall": "execve", "is_network": False, "path": "/bin/ls",
        "is_read": True, "is_write": False
    },
    '--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, ...} ---': None,
    '+++ exited with 0 +++': None
}

@pytest.mark.parametrize("line,expected", TEST_CASES.items())
def test_parse_strace_line(line, expected):
    assert parse_strace_line(line) == expected