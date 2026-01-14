import re

# More specific regex to capture PID (optional), syscall, and args
LINE_REGEX = re.compile(
    r"^(?:\[pid\s+\d+\]\s)?"       # Optional PID prefix
    r"(?P<syscall>[a-zA-Z0-9_]+)"  # Syscall name
    r"\((?P<args>.*?)\)"          # Arguments
    r"\s+=\s+(?P<result>.*)"      # Result
)

# Regex to find a quoted path, usually the first argument
PATH_REGEX = re.compile(r'"(?P<path>[^"]+)"')

# Syscalls known to be related to network operations
NETWORK_SYSCALLS = {
    "socket", "connect", "bind", "accept", "accept4", "sendto", "recvfrom",
    "listen", "getpeername", "getsockname", "setsockopt", "getsockopt",
    "sendmsg", "recvmsg", "shutdown"
}

# Syscalls known to take a file path as one of their primary arguments.
# This is the key to fixing the bug.
PATH_SYSCALLS = {
    "access", "faccessat", "faccessat2",
    "stat", "lstat", "fstatat", "newfstatat", "statx",
    "readlink", "readlinkat",
    "execve", "execveat",
    "openat", "openat2",
    "renameat", "renameat2", "symlinkat", "mkdirat", "unlinkat",
    "statfs", "fchmodat", "fchownat", "linkat", "utimensat"
}

def parse_strace_line(line):
    """
    Parses a single line of strace output into a structured dictionary.
    Returns None if the line is not a valid syscall execution line.
    """
    match = LINE_REGEX.match(line.strip())
    if not match:
        return None

    syscall = match.group("syscall")
    args = match.group("args")
    
    details = {
        "syscall": syscall,
        "is_network": syscall in NETWORK_SYSCALLS,
        "path": None,
        "is_read": False,
        "is_write": False
    }

    # --- File Access Logic ---
    # **FIX:** Only search for a path if the syscall is known to handle paths.
    if syscall in PATH_SYSCALLS:
        path_match = PATH_REGEX.search(args)
        if path_match:
            path = path_match.group("path")
            # Ignore abstract socket paths
            if not path.startswith('@'):
                details["path"] = path

    # Check for read operations
    read_syscalls = {
        "access", "faccessat", "faccessat2",
        "stat", "lstat", "fstatat", "newfstatat", "statx",
        "readlink", "readlinkat",
        "execve", "execveat",
        "openat", "openat2"
    }
    if syscall in read_syscalls:
        # For openat/openat2, be more specific
        if syscall in ("openat", "openat2"):
            if "O_WRONLY" not in args:  # O_RDONLY or O_RDWR are reads
                details["is_read"] = True
        else:
            details["is_read"] = True
            
    # Check for write operations
    write_syscalls = {
        "openat", "openat2",
        "renameat", "renameat2", "symlinkat", "mkdirat", "unlinkat",
        "fchmodat", "fchownat", "linkat", "utimensat"
    }
    if syscall in write_syscalls:
        if syscall in ("openat", "openat2"):
            if "O_WRONLY" in args or "O_RDWR" in args or "O_CREAT" in args:
                details["is_write"] = True
        else:
            details["is_write"] = True
            
    return details

# The parse_strace_output function remains the same.
def parse_strace_output(strace_output):
    """
    Parses a full block of strace output. Used for profiling.
    """
    syscalls = set()
    read_files = set()
    write_files = set()
    network_activity = False

    for line in strace_output.strip().split('\n'):
        parsed = parse_strace_line(line)
        if not parsed:
            continue
        
        syscalls.add(parsed["syscall"])
        
        if parsed["is_network"]:
            network_activity = True
        
        if parsed["is_read"] and parsed["path"]:
            read_files.add(parsed["path"])
            
        if parsed["is_write"] and parsed["path"]:
            write_files.add(parsed["path"])

    return {
        "allowed_syscalls": sorted(list(syscalls)),
        "file_access": {
            "read": sorted(list(read_files)),
            "write": sorted(list(write_files)),
        },
        "network": {
            "allowed": network_activity
        }
    }