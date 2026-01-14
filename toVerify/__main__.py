"""toVerify CLI - Profile and verify command behavior using strace."""

import argparse
import sys

from .core import do_profile, do_verify, StraceNotFoundError, ProfileError
from .profile import do_validate, do_diff


def main():
    parser = argparse.ArgumentParser(
        prog="toVerify",
        description="A tool to profile and verify command execution behavior using strace.",
        epilog="Examples:\n"
               "  toVerify --profile 'ls -l /tmp' --output-file ls_tmp.yaml\n"
               "  toVerify --verify ls_tmp.yaml --command 'ls -l /tmp'",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Main mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--profile", metavar="CMD",
        help="Profile the given command and capture its behavior."
    )
    mode_group.add_argument(
        "--verify", metavar="PROFILE_FILE",
        help="Verify a command against a behavior profile."
    )
    mode_group.add_argument(
        "--validate", metavar="PROFILE_FILE",
        help="Validate a profile's syntax and structure."
    )
    mode_group.add_argument(
        "--diff", nargs=2, metavar=("PROFILE1", "PROFILE2"),
        help="Compare two profiles and show differences."
    )
    
    # Output options
    parser.add_argument(
        "--output-file", "-o", metavar="FILE",
        help="File to save the profile to (required with --profile)."
    )
    parser.add_argument(
        "--command", "-c", metavar="CMD",
        help="The command to run for verification (required with --verify)."
    )
    parser.add_argument(
        "--timeout", "-t", metavar="SECONDS", type=int,
        help="Timeout in seconds for command execution (default: 300)."
    )
    
    # Verbosity options
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed output including all syscalls being checked."
    )
    verbosity_group.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress all output except errors and violations."
    )
    
    # Verification options
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report all violations without terminating the process (used with --verify)."
    )

    args = parser.parse_args()
    
    # Determine verbosity level: 0=quiet, 1=normal, 2=verbose
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2
    else:
        verbosity = 1

    try:
        if args.profile:
            if not args.output_file:
                parser.error("--output-file is required when using --profile.")
            do_profile(
                args.profile,
                args.output_file,
                timeout=args.timeout,
                verbosity=verbosity
            )
        elif args.verify:
            if not args.command:
                parser.error("--command is required when using --verify.")
            do_verify(
                args.verify,
                args.command,
                verbosity=verbosity,
                dry_run=args.dry_run
            )
        elif args.validate:
            do_validate(
                args.validate,
                verbosity=verbosity
            )
        elif args.diff:
            do_diff(
                args.diff[0],
                args.diff[1],
                verbosity=verbosity
            )
    except StraceNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ProfileError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
