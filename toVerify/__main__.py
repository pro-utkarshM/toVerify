import argparse
import sys

from .core import do_profile, do_verify

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
