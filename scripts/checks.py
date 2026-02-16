#!/usr/bin/env python3
"""Shared checks for pre-commit hooks and CI.

Usage:
    checks.py branch-name [<name>]
    checks.py commit-message <file>
    checks.py commit-message --ci [<base-ref>]
    checks.py goimports [--fix] [<files>...]
    checks.py wasm
    checks.py verified-commits <repo> <pr-number>
"""

import argparse
import json
import os
import re
import subprocess
import sys

VALID_TYPES = [
    "feat", "fix", "docs", "style", "refactor",
    "perf", "test", "build", "ci", "chore", "revert",
]
TYPES_PATTERN = "|".join(VALID_TYPES)
TYPES_LIST = ", ".join(VALID_TYPES)

COMMIT_RE = re.compile(rf"^({TYPES_PATTERN})(\(.+\))?: .+")
BRANCH_RE = re.compile(rf"^({TYPES_PATTERN})/")
EXEMPT_RE = re.compile(r"^(dependabot|release)/")


def run(cmd, **kwargs):
    """Run a command and return the CompletedProcess."""
    return subprocess.run(cmd, **kwargs)


def run_output(cmd):
    """Run a command and return its stdout as a string."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip(), result.returncode


def fail(message):
    """Print an error message and exit."""
    print(message, file=sys.stderr)
    sys.exit(1)


# ── branch-name ──────────────────────────────────────────


def cmd_branch_name(args):
    """Check branch naming convention: type/description."""
    if args.name:
        branch = args.name
    else:
        output, rc = run_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        if rc != 0:
            fail("Could not determine branch name.")
        branch = output

    if EXEMPT_RE.match(branch):
        return

    if BRANCH_RE.match(branch):
        return

    print(f'Branch "{branch}" does not follow type/description convention.')
    print(f"Valid types: {TYPES_LIST}")
    print("Examples: feat/export-csv, fix/nil-panic, ci/add-govulncheck")
    sys.exit(1)


# ── commit-message ───────────────────────────────────────


def check_subject(subject):
    """Validate a single commit message subject line. Returns True if valid."""
    if subject.startswith("Merge"):
        return True
    return bool(COMMIT_RE.match(subject))


def print_commit_error(subject):
    """Print a helpful error for an invalid commit message."""
    print(f"Invalid commit message: {subject}")
    print()
    print("Expected format:")
    print("  type: description")
    print("  type(scope): description")
    print()
    print(f"Valid types: {TYPES_LIST}")


def cmd_commit_message(args):
    """Check commit messages follow Conventional Commits."""
    if args.ci:
        # CI mode: check all commits between base and HEAD.
        base = args.base_ref or "origin/main"
        output, rc = run_output(["git", "rev-list", f"{base}..HEAD"])
        if rc != 0:
            fail(f"Could not list commits from {base}..HEAD")

        if not output:
            print("No commits to check.")
            return

        failed = False
        for sha in output.splitlines():
            subject, _ = run_output(["git", "log", "--format=%s", "-n1", sha])
            if not check_subject(subject):
                print_commit_error(subject)
                print(f"  commit: {sha[:7]}")
                print()
                failed = True

        if failed:
            sys.exit(1)

        print("All commit messages follow Conventional Commits format.")
    else:
        # commit-msg hook mode: check the message file.
        if not args.file:
            fail("Usage: checks.py commit-message <file>")

        with open(args.file) as f:
            subject = f.readline().strip()

        if not check_subject(subject):
            print_commit_error(subject)
            sys.exit(1)


# ── goimports ────────────────────────────────────────────


def cmd_goimports(args):
    """Check or fix Go import ordering."""
    gopath, _ = run_output(["go", "env", "GOPATH"])
    os.environ["PATH"] = f"{gopath}/bin:{os.environ.get('PATH', '')}"

    # Install goimports if not available.
    result = run(["which", "goimports"], capture_output=True)
    if result.returncode != 0:
        print("Installing goimports...")
        run(["go", "install", "golang.org/x/tools/cmd/goimports@latest"], check=True)

    if args.fix:
        # Fix mode: rewrite files in place.
        targets = args.files if args.files else ["."]
        run(["goimports", "-w"] + targets, check=True)
    else:
        # Check mode: list files with incorrect imports.
        output, _ = run_output(["goimports", "-l", "."])
        if output:
            print("The following files have incorrect imports:")
            print(output)
            sys.exit(1)


# ── wasm ─────────────────────────────────────────────────


def cmd_wasm(args):
    """Verify WASM target compiles cleanly (vet + build)."""
    env = {**os.environ, "GOOS": "js", "GOARCH": "wasm"}

    print("Running go vet (WASM)...")
    result = run(["go", "vet", "./cmd/wasm/"], env=env)
    if result.returncode != 0:
        sys.exit(result.returncode)

    print("Running go build (WASM)...")
    result = run(["go", "build", "-o", "/dev/null", "./cmd/wasm/"], env=env)
    if result.returncode != 0:
        sys.exit(result.returncode)


# ── verified-commits ─────────────────────────────────────


def cmd_verified_commits(args):
    """Verify all commits in a PR are signed/verified."""
    result = subprocess.run(
        [
            "gh", "api", "--paginate",
            f"repos/{args.repo}/pulls/{args.pr}/commits",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        fail(f"GitHub API error: {result.stderr}")

    commits = json.loads(result.stdout)
    failed = False

    for commit in commits:
        sha = commit["sha"][:7]
        verified = commit["commit"]["verification"]["verified"]
        subject = commit["commit"]["message"].split("\n")[0]

        if not verified:
            print(f"Unverified commit: {sha} {subject}")
            failed = True

    if failed:
        print()
        print("All commits must be signed.")
        print("See: https://docs.github.com/en/authentication/managing-commit-signature-verification")
        sys.exit(1)

    print("All commits are verified.")


# ── main ─────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Shared checks for pre-commit and CI.")
    sub = parser.add_subparsers(dest="command", required=True)

    # branch-name
    p = sub.add_parser("branch-name", help="Check branch naming convention.")
    p.add_argument("name", nargs="?", help="Branch name (auto-detected if omitted).")

    # commit-message
    p = sub.add_parser("commit-message", help="Check commit message format.")
    p.add_argument("file", nargs="?", help="Commit message file (commit-msg hook).")
    p.add_argument("--ci", action="store_true", help="CI mode: check all PR commits.")
    p.add_argument("--base-ref", help="Base ref for CI mode (default: origin/main).")

    # goimports
    p = sub.add_parser("goimports", help="Check or fix Go import ordering.")
    p.add_argument("--fix", action="store_true", help="Fix files in place.")
    p.add_argument("files", nargs="*", help="Specific files to fix.")

    # wasm
    sub.add_parser("wasm", help="Verify WASM target compiles.")

    # verified-commits
    p = sub.add_parser("verified-commits", help="Check PR commits are signed.")
    p.add_argument("repo", help="Repository (owner/repo).")
    p.add_argument("pr", help="PR number.")

    args = parser.parse_args()

    commands = {
        "branch-name": cmd_branch_name,
        "commit-message": cmd_commit_message,
        "goimports": cmd_goimports,
        "wasm": cmd_wasm,
        "verified-commits": cmd_verified_commits,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
