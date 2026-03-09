#!/usr/bin/env python3
"""PR comment helper for review triage.

This is a thin wrapper around `gh api graphql` plus one REST endpoint for
review-comment replies. It exists to replace ad hoc shell one-liners with:

- reusable GraphQL documents
- predictable output for fresh PR snapshots
- direct URL-based operations for reply / resolve / minimize

Typical usage:
    .github/scripts/pr-comments.py snapshot
    .github/scripts/pr-comments.py snapshot --json
    .github/scripts/pr-comments.py show --url <comment-url>
    .github/scripts/pr-comments.py reply --url <comment-url> --body "Fixed in abc123"
    .github/scripts/pr-comments.py resolve --url <comment-url>
    .github/scripts/pr-comments.py minimize --url <comment-url>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


SCRIPT_DIR = Path(__file__).resolve().parent
GRAPHQL_DIR = SCRIPT_DIR / "graphql" / "pr"
DEFAULT_MINIMIZE_CLASSIFIER = "RESOLVED"


class CommandError(RuntimeError):
    """Raised when an external command or lookup fails."""


def run(cmd: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command and return the completed process."""
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def require_success(result: subprocess.CompletedProcess[str], *, context: str) -> str:
    """Return stdout or raise a readable command error."""
    if result.returncode == 0:
        return result.stdout
    stderr = result.stderr.strip()
    stdout = result.stdout.strip()
    detail = stderr or stdout or f"exit code {result.returncode}"
    raise CommandError(f"{context}: {detail}")


def run_json(cmd: list[str], *, context: str) -> Any:
    """Run a command expected to return JSON."""
    stdout = require_success(run(cmd), context=context)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as err:
        raise CommandError(f"{context}: invalid JSON output: {err}") from err


def load_graphql(name: str) -> str:
    """Load a GraphQL document by basename."""
    path = GRAPHQL_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as err:
        raise CommandError(f"missing GraphQL template: {path}") from err


def gh_graphql(document: str, **variables: Any) -> Any:
    """Run a GraphQL operation through gh."""
    query = load_graphql(document)
    cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
    for key, value in variables.items():
        cmd.extend(["-F", f"{key}={value}"])
    return run_json(cmd, context=f"running GraphQL {document}")


def current_repo() -> tuple[str, str]:
    """Return (owner, repo) for the current checkout."""
    payload = run_json(
        ["gh", "repo", "view", "--json", "owner,name"],
        context="detecting current repo",
    )
    return payload["owner"]["login"], payload["name"]


def current_pr() -> dict[str, Any]:
    """Return metadata for the current branch PR."""
    return run_json(
        ["gh", "pr", "view", "--json", "number,title,url,headRefName,baseRefName"],
        context="detecting current pull request",
    )


def resolve_repo_and_pr(args: argparse.Namespace) -> tuple[str, str, int]:
    """Resolve owner, repo, and PR number from args or the current checkout."""
    if args.repo:
        if "/" not in args.repo:
            raise CommandError(f"invalid --repo value {args.repo!r}; expected owner/name")
        owner, repo = args.repo.split("/", 1)
    else:
        owner, repo = current_repo()

    if args.pr is not None:
        pr_number = args.pr
    else:
        pr_number = current_pr()["number"]

    return owner, repo, pr_number


def first_line(body: str) -> str:
    """Return the first non-empty line for summary output."""
    for line in body.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def ellipsize(text: str, limit: int = 120) -> str:
    """Clamp text for one-line summaries."""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    """Fetch and normalize the current PR review state."""
    owner, repo, pr_number = resolve_repo_and_pr(args)
    raw = gh_graphql("snapshot.graphql", owner=owner, repo=repo, number=pr_number)
    pr = raw["data"]["repository"]["pullRequest"]

    unresolved_threads: list[dict[str, Any]] = []
    resolved_threads: list[dict[str, Any]] = []
    all_thread_comments: list[dict[str, Any]] = []

    for thread in pr["reviewThreads"]["nodes"]:
        comments = []
        for comment in thread["comments"]["nodes"]:
            normalized = {
                "id": comment["id"],
                "database_id": comment["databaseId"],
                "url": comment["url"],
                "path": comment.get("path") or "",
                "is_minimized": comment["isMinimized"],
                "author": (comment.get("author") or {}).get("login", ""),
                "body": comment["body"],
            }
            comments.append(normalized)
            all_thread_comments.append({**normalized, "thread_id": thread["id"], "thread_resolved": thread["isResolved"]})

        entry = {
            "thread_id": thread["id"],
            "is_resolved": thread["isResolved"],
            "path": comments[0]["path"] if comments else "",
            "comments": comments,
            "comment_count": len(comments),
            "first_comment": comments[0] if comments else None,
        }
        if thread["isResolved"]:
            resolved_threads.append(entry)
        else:
            unresolved_threads.append(entry)

    all_top_level_comments = [
        {
            "id": comment["id"],
            "database_id": comment["databaseId"],
            "url": comment["url"],
            "is_minimized": comment["isMinimized"],
            "author": (comment.get("author") or {}).get("login", ""),
            "body": comment["body"],
        }
        for comment in pr["comments"]["nodes"]
    ]
    visible_comments = [comment for comment in all_top_level_comments if not comment["is_minimized"]]

    return {
        "repo": {"owner": owner, "name": repo},
        "pull_request": {
            "number": pr["number"],
            "title": pr["title"],
            "url": pr["url"],
        },
        "unresolved_threads": unresolved_threads,
        "resolved_threads": resolved_threads,
        "visible_comments": visible_comments,
        "all_top_level_comments": all_top_level_comments,
        "all_thread_comments": all_thread_comments,
    }


def compact_thread_entry(thread: dict[str, Any]) -> dict[str, Any]:
    """Return a compact unresolved/resolved thread shape."""
    comment = thread["first_comment"] or {}
    return {
        "thread_id": thread["thread_id"],
        "path": thread["path"],
        "url": comment.get("url", ""),
        "author": comment.get("author", ""),
        "body": comment.get("body", ""),
        "preview": ellipsize(first_line(comment.get("body", ""))),
        "comment_count": thread["comment_count"],
    }


def compact_comment_entry(comment: dict[str, Any]) -> dict[str, Any]:
    """Return a compact comment shape."""
    return {
        "id": comment["id"],
        "database_id": comment["database_id"],
        "url": comment["url"],
        "author": comment["author"],
        "body": comment["body"],
        "preview": ellipsize(first_line(comment["body"])),
    }


def filtered_snapshot(snapshot: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Apply snapshot filters and compact shaping."""
    include_unresolved = not args.visible_only
    include_visible = not args.unresolved_only

    result: dict[str, Any] = {
        "repo": snapshot["repo"],
        "pull_request": snapshot["pull_request"],
    }

    if include_unresolved:
        unresolved = [compact_thread_entry(thread) for thread in snapshot["unresolved_threads"]]
        result["unresolved_threads"] = unresolved
        result["unresolved_count"] = len(unresolved)

    if include_visible:
        visible = [compact_comment_entry(comment) for comment in snapshot["visible_comments"]]
        result["visible_comments"] = visible
        result["visible_count"] = len(visible)

    return result


def print_snapshot_summary(snapshot: dict[str, Any]) -> None:
    """Render a compact human summary."""
    pr = snapshot["pull_request"]
    print(f"PR #{pr['number']}: {pr['title']}")
    print(pr["url"])
    print()
    if "unresolved_threads" in snapshot:
        if snapshot["unresolved_threads"]:
            print(f"Unresolved review threads: {len(snapshot['unresolved_threads'])}")
        else:
            print("Unresolved review threads: 0")
        for thread in snapshot["unresolved_threads"]:
            print(f"- [{thread.get('author', '?')}] {thread.get('path', '') or '(no path)'}")
            print(f"  {thread.get('url', '')}")
            print(f"  thread_id={thread.get('thread_id', '')}")
            preview = thread.get("preview", "")
            if preview:
                print(f"  {preview}")

    if "visible_comments" in snapshot:
        if "unresolved_threads" in snapshot:
            print()
        print(f"Visible top-level comments: {len(snapshot['visible_comments'])}")
        for comment in snapshot["visible_comments"]:
            print(f"- [{comment['author'] or '?'}] {comment['url']}")
            print(f"  node_id={comment['id']} database_id={comment['database_id']}")
            preview = comment.get("preview", "")
            if preview:
                print(f"  {preview}")


def find_thread_by_url(snapshot: dict[str, Any], url: str) -> dict[str, Any]:
    """Find a review thread containing the given comment URL."""
    for thread in snapshot["unresolved_threads"] + snapshot["resolved_threads"]:
        for comment in thread["comments"]:
            if comment["url"] == url:
                return thread
    raise CommandError(f"no review thread found for URL: {url}")


def find_review_comment_by_url(snapshot: dict[str, Any], url: str) -> dict[str, Any]:
    """Find a review comment by URL."""
    for comment in snapshot["all_thread_comments"]:
        if comment["url"] == url:
            return comment
    raise CommandError(f"no review comment found for URL: {url}")


def find_any_comment_by_url(snapshot: dict[str, Any], url: str) -> dict[str, Any]:
    """Find either a review comment or a top-level PR comment by URL."""
    for comment in snapshot["all_thread_comments"]:
        if comment["url"] == url:
            return comment
    for comment in snapshot["all_top_level_comments"]:
        if comment["url"] == url:
            return comment
    raise CommandError(f"no PR comment found for URL: {url}")


def find_comment_by_database_id(snapshot: dict[str, Any], database_id: int) -> dict[str, Any]:
    """Find either a review comment or a top-level PR comment by database ID."""
    for comment in snapshot["all_thread_comments"]:
        if comment["database_id"] == database_id:
            return {**comment, "kind": "review_comment"}
    for comment in snapshot["all_top_level_comments"]:
        if comment["database_id"] == database_id:
            return {**comment, "kind": "issue_comment"}
    raise CommandError(f"no PR comment found for database ID: {database_id}")


def find_comment_by_node_id(snapshot: dict[str, Any], node_id: str) -> dict[str, Any]:
    """Find either a review comment or a top-level PR comment by node ID."""
    for comment in snapshot["all_thread_comments"]:
        if comment["id"] == node_id:
            return {**comment, "kind": "review_comment"}
    for comment in snapshot["all_top_level_comments"]:
        if comment["id"] == node_id:
            return {**comment, "kind": "issue_comment"}
    raise CommandError(f"no PR comment found for node ID: {node_id}")


def find_thread_by_id(snapshot: dict[str, Any], thread_id: str) -> dict[str, Any]:
    """Find a review thread by node ID."""
    for thread in snapshot["unresolved_threads"] + snapshot["resolved_threads"]:
        if thread["thread_id"] == thread_id:
            return thread
    raise CommandError(f"no review thread found for thread ID: {thread_id}")


def print_comment_detail(comment: dict[str, Any]) -> None:
    """Render a full comment payload in a human-readable format."""
    print(f"Kind:          {comment.get('kind', 'comment')}")
    print(f"Author:        {comment.get('author') or '?'}")
    print(f"URL:           {comment.get('url') or ''}")
    print(f"Database ID:   {comment.get('database_id')}")
    print(f"Node ID:       {comment.get('id')}")
    if "path" in comment:
        print(f"Path:          {comment.get('path') or '(no path)'}")
    if "thread_id" in comment:
        print(f"Thread ID:     {comment.get('thread_id')}")
        print(f"Thread State:  {'resolved' if comment.get('thread_resolved') else 'unresolved'}")
    print(f"Minimized:     {comment.get('is_minimized')}")
    print()
    print(comment.get("body", ""))


def print_thread_detail(thread: dict[str, Any]) -> None:
    """Render a full review thread payload in a human-readable format."""
    print("Kind:          review_thread")
    print(f"Thread ID:     {thread.get('thread_id')}")
    print(f"Path:          {thread.get('path') or '(no path)'}")
    print(f"State:         {'resolved' if thread.get('is_resolved') else 'unresolved'}")
    print(f"Comments:      {thread.get('comment_count')}")
    print()
    for index, comment in enumerate(thread["comments"], start=1):
        print(f"[{index}] {comment.get('author') or '?'}")
        print(f"  URL:         {comment.get('url') or ''}")
        print(f"  Database ID: {comment.get('database_id')}")
        print(f"  Node ID:     {comment.get('id')}")
        print(f"  Minimized:   {comment.get('is_minimized')}")
        print()
        print(comment.get("body", ""))
        print()


def command_snapshot(args: argparse.Namespace) -> int:
    """Handle snapshot command."""
    snapshot = build_snapshot(args)
    display = filtered_snapshot(snapshot, args)
    if args.json:
        if args.raw:
            print(json.dumps(snapshot, indent=2))
        else:
            print(json.dumps(display, indent=2))
    else:
        print_snapshot_summary(display)
    return 0


def command_show(args: argparse.Namespace) -> int:
    """Show one comment or one review thread in full detail."""
    selectors = [
        bool(args.url),
        bool(args.thread_id),
        args.database_id is not None,
        args.node_id is not None,
    ]
    if sum(selectors) != 1:
        raise CommandError("show requires exactly one of --url, --thread-id, --database-id, or --node-id")

    snapshot = build_snapshot(args)
    if args.thread_id:
        detail = find_thread_by_id(snapshot, args.thread_id)
        if args.json:
            print(json.dumps({"kind": "review_thread", **detail}, indent=2))
        else:
            print_thread_detail(detail)
        return 0

    if args.url:
        try:
            detail = find_thread_by_url(snapshot, args.url)
        except CommandError:
            comment = find_any_comment_by_url(snapshot, args.url)
            kind = "review_comment" if "thread_id" in comment else "issue_comment"
            detail = {**comment, "kind": kind}
        else:
            if args.json:
                print(json.dumps({"kind": "review_thread", **detail}, indent=2))
            else:
                print_thread_detail(detail)
            return 0
    elif args.database_id is not None:
        detail = find_comment_by_database_id(snapshot, args.database_id)
    else:
        detail = find_comment_by_node_id(snapshot, args.node_id)

    if args.json:
        print(json.dumps(detail, indent=2))
    else:
        print_comment_detail(detail)
    return 0


def command_reply(args: argparse.Namespace) -> int:
    """Reply to a review comment."""
    owner, repo, pr_number = resolve_repo_and_pr(args)
    _ = pr_number  # resolved for consistency and clearer failure mode

    if bool(args.url) == bool(args.database_id):
        raise CommandError("reply requires exactly one of --url or --database-id")

    if args.url:
        snapshot = build_snapshot(args)
        comment = find_review_comment_by_url(snapshot, args.url)
        database_id = comment["database_id"]
    else:
        database_id = args.database_id

    body = args.body
    if args.body_file:
        body = Path(args.body_file).read_text(encoding="utf-8")
    if not body:
        raise CommandError("reply requires --body or --body-file")

    payload = run_json(
        [
            "gh",
            "api",
            f"repos/{owner}/{repo}/pulls/comments/{database_id}/replies",
            "-X",
            "POST",
            "-f",
            f"body={body}",
        ],
        context="replying to review comment",
    )
    print(payload.get("html_url", "reply created"))
    return 0


def command_resolve(args: argparse.Namespace) -> int:
    """Resolve a review thread."""
    if bool(args.url) == bool(args.thread_id):
        raise CommandError("resolve requires exactly one of --url or --thread-id")

    if args.url:
        snapshot = build_snapshot(args)
        thread_id = find_thread_by_url(snapshot, args.url)["thread_id"]
    else:
        thread_id = args.thread_id

    payload = gh_graphql("resolve_review_thread.graphql", threadId=thread_id)
    is_resolved = payload["data"]["resolveReviewThread"]["thread"]["isResolved"]
    print(json.dumps({"thread_id": thread_id, "is_resolved": is_resolved}, indent=2))
    return 0


def command_minimize(args: argparse.Namespace) -> int:
    """Minimize a review or top-level PR comment."""
    if bool(args.url) == bool(args.node_id):
        raise CommandError("minimize requires exactly one of --url or --node-id")

    if args.url:
        snapshot = build_snapshot(args)
        node_id = find_any_comment_by_url(snapshot, args.url)["id"]
    else:
        node_id = args.node_id

    payload = gh_graphql(
        "minimize_comment.graphql",
        subjectId=node_id,
        classifier=args.classifier,
    )
    is_minimized = payload["data"]["minimizeComment"]["minimizedComment"]["isMinimized"]
    print(json.dumps({"node_id": node_id, "is_minimized": is_minimized}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="GitHub repo in owner/name form (defaults to current repo)")
    parser.add_argument("--pr", type=int, help="Pull request number (defaults to current branch PR)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot", help="Fetch a fresh PR comment snapshot")
    snapshot_parser.add_argument("--json", action="store_true", help="Print JSON instead of human summary")
    snapshot_group = snapshot_parser.add_mutually_exclusive_group()
    snapshot_group.add_argument("--unresolved-only", action="store_true", help="Show only unresolved review threads")
    snapshot_group.add_argument("--visible-only", action="store_true", help="Show only visible top-level comments")
    snapshot_parser.add_argument("--raw", action="store_true", help="With --json, print the full raw snapshot instead of the compact filtered shape")
    snapshot_parser.set_defaults(func=command_snapshot)

    show_parser = subparsers.add_parser("show", help="Show one review thread or one PR comment in full")
    show_parser.add_argument("--url", help="Comment URL")
    show_parser.add_argument("--thread-id", help="Review thread node ID")
    show_parser.add_argument("--database-id", type=int, help="Comment database ID")
    show_parser.add_argument("--node-id", help="Comment node ID")
    show_parser.add_argument("--json", action="store_true", help="Print JSON instead of a human-readable detail view")
    show_parser.set_defaults(func=command_show)

    reply_parser = subparsers.add_parser("reply", help="Reply to a review comment")
    reply_parser.add_argument("--url", help="Review comment URL to reply to")
    reply_parser.add_argument("--database-id", type=int, help="Review comment database ID")
    reply_group = reply_parser.add_mutually_exclusive_group(required=True)
    reply_group.add_argument("--body", help="Reply body")
    reply_group.add_argument("--body-file", help="Path to a file containing the reply body")
    reply_parser.set_defaults(func=command_reply)

    resolve_parser = subparsers.add_parser("resolve", help="Resolve a review thread")
    resolve_parser.add_argument("--url", help="Review comment URL inside the thread")
    resolve_parser.add_argument("--thread-id", help="Review thread node ID")
    resolve_parser.set_defaults(func=command_resolve)

    minimize_parser = subparsers.add_parser("minimize", help="Minimize a review or top-level PR comment")
    minimize_parser.add_argument("--url", help="Comment URL to minimize")
    minimize_parser.add_argument("--node-id", help="Comment node ID")
    minimize_parser.add_argument(
        "--classifier",
        default=DEFAULT_MINIMIZE_CLASSIFIER,
        help=f"ReportedContentClassifiers value (default: {DEFAULT_MINIMIZE_CLASSIFIER})",
    )
    minimize_parser.set_defaults(func=command_minimize)

    return parser


def main() -> int:
    """Program entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except CommandError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
