---
description: Git conventions for commits, branches, and PRs
---

# Commit & PR Conventions

These rules supplement `CLAUDE.md`. If there is any conflict, `CLAUDE.md` wins.

## Conventional Commits (enforced by CI and pre-commit)

Both commit messages AND PR titles must follow Conventional Commits:

```text
type: short description

Optional body explaining why.
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

Scope is optional: `fix(jks): handle empty alias`.

Bad: `Update stuff`, `Fix bug`, `WIP`
Good: `feat: add PKCS#7 export`, `fix(jks): handle empty alias`

## Branch naming

Create branches as `type/description` (kebab-case):

```text
feat/export-csv
fix/nil-panic
ci/add-govulncheck
```

Exempt: `dependabot/*`, `release/*`.

## Verified commits

All commits must be signed/verified. CI rejects unverified commits.

## Before committing

1. Commit message follows `type: description` format
2. Commits are signed (GPG or SSH)
3. Branch name follows `type/description` format
4. If production code changed, CHANGELOG.md is updated in the same commit
5. Run `pre-commit run --all-files` and fix every failure before committing

Do not rely on "it probably passes". The required local gate is `pre-commit run --all-files`, because that matches the enforced repo checks more closely than ad hoc individual commands.

## Pre-commit hook failures

When a pre-commit hook modifies files (e.g., goimports reformats struct alignment), the commit did NOT happen. To recover:

1. Re-stage the modified files: `git add <files>`
2. Create a NEW commit (same message is fine)
3. Do NOT use `--amend` for that failed attempt — there is no commit to amend

This is especially common with `goimports` reformatting Go files.

## Before pushing

Before **every** `git push`, launch a dedicated reviewer agent whose only job is to audit the current branch for rule adherence.

Use `.github/scripts/pr-comments.py` as the default PR comment tool. Do not fall back to raw `gh api graphql` one-liners or `jq` pipelines for the normal review loop unless the helper is broken and you need a temporary break-glass query.

Preferred commands:

```sh
python3 .github/scripts/pr-comments.py snapshot
python3 .github/scripts/pr-comments.py snapshot --json --unresolved-only
python3 .github/scripts/pr-comments.py show --url <comment-url>
python3 .github/scripts/pr-comments.py reply --url <comment-url> --body "Fixed in <sha>"
python3 .github/scripts/pr-comments.py resolve --url <comment-url>
python3 .github/scripts/pr-comments.py minimize --url <comment-url>
```

Required push gate:

1. If a PR exists, query for new review comments and issue-style PR comments first
2. Address any newly arrived feedback before continuing
3. Before spawning new agents, close stale completed agents so the active agent budget is reserved for current work
4. Spawn one agent specifically to check this branch against `CLAUDE.md` and `.claude/rules/*`
5. If a PR exists, spawn a second dedicated docs-checking agent for that PR
6. The docs-checking agent must review `README.md`, `EXAMPLES.md`, `.claude/docs/architecture.md`, generated CLI docs, and `CHANGELOG.md` for drift against the current code and command surface
7. Have both agents report any rule violations, doc drift, missing changelog entries, unresolved PR-thread obligations, or skipped validation
8. Run a CLI LSP pass for Go changes before pushing so editor-only diagnostics are not missed. Prefer `gopls check` on the changed Go files or a host-build Go file set; do not treat known cross-target `js/wasm` workspace false positives as blockers for host-only PRs
9. When fixes are needed and can be cleanly isolated, dispatch dedicated worker agents to make the code or docs changes instead of doing all fix work in the main thread
10. Keep the main thread focused on PR context, review triage, rule compliance, integration, and final verification
11. Fix every violation before pushing
12. If a PR exists, query for comments again immediately before `git push` in case new feedback arrived during the audit/fix cycle
13. Address that feedback too if needed
14. Only then push

When reporting PR comment state to the user, pull a fresh snapshot immediately before answering. Do not rely on an earlier query once more work, waiting, or other GitHub activity has happened.

This audit is mandatory even if the change looks trivial. Treat it as a pre-push policy check, not an optional extra review.

If the user requests a commit on a branch that already has a PR open, pushing the branch is implied after the commit and after the pre-push audit passes.

## Addressing PR feedback

When working on a PR, address **both** PR review comments (on diffs) and issue-style comments (on the PR conversation). For each piece of feedback:

1. **Fix the code** — make the requested change or explain why not
2. **Prefer delegated fixes** — when the fix is more than a trivial one-line change, spawn a worker agent to make the change so the main thread preserves PR context and review state
3. **Reply** explaining what was done: `python3 .github/scripts/pr-comments.py reply --url <comment-url> --body "Fixed in <sha>"`
4. **Resolve** the thread: `python3 .github/scripts/pr-comments.py resolve --url <comment-url>`
5. **Minimize** addressed comments to reduce noise: `python3 .github/scripts/pr-comments.py minimize --url <comment-url>`

If you disagree with feedback, do not silently ignore it. Reply with the technical reason, leave the thread unresolved unless the reviewer/user explicitly agrees, and do not minimize unresolved disagreement.

To inspect a specific thread or comment in full, use:

```sh
python3 .github/scripts/pr-comments.py show --url <comment-url>
python3 .github/scripts/pr-comments.py show --thread-id <thread-id>
```

For issue-style comments (PR conversation), use `python3 .github/scripts/pr-comments.py minimize --url <comment-url>`. For review comments, reply + resolve + minimize.

Just replying does NOT mark the thread as resolved or minimized in the GitHub UI — all three steps are required.

After resolving comments, re-query the PR with `python3 .github/scripts/pr-comments.py snapshot`. Do not assume the comment queue is empty until the snapshot shows no unresolved review threads and no unaddressed issue-style feedback.

If the user asks whether there are comments, new feedback, or whether the PR is clear, fetch a fresh PR comment snapshot right before answering. Do not answer from memory or from an older query result.

For PRs that change behavior, flags, command output, or package structure, also run the dedicated docs-checking agent before pushing or answering "is this ready?". It must explicitly confirm whether `README.md`, `EXAMPLES.md`, `.claude/docs/architecture.md`, generated CLI docs, and `CHANGELOG.md` still match the branch.

## Merging PRs

1. Wait for **all** CI checks to complete — including non-blocking checks like `claude-review`. Post-merge review comments require follow-up PRs.
2. Check for new review comments (`gh api repos/.../pulls/N/comments`, `gh api repos/.../issues/N/comments`) before merging.
3. Confirm there are no unresolved review threads and that resolved threads/comments have been minimized where appropriate.
4. Confirm the branch is up to date with `main`.
5. Use squash merge: `gh pr merge N --squash --delete-branch`

## Changelog refs (CL-3)

Each changelog entry must reference the commit or PR **where the change was made**, not the PR where the bug was found. A follow-up fix PR gets its own ref, even if it addresses findings from an earlier PR.
