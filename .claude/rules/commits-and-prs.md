---
description: Git conventions for commits, branches, and PRs
---

# Commit & PR Conventions

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
5. All code compiles and tests pass

## Pre-commit hook failures

When a pre-commit hook modifies files (e.g., goimports reformats struct alignment), the commit did NOT happen. To recover:

1. Re-stage the modified files: `git add <files>`
2. Create a NEW commit (same message is fine)
3. Do NOT use `--amend` — the previous commit never happened

This is especially common with `goimports` reformatting Go files.

## Resolving PR review threads

When addressing review feedback, both reply AND resolve:

1. **Reply** via REST: `gh api repos/OWNER/REPO/pulls/N/comments -X POST -F body="..." -F in_reply_to=COMMENT_ID`
2. **Resolve** via GraphQL: `gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: "THREAD_ID"}) { thread { isResolved } } }'`

To get thread IDs, query:

```sh
gh api graphql -f query='{
  repository(owner: "sensiblebit", name: "certkit") {
    pullRequest(number: N) {
      reviewThreads(first: 20) {
        nodes { id isResolved comments(first: 1) { nodes { body } } }
      }
    }
  }
}'
```

Just replying does NOT mark the thread as resolved in the GitHub UI.

## Merging PRs

1. Wait for **all** CI checks to complete — including non-blocking checks like `claude-review`. Post-merge review comments require follow-up PRs.
2. Check for new review comments (`gh api repos/.../pulls/N/comments`, `gh api repos/.../issues/N/comments`) before merging.
3. Use squash merge: `gh pr merge N --squash --delete-branch`

## Changelog refs (CL-3)

Each changelog entry must reference the commit or PR **where the change was made**, not the PR where the bug was found. A follow-up fix PR gets its own ref, even if it addresses findings from an earlier PR.
