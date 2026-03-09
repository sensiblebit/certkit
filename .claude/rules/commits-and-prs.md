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

Required push gate:

1. If a PR exists, query for new review comments and issue-style PR comments first
2. Address any newly arrived feedback before continuing
3. Spawn one agent specifically to check this branch against `CLAUDE.md` and `.claude/rules/*`
4. Have that agent report any rule violations, missing changelog entries, unresolved PR-thread obligations, or skipped validation
5. Fix every violation before pushing
6. If a PR exists, query for comments again immediately before `git push` in case new feedback arrived during the audit/fix cycle
7. Address that feedback too if needed
8. Only then push

This audit is mandatory even if the change looks trivial. Treat it as a pre-push policy check, not an optional extra review.

If the user requests a commit on a branch that already has a PR open, pushing the branch is implied after the commit and after the pre-push audit passes.

## Addressing PR feedback

When working on a PR, address **both** PR review comments (on diffs) and issue-style comments (on the PR conversation). For each piece of feedback:

1. **Fix the code** — make the requested change or explain why not
2. **Reply** explaining what was done: `gh api repos/OWNER/REPO/pulls/N/comments -X POST -F body="..." -F in_reply_to=COMMENT_ID`
3. **Resolve** the thread: `gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: "THREAD_ID"}) { thread { isResolved } } }'`
4. **Minimize** addressed comments to reduce noise: `gh api graphql -f query='mutation { minimizeComment(input: {subjectId: "COMMENT_NODE_ID", classifier: RESOLVED}) { minimizedComment { isMinimized } } }'`

If you disagree with feedback, do not silently ignore it. Reply with the technical reason, leave the thread unresolved unless the reviewer/user explicitly agrees, and do not minimize unresolved disagreement.

To get thread IDs and comment node IDs, query:

```sh
gh api graphql -f query='{
  repository(owner: "sensiblebit", name: "certkit") {
    pullRequest(number: N) {
      reviewThreads(first: 50) {
        nodes {
          id
          isResolved
          comments(first: 5) {
            nodes { id databaseId body }
          }
        }
      }
      comments(first: 50) {
        nodes { id databaseId body }
      }
    }
  }
}'
```

For issue-style comments (PR conversation), use `minimizeComment` with the comment's node `id`. For review comments, reply + resolve + minimize.

Just replying does NOT mark the thread as resolved or minimized in the GitHub UI — all three steps are required.

After resolving comments, re-query the PR. Do not assume the comment queue is empty until the API shows no unresolved review threads and no unaddressed issue-style feedback.

## Merging PRs

1. Wait for **all** CI checks to complete — including non-blocking checks like `claude-review`. Post-merge review comments require follow-up PRs.
2. Check for new review comments (`gh api repos/.../pulls/N/comments`, `gh api repos/.../issues/N/comments`) before merging.
3. Confirm there are no unresolved review threads and that resolved threads/comments have been minimized where appropriate.
4. Confirm the branch is up to date with `main`.
5. Use squash merge: `gh pr merge N --squash --delete-branch`

## Changelog refs (CL-3)

Each changelog entry must reference the commit or PR **where the change was made**, not the PR where the bug was found. A follow-up fix PR gets its own ref, even if it addresses findings from an earlier PR.
