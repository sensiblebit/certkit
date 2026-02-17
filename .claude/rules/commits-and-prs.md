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
