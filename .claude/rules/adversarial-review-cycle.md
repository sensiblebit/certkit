---
description: Adversarial review cycle automation
---

# Adversarial review cycle

Trigger: user says "execute adversarial review cycle" or "yolo review cycle".

Behavior: unattended YOLO run. Do not ask questions. Draft a brief approach and test plan, then proceed without waiting for confirmation.

## Flow

1. Evaluation

   - Launch adversarial reviewers (in parallel) on the current branch to produce findings.
   - Summarize the highest-severity issue into a short slug (2-4 words) to name the branch.

1. Branch/PR setup

   - If the current branch already has an open PR, stay on it and use that PR.
   - If no PR exists:

     - If on main, create a new branch from main named `fix/<slug>` where `<slug>` is derived from the top finding (e.g., `fix/export-path-sanitization`).
     - If on a non-main branch, keep the branch and open a PR from it (do not rename unless required by branch rules).

   - If there are no findings, use `fix/yolo-review-cycle` (or `fix/yolo-review-cycle-YYYYMMDD` if taken).
   - Use `gh` to detect/handle PRs and to create a new PR when needed.

1. Launch adversarial reviewers (in parallel)

   - Use Task subagents to produce deep, adversarial findings in these areas:

     - Security & input handling (SEC, ERR, CLI rules)
     - Code correctness & standards (ERR, CS, API, CTX, CC rules)
     - Tests & coverage quality (T-1..T-14, table-driven, right scope)
     - UX/CLI output consistency & design standards (CLI-1..CLI-7)

   - Aggregate findings into a prioritized list with file references and severity.

1. Plan + implementation

   - Create `IMPLEMENTATION_PLAN.md` with 3-5 stages (goal, success criteria, tests, status). Update as you work. Remove the file before the final commit.
   - Apply fixes with minimal changes, matching existing patterns. Avoid new dependencies unless clearly justified.
   - If behavior changes, update `CHANGELOG.md` under `## [Unreleased]` with proper refs.

1. Address PR feedback

   - If the PR has review or issue comments, address every item.
   - Reply, resolve threads, and minimize addressed comments per `.claude/rules/commits-and-prs.md`.

1. Tests and quality gates

   - Run `pre-commit run --all-files` and fix failures.
   - Run targeted tests when appropriate; use `go test` for focused validation before full pre-commit when helpful.

1. Human review exceptions

   - Only when a decision truly needs human input, create or update `HUMAN_REVIEW.md` with concise bullets describing the decision and impact.

1. Commit and push

   - If there are changes, commit with a Conventional Commit message that explains why.
   - Push the branch so CI/Claude/Copilot/Codex re-runs.
   - If no changes, do not create an empty commit.

1. Repeat

   - Repeat the cycle until no new findings and no open feedback remain.
