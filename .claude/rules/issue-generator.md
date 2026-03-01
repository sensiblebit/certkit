---
description: Issue generation cycle automation
---

# Issue generator

Trigger: user says "run issue generator" or "issue generator".

Behavior: unattended YOLO-style discovery run focused on creating actionable GitHub issues (not implementing fixes). Do not ask questions. Draft a brief approach and investigation plan, then proceed without waiting for confirmation.

## Flow

1. Fresh-main baseline

   - Ensure local `main` is clean and synced with `origin/main`.
   - If currently on another branch, switch to `main` and fast-forward to `origin/main`.
   - All analysis must be based on this fresh `main` state.

1. Scope and constraints

   - Review the entire repository (library, CLI, internal packages, tests, docs, web when relevant).
   - Identify at least 10 distinct problems.
   - Group related findings into fewer issues when they share root cause or remediation path.
   - Prefer behavior-impacting, user-facing, correctness, security, reliability, performance, and standards violations over style-only nits.

1. Existing-issues dedupe pass (required)

   - Before drafting any new issue, query existing open issues with `gh issue list` and `gh issue search`.
   - Build a dedupe map of existing issue title/labels/body themes (bug class, component, symptom).
   - For every candidate finding, explicitly classify as one of:
     - `duplicate` (already tracked; do not create new issue)
     - `related` (partially overlaps; create only if scope is meaningfully different, and cross-link)
     - `new` (no meaningful overlap; eligible to open)
   - Never open a new issue without checking and documenting dedupe status.

1. Parallel multi-persona adversarial review

   - Launch parallel Task subagents as distinct reviewer personas with different goals and adversarial mindsets.
   - Use a minimum of 7 personas, each implemented as an individual parallel agent.
   - Required baseline personas (5):
     - Security attacker: abuse inputs, trust boundaries, secret handling, unsafe defaults.
     - Correctness auditor: logic errors, edge-case failures, API contract drift.
     - Test skeptic: missing/weak coverage, false confidence, rule violations (T-1..T-14).
     - CLI/UX contract enforcer: stdout/stderr correctness, JSON contract, exit-code semantics (CLI-1..CLI-7).
     - Performance/reliability engineer: timeout gaps, leak risks, expensive paths, retry/backoff misuse.
   - Add at least 2 creative personas per run (examples):
     - Chaos monkey operator: looks for brittle assumptions, partial-failure handling, and degraded-mode behavior.
     - Documentation prosecutor: finds mismatches between docs/help text and actual behavior/flags/output.
     - Backward-compatibility guardian: hunts for behavior changes that could break existing scripts/integrations.
     - Data-shape validator: focuses on JSON field consistency, naming drift, and schema-like contract regressions.
     - Incident responder: prioritizes high-blast-radius failure paths and observability blind spots.
     - Dependency/risk analyst: evaluates third-party usage, vulnerable surfaces, and upgrade landmines.
   - Persona prompts must clearly state unique goals, anti-goals, and severity criteria so agents do not converge on identical findings.
   - Record the persona roster used in the final report.
   - Personas must work independently first, then findings are merged and deduplicated centrally.
   - Consolidate findings into a prioritized, deduplicated list.

1. Validate each finding

   - Confirm each finding with direct file references and concrete evidence.
   - Include severity, impact, and a clear expected-vs-actual statement.
   - Discard weak or speculative findings.

1. Issue drafting

   - Create GitHub issues with `gh issue create` only for findings classified as `new` or clearly `related` but distinct.
   - Use one issue per grouped problem set.
   - Each issue body should include:
     - Summary
     - Why this matters
     - Evidence (file references, command output snippets if helpful)
     - Acceptance criteria
     - Suggested approach (short, non-binding)
     - Dedupe notes (existing issue links checked, and why this is not a duplicate)
   - Apply labels when available (e.g., `bug`, `security`, `tests`, `performance`, `cli`, `docs`).
   - If `related`, include explicit cross-links (`Related: #123`) in both direction when appropriate.

1. Minimum output requirements

   - Open enough issues to cover at least 10 total problems.
   - If grouped, explicitly list every underlying problem in the issue body.
   - Return a final report containing:
     - Total problems found
     - Number of issues opened
     - Issue URLs
     - Mapping of problem -> issue

1. Non-goals

   - Do not implement fixes in this cycle.
   - Do not create commits or PRs unless explicitly requested.

1. Quality bar

   - Prefer fewer, higher-signal issues over many low-value ones.
   - Dedupe against existing issues is mandatory and evidenced in the final report.
   - Keep issues reproducible and specific enough for another engineer to execute without re-discovery.
