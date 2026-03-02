#!/usr/bin/env bash

set -euo pipefail

branch_name="$(git rev-parse --abbrev-ref HEAD)"

if [[ "$branch_name" == "develop" ]]; then
  exit 0
fi

if [[ "$branch_name" =~ ^(dependabot|release)/ ]]; then
  exit 0
fi

if [[ "$branch_name" =~ ^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)/ ]]; then
  exit 0
fi

echo "Branch \"$branch_name\" does not follow type/description convention." >&2
echo "Valid types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert" >&2
echo "Examples: feat/export-csv, fix/nil-panic, ci/add-govulncheck" >&2
echo "Also allowed: develop, dependabot/*, release/*" >&2
exit 1
