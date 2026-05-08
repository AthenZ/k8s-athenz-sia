#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <checkout-dir> <repo-url> <ref>" >&2
  exit 1
fi

checkout_dir="$1"
repo_url="$2"
ref="$3"
resolved_ref="$ref"

mkdir -p "$(dirname "$checkout_dir")"

if [[ ! -d "$checkout_dir/.git" ]]; then
  git clone "$repo_url" "$checkout_dir"
fi

git -C "$checkout_dir" fetch --tags origin

if [[ "$ref" == "latest" ]]; then
  git -C "$checkout_dir" remote set-head origin -a >/dev/null 2>&1 || true
  default_branch="$(git -C "$checkout_dir" symbolic-ref --short refs/remotes/origin/HEAD | sed 's@^origin/@@')"
  resolved_ref="origin/$default_branch"
fi

git -C "$checkout_dir" checkout "$resolved_ref"

echo "Prepared athenz-distribution at $checkout_dir ($resolved_ref)"