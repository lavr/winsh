#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"
if [[ "${1:-}" == status ]]; then
    git status --short
    git log -1 --oneline
    git tag --list 'v*' --sort=-version:refname | head -5
    exit 0
fi
if [[ $# != 1 || ! "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo 'Usage: ./release.sh status | vMAJOR.MINOR.PATCH' >&2
    exit 1
fi
release_version="$1"
[[ "$(git branch --show-current)" == main ]] || { echo 'Release from main' >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo 'Working tree must be clean' >&2; exit 1; }
if git show-ref --verify --quiet "refs/tags/$release_version"; then
    echo 'Tag already exists' >&2
    exit 1
fi
git fetch origin main --tags
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || { echo 'main must match origin/main' >&2; exit 1; }
: "${WINSH_TEST_ENDPOINT:?Run release with live Windows smoke-test configuration}"
: "${WINSH_TEST_USER:?Set live Windows smoke-test user}"
: "${WINSH_TEST_PASSWORD:?Set live Windows smoke-test password through the environment}"
make check integration cross-build VERSION="$release_version"
git tag -a "$release_version" -m "winsh $release_version"
git push origin "refs/tags/$release_version"
