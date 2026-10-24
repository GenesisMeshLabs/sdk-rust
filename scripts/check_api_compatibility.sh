#!/usr/bin/env bash
# The public API against the latest release tag (the API compatibility check).
#
# cargo-semver-checks compares the crate with the latest v* tag; only changes
# that need a new major version fail (--release-type minor). When it fails,
# the same check runs on the change's base commit, and only failures new in
# this change count: once a change labelled breaking has merged, later
# changes are not held to it until the next release. A new incompatible
# change passes only when its pull request carries the label "breaking" (the
# Maintainer adds it) and its changes include a changelog fragment with an
# "### Upgrading" note.
#
# Environment (all optional outside CI):
#   EVENT           pull_request, merge_group or push
#   PR_BASE_SHA     pull_request: the base branch commit (merge-base with HEAD)
#   QUEUE_BASE_SHA  merge_group: the queue's base commit
#   QUEUE_REF       merge_group: the queue branch (names the pull request)
#   PUSH_BEFORE     push: the commit before the push
#   PR_NUMBER       pull_request: its number
#   BASE_REF        a base commit, overriding the ones above
#   GITHUB_REPOSITORY, GITHUB_SHA, GH_TOKEN: to read labels with gh
set -uo pipefail

package=genesis-mesh-sdk
baseline="$(git tag --list 'v*' --sort=-v:refname | head -n 1)"
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/api-compatibility.XXXXXX")"
echo "Baseline: $baseline"
mkdir -p "$work/baseline"
git archive "$baseline" | tar -x -C "$work/baseline"

# semver-checks for the crate at a source directory: its log in $2.log, one
# line per failed lint and item in $2 (paths and line numbers dropped, so
# two checkouts compare); its exit status.
failures() {
    cargo semver-checks check-release --manifest-path "$1/Cargo.toml" -p "$package" \
        --baseline-root "$work/baseline" --release-type minor > "$2.log" 2>&1
    local status=$?
    # The log is colored in CI (CARGO_TERM_COLOR): drop the escapes first.
    awk '
        { gsub(/\033\[[0-9;]*m/, "") }
        /^--- failure / { lint = $3; sub(/:$/, "", lint); next }
        /^Failed in:/ { listing = 1; next }
        listing && /^  / {
            item = $0
            sub(/^ +/, "", item)
            sub(/,? (previously )?in (file )?\/.*$/, "", item)
            print lint ": " item
            next
        }
        { listing = 0 }
    ' "$2.log" | sort -u > "$2"
    return "$status"
}

if failures . "$work/head"; then
    tail -n 3 "$work/head.log"
    exit 0
fi
cat "$work/head.log"
if [ ! -s "$work/head" ]; then
    echo "::error::cargo-semver-checks failed without an API finding (above)."
    exit 1
fi

base="${BASE_REF:-}"
if [ -z "$base" ]; then
    case "${EVENT:-}" in
        pull_request) [ -z "${PR_BASE_SHA:-}" ] || base="$(git merge-base HEAD "$PR_BASE_SHA")" ;;
        merge_group) base="${QUEUE_BASE_SHA:-}" ;;
        push) [ "${PUSH_BEFORE:-}" = "0000000000000000000000000000000000000000" ] || base="${PUSH_BEFORE:-}" ;;
    esac
fi
if [ -n "$base" ]; then
    echo "Checking the base commit $base the same way."
    mkdir -p "$work/base-src"
    git archive "$base" | tar -x -C "$work/base-src"
    failures "$work/base-src" "$work/base"
    new="$(comm -23 "$work/head" "$work/base")"
    if [ -z "$new" ]; then
        echo "Every incompatibility above is already in the base commit $base (merged earlier, labelled breaking): none is new in this change."
        exit 0
    fi
    echo "New in this change:"
    printf '%s\n' "$new" | sed 's/^/  /'
fi

number="${PR_NUMBER:-}"
case "${EVENT:-}" in
    merge_group)
        if [[ "${QUEUE_REF:-}" =~ /pr-([0-9]+)- ]]; then number="${BASH_REMATCH[1]}"; else number=""; fi ;;
    push)
        number="$(gh api "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/pulls" --jq '.[0].number // empty')" ;;
esac
if [ -z "$number" ]; then
    echo "::error::An incompatible API change against $baseline, and no pull request to read the label breaking from."
    exit 1
fi
labels="$(gh pr view "$number" --repo "$GITHUB_REPOSITORY" --json labels --jq '[.labels[].name] | join(",")')"
case ",$labels," in
    *,breaking,*) ;;
    *)
        echo "::error::Pull request #$number changes the public API incompatibly against $baseline (above). Keep it compatible, or ask the Maintainer for the label breaking and add a changelog fragment with an ### Upgrading note."
        exit 1 ;;
esac
upgrading=""
while IFS= read -r file; do
    case "$file" in
        changelog.d/*.md)
            if [ -f "$file" ] && grep -q '^### Upgrading' "$file"; then upgrading="$file"; fi ;;
    esac
done < <(gh pr view "$number" --repo "$GITHUB_REPOSITORY" --json files --jq '.files[].path')
if [ -z "$upgrading" ]; then
    echo "::error::Pull request #$number is labelled breaking but adds no changelog fragment with an ### Upgrading note."
    exit 1
fi
echo "Incompatible change accepted: labelled breaking, Upgrading note in $upgrading."
