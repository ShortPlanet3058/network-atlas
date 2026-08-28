#!/usr/bin/env bash
# Publish wiki/*.md to the repository's GitHub wiki.
#
# The wiki is a separate git repository (<repo>.wiki.git). Keeping the sources
# here means they are reviewed with the code and cannot silently drift from it;
# this script is what pushes them.
#
# GitHub does not create the wiki repository until the first page exists, and
# that can only be done through the web UI. If this script reports the wiki as
# missing, create any page at the URL it prints, then run it again.

set -euo pipefail

REPO="${WIKI_REPO:-git@github.com:ShortPlanet3058/network-atlas.wiki.git}"
SOURCE="${WIKI_SOURCE:-wiki}"
MESSAGE="${WIKI_MESSAGE:-Update documentation}"

cd "$(git rev-parse --show-toplevel)"

if [[ ! -d "$SOURCE" ]]; then
    echo "No $SOURCE/ directory to publish." >&2
    exit 1
fi

if ! git ls-remote "$REPO" >/dev/null 2>&1; then
    cat >&2 <<MSG
The wiki repository does not exist yet.

GitHub creates it only once the first page has been saved through the web UI:

    https://github.com/ShortPlanet3058/network-atlas/wiki

Create any page there (this script overwrites it), then run this again.
MSG
    exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git clone --quiet --depth 1 "$REPO" "$work/wiki"

# Mirror the source directory: pages removed here are removed there too.
find "$work/wiki" -maxdepth 1 -name '*.md' -delete
cp "$SOURCE"/*.md "$work/wiki/"

# Read the committer identity before leaving the source repository, so wiki
# commits are attributed to whoever ran this rather than to a placeholder.
author_name="$(git config user.name || true)"
author_email="$(git config user.email || true)"

cd "$work/wiki"
if [[ -z "$(git status --porcelain)" ]]; then
    echo "Wiki is already up to date."
    exit 0
fi

git add -A
git ${author_name:+-c "user.name=$author_name"} \
    ${author_email:+-c "user.email=$author_email"} \
    commit --quiet -m "$MESSAGE"
git push --quiet origin HEAD

printf 'Published %d page(s) to the wiki.\n' "$(ls -1 *.md | wc -l)"
echo "https://github.com/ShortPlanet3058/network-atlas/wiki"
