#!/usr/bin/env bash
# Tags HEAD with the next release and creates its GitHub Release.
#
# usage: .github/release.sh [patch|minor|major]   (default patch; the first release is v0.1.0)
# needs: a full clone (fetch-depth: 0), gh, GH_TOKEN (with actions: write); pushes the tag to origin.
# Called by release.yml and by the engine drift job, whose pushes do not trigger other workflows.
set -euo pipefail

bump=${1:-patch}
git fetch --tags --force origin

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged: $(git tag --points-at HEAD 'v*' | head -1)"
  exit 0
fi

latest=$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1 || true)
if [ -z "$latest" ]; then
  next=v0.1.0
else
  IFS=. read -r major minor patch <<< "${latest#v}"
  case "$bump" in
    major) next="v$((major + 1)).0.0" ;;
    minor) next="v$major.$((minor + 1)).0" ;;
    patch) next="v$major.$minor.$((patch + 1))" ;;
    *) echo "unknown bump: $bump (patch, minor or major)" >&2; exit 1 ;;
  esac
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$next" -m "$next"
git push origin "$next"
gh release create "$next" --verify-tag --generate-notes --title "$next"
# A tag and a Release made with GITHUB_TOKEN start no workflow: build the binaries explicitly.
gh workflow run goreleaser.yml -f tag="$next"
echo "released $next"
