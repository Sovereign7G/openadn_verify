#!/bin/sh
# publish.sh -- one-shot publish for openadn_verify. Run AFTER `gh auth login` succeeds.
#
#   gh auth login          # once (interactive: GitHub.com -> HTTPS -> web browser OR paste a token)
#   ./publish.sh
#
# Does: create the public repo, push main + tag, create the release with both assets, then print the
# public key to cross-publish. Safe to re-run: it checks auth, detects an existing origin, and skips an
# existing release instead of erroring.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2

VER="1.0.0"
TAG="openadn-verify-v$VER"
ARCHIVE="dist/openadn_verify-$VER.tar.gz"
SIG="$ARCHIVE.sig"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh (GitHub CLI) not found. Install it or create the repo in a browser and push manually." >&2
  exit 2
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "Not authenticated. Run this first, and FINISH it (do not Ctrl-C at the browser step):"
  echo
  echo "    gh auth login      # GitHub.com -> HTTPS -> 'Login with a web browser'"
  echo
  echo "If the browser does not open, choose 'Paste an authentication token' and paste a PAT instead."
  exit 1
fi

if [ ! -f "$ARCHIVE" ]; then
  echo "Missing $ARCHIVE. Build it first:  sh make_release.sh --version $VER" >&2
  exit 2
fi

echo "Authenticated as: $(gh api user --jq .login 2>/dev/null || echo '?')"

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "Creating public repo 'openadn_verify' and pushing main..."
  gh repo create openadn_verify --public --source=. --remote=origin --push || exit 1
else
  echo "origin already set:"; git remote -v
  git push -u origin main || exit 1
fi

echo "Pushing tag $TAG..."
git push origin "$TAG" || exit 1

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "Release $TAG already exists; skipping create."
else
  echo "Creating release $TAG with both assets..."
  gh release create "$TAG" "$ARCHIVE" "$SIG" \
      --title "OpenADN verification bundle v$VER" --notes-file README.md || exit 1
fi

echo
echo "============================================================"
echo "Published. CROSS-PUBLISH this public key somewhere OUTSIDE"
echo "the archive (release body / gist / personal site):"
echo
cat "dist/openadn_verify-$VER/release_pubkey.txt"
echo
echo "Archive sha256:"
sha256sum "$ARCHIVE"
echo "============================================================"
echo
echo "Then let METRIC.md stand as-is (OPEN since 2026-10-03) until a stranger reports."
