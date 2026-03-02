#!/usr/bin/env bash
# inventory.sh — checks that every repo the agent app is installed on has the
# expected branch protection rulesets. Exits non-zero if any are missing.
#
# Called by .github/workflows/inventory.yml with GH_APP_ID and GH_APP_PEM_B64
# set from Actions secrets. Can also be run locally with those vars exported.
set -euo pipefail

if [[ -z "${GH_APP_ID:-}" || -z "${GH_APP_PEM_B64:-}" ]]; then
  echo "Error: GH_APP_ID and GH_APP_PEM_B64 must be set." >&2
  echo "Run install.sh to populate them." >&2
  exit 1
fi

# ── Build JWT ─────────────────────────────────────────────────────────────────
APP_PEM=$(printf '%s' "$GH_APP_PEM_B64" | base64 -d)
NOW=$(date +%s)
EXP=$((NOW + 540))

b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

HEADER=$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | b64url)
PAYLOAD=$(printf '{"iat":%d,"exp":%d,"iss":%d}' "$NOW" "$EXP" "$GH_APP_ID" | b64url)

TMPKEY=$(mktemp); chmod 600 "$TMPKEY"
printf '%s' "$APP_PEM" > "$TMPKEY"
SIG=$(printf '%s.%s' "$HEADER" "$PAYLOAD" \
  | openssl dgst -binary -sha256 -sign "$TMPKEY" | b64url)
rm -f "$TMPKEY"
JWT="${HEADER}.${PAYLOAD}.${SIG}"

# ── Get installation ID and token ─────────────────────────────────────────────
INSTALL_ID=$(curl -sSf --fail-with-body \
  -H "Authorization: Bearer ${JWT}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/app/installations" \
  | jq -r '.[0].id // empty')

if [[ -z "$INSTALL_ID" ]]; then
  echo "Error: no installation found for this app." >&2
  exit 1
fi

INSTALL_TOKEN=$(curl -sSf --fail-with-body -X POST \
  -H "Authorization: Bearer ${JWT}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/app/installations/${INSTALL_ID}/access_tokens" \
  | jq -r '.token')

if [[ -z "$INSTALL_TOKEN" || "$INSTALL_TOKEN" == "null" ]]; then
  echo "Error: failed to obtain installation token." >&2
  exit 1
fi

# ── Check each installed repo for expected rulesets ───────────────────────────
REPOS=$(curl -sSf --fail-with-body \
  -H "Authorization: Bearer ${INSTALL_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/installation/repositories" \
  | jq -r '.repositories[].full_name')

FAIL=0
while IFS= read -r repo; do
  COUNT=$(curl -sSf --fail-with-body \
    -H "Authorization: Bearer ${INSTALL_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/${repo}/rulesets" \
    | jq '[.[] | select(
        .name == "agent-gh-access-apps-blocked-from-non-ai-branches" or
        .name == "agent-gh-access-apps-must-sign"
      )] | length')
  if [[ "$COUNT" -eq 2 ]]; then
    echo "PASS  ${repo}"
  else
    echo "FAIL  ${repo} — missing rulesets (found ${COUNT}/2)"
    FAIL=1
  fi
done <<< "$REPOS"

if [[ "$FAIL" -eq 1 ]]; then
  echo ""
  echo "One or more repos are missing required rulesets." >&2
  echo "Run ./onboard-repo.sh <repo> for each failing repo." >&2
  exit 1
fi

echo ""
echo "All installed repos have required branch protection rulesets."

# ── Update inventory branch ───────────────────────────────────────────────────
# Only runs inside GitHub Actions (GITHUB_TOKEN is available).
# Pushes onboarded-repos.txt to a dedicated agent branch via the GitHub API
# so that the push is signed and doesn't require pushing to main.
# First line is a comment with the app ID — if it changes (app recreated),
# the file is reset so the inventory reflects only the current app.
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  echo "Updating inventory branch..."
  OWNER_LOGIN=$(curl -sSf --fail-with-body \
    -H "Authorization: Bearer ${INSTALL_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/installation/repositories" \
    | jq -r '.repositories[0].owner.login')
  FORK_REPO="${OWNER_LOGIN}/agent-github-access"
  INV_BRANCH="x-ai/${OWNER_LOGIN}/inventory---internal-do-not-delete"
  HEADER_LINE="# app-id:${GH_APP_ID}"

  # Fetch current inventory from branch if it exists
  echo "Fetching current inventory..."
  CURRENT_INV=$(curl -sSf --fail-with-body \
    -H "Authorization: Bearer ${INSTALL_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/${FORK_REPO}/contents/onboarded-repos.txt?ref=${INV_BRANCH}" \
    | jq -r '.content' | base64 -d || true)

  # Reset if app ID changed or branch doesn't exist yet
  if [[ -z "$CURRENT_INV" ]] || [[ "$(printf '%s' "$CURRENT_INV" | head -1)" != "$HEADER_LINE" ]]; then
    NEW_INV="${HEADER_LINE}"$'\n'
    INITIALIZING=true
  else
    NEW_INV="$CURRENT_INV"
    INITIALIZING=false
  fi

  # Merge current repos into inventory (cumulative, no removals)
  while IFS= read -r repo; do
    if ! printf '%s' "$NEW_INV" | grep -qxF "$repo"; then
      NEW_INV="${NEW_INV}${repo}"$'\n'
    fi
  done <<< "$REPOS"

  # Only update if content changed
  if [[ "$NEW_INV" != "$CURRENT_INV" ]]; then
    # Upload blob
    echo "Uploading blob..."
    BLOB_CONTENT=$(printf '%s' "$NEW_INV" | base64 | tr -d '\n')
    BLOB_SHA=$(curl -sSf --fail-with-body -X POST \
      -H "Authorization: Bearer ${INSTALL_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Content-Type: application/json" \
      -d "{\"content\":\"${BLOB_CONTENT}\",\"encoding\":\"base64\"}" \
      "https://api.github.com/repos/${FORK_REPO}/git/blobs" \
      | jq -r '.sha')

    if [[ -z "$BLOB_SHA" || "$BLOB_SHA" == "null" ]]; then
      echo "Error: failed to upload blob (got empty/null sha)." >&2
      exit 1
    fi

    # Get parent commit and base tree
    # On init: orphan from main with no base_tree so only onboarded-repos.txt is present.
    # On update: build on the inventory branch's own HEAD to avoid inheriting main's files.
    MAIN_SHA=$(curl -sSf --fail-with-body \
      -H "Authorization: Bearer ${INSTALL_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/${FORK_REPO}/git/ref/heads/main" \
      | jq -r '.object.sha')

    if [[ "$INITIALIZING" == "true" ]]; then
      PARENT_SHA="$MAIN_SHA"
      TREE_PAYLOAD="{\"tree\":[{\"path\":\"onboarded-repos.txt\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"${BLOB_SHA}\"}]}"
    else
      ENCODED_BRANCH=$(printf '%s' "$INV_BRANCH" | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))')
      PARENT_SHA=$(curl -sSf --fail-with-body \
        -H "Authorization: Bearer ${INSTALL_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${FORK_REPO}/git/ref/heads/${ENCODED_BRANCH}" \
        | jq -r '.object.sha')
      if [[ -z "$PARENT_SHA" || "$PARENT_SHA" == "null" ]]; then
        echo "Error: failed to fetch inventory branch ref (got empty/null sha)." >&2
        exit 1
      fi
      BASE_TREE=$(curl -sSf --fail-with-body \
        -H "Authorization: Bearer ${INSTALL_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${FORK_REPO}/git/commits/${PARENT_SHA}" \
        | jq -r '.tree.sha')
      TREE_PAYLOAD="{\"base_tree\":\"${BASE_TREE}\",\"tree\":[{\"path\":\"onboarded-repos.txt\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"${BLOB_SHA}\"}]}"
    fi

    # Create tree and commit
    echo "Creating commit..."
    NEW_TREE=$(curl -sSf --fail-with-body -X POST \
      -H "Authorization: Bearer ${INSTALL_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Content-Type: application/json" \
      -d "$TREE_PAYLOAD" \
      "https://api.github.com/repos/${FORK_REPO}/git/trees" \
      | jq -r '.sha')

    if [[ -z "$NEW_TREE" || "$NEW_TREE" == "null" ]]; then
      echo "Error: failed to create git tree (got empty/null sha)." >&2
      exit 1
    fi

    NEW_COMMIT=$(curl -sSf --fail-with-body -X POST \
      -H "Authorization: Bearer ${INSTALL_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Content-Type: application/json" \
      -d "{\"message\":\"chore: update onboarded-repos inventory\",\"tree\":\"${NEW_TREE}\",\"parents\":[\"${PARENT_SHA}\"]}" \
      "https://api.github.com/repos/${FORK_REPO}/git/commits" \
      | jq -r '.sha')

    if [[ -z "$NEW_COMMIT" || "$NEW_COMMIT" == "null" ]]; then
      echo "Error: failed to create git commit (got empty/null sha)." >&2
      exit 1
    fi

    # Create or force-update the inventory branch
    echo "Updating branch ref..."
    ENCODED_BRANCH=$(printf '%s' "$INV_BRANCH" | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))')
    BRANCH_EXISTS=$(curl -sSf --fail-with-body \
      -H "Authorization: Bearer ${INSTALL_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/${FORK_REPO}/git/ref/heads/${ENCODED_BRANCH}" \
      | jq -r '.ref // empty' || true)

    if [[ -n "$BRANCH_EXISTS" ]]; then
      curl -sSf --fail-with-body -X PATCH \
        -H "Authorization: Bearer ${INSTALL_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Content-Type: application/json" \
        -d "{\"sha\":\"${NEW_COMMIT}\",\"force\":true}" \
        "https://api.github.com/repos/${FORK_REPO}/git/refs/heads/${ENCODED_BRANCH}"
    else
      curl -sSf --fail-with-body -X POST \
        -H "Authorization: Bearer ${INSTALL_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Content-Type: application/json" \
        -d "{\"ref\":\"refs/heads/${INV_BRANCH}\",\"sha\":\"${NEW_COMMIT}\"}" \
        "https://api.github.com/repos/${FORK_REPO}/git/refs"
    fi

    echo "Inventory updated on branch ${INV_BRANCH}."
  else
    echo "Inventory unchanged."
  fi
fi
