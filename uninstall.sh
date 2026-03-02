#!/usr/bin/env bash
# uninstall.sh — removes all agent-github-access state after the GitHub App has
# been deleted. Run this after deleting the app in the GitHub UI.
#
# What it does:
#   1. Fetches the inventory from the x-ai/<owner>/inventory---internal-do-not-delete branch
#   2. Verifies the GitHub App no longer exists (polls until confirmed)
#   3. Deletes GH_APP_ID and GH_APP_PEM secrets from the agent-github-access fork
#   4. Deletes the two agent-gh-access-* rulesets from every repo in the inventory
#
# Requires: gh CLI authenticated with the fine-grained PAT used during setup
#   (Administration read/write + Secrets read/write on agent-github-access fork)
set -euo pipefail

OWNER_LOGIN=$(gh api user --jq '.login')
FORK_REPO="${OWNER_LOGIN}/agent-github-access"
INV_BRANCH="x-ai/${OWNER_LOGIN}/inventory---internal-do-not-delete"

# ── Fetch latest inventory from inventory branch ──────────────────────────────
echo "Fetching latest inventory from ${FORK_REPO} (branch: ${INV_BRANCH})…"
INVENTORY_CONTENT=$(gh api \
  "/repos/${FORK_REPO}/contents/onboarded-repos.txt?ref=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${INV_BRANCH}', safe=''))")" \
  --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)

if [[ -z "$INVENTORY_CONTENT" ]]; then
  echo "Error: inventory not found on branch ${INV_BRANCH}." >&2
  echo "  Ensure the inventory workflow has run at least once." >&2
  exit 1
fi
echo "  ✓ Inventory fetched."
echo ""

# ── Read app ID and derive slug ───────────────────────────────────────────────
HEADER=$(printf '%s' "$INVENTORY_CONTENT" | head -1)
if [[ "$HEADER" != "# app-id:"* ]]; then
  echo "Error: inventory has unexpected format (first line: ${HEADER})" >&2
  exit 1
fi

APP_ID="${HEADER#\# app-id:}"
APP_SLUG="${OWNER_LOGIN}-agent"

echo "App ID:   ${APP_ID}"
echo "App slug: ${APP_SLUG}"
echo "Owner:    ${OWNER_LOGIN}"
echo ""

# ── Verify the app has been deleted ──────────────────────────────────────────
# GET /apps/{slug} is public and returns 404 once the app is gone.
echo "Checking if GitHub App '${APP_SLUG}' still exists…"
while true; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/apps/${APP_SLUG}")
  if [[ "$STATUS" == "404" ]]; then
    echo "  ✓ App not found — confirmed deleted."
    break
  fi
  echo "  App still exists (HTTP ${STATUS})."
  echo "  Delete it at: https://github.com/settings/apps/${APP_SLUG}"
  echo "    Settings → Developer settings → GitHub Apps → ${APP_SLUG}"
  echo "    → Edit → Advanced → Delete GitHub App"
  echo ""
  printf "  Press Enter to check again, or Ctrl-C to abort: "
  read -r
done
echo ""

# ── Delete secrets from fork ──────────────────────────────────────────────────
echo "Deleting secrets from ${FORK_REPO}…"
for secret in GH_APP_ID GH_APP_PEM; do
  if gh api "/repos/${FORK_REPO}/actions/secrets/${secret}" --silent 2>/dev/null; then
    gh api --method DELETE "/repos/${FORK_REPO}/actions/secrets/${secret}" --silent
    echo "  ✓ Deleted secret: ${secret}"
  else
    echo "  – Secret already absent: ${secret}"
  fi
done
echo ""

# ── Delete rulesets from every inventoried repo ───────────────────────────────
REPOS=$(printf '%s' "$INVENTORY_CONTENT" | tail -n +2)
if [[ -z "$REPOS" ]]; then
  echo "No repos in inventory — nothing to clean up."
else
  echo "Removing rulesets from inventoried repos…"
  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    for ruleset in \
      "agent-gh-access-apps-blocked-from-non-ai-branches" \
      "agent-gh-access-apps-must-sign"
    do
      ruleset_id=$(gh api "/repos/${repo}/rulesets" \
        --jq ".[] | select(.name == \"${ruleset}\") | .id" 2>/dev/null | head -1 || true)
      if [[ -n "$ruleset_id" ]]; then
        gh api --method DELETE "/repos/${repo}/rulesets/${ruleset_id}" --silent
        echo "  ✓ ${repo}: deleted ${ruleset}"
      else
        echo "  – ${repo}: ${ruleset} not found"
      fi
    done
  done <<< "$REPOS"
fi
echo ""

echo "Cleanup complete."
echo "You may now delete your agent-github-access fork if it is no longer needed."
