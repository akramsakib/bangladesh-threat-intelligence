#!/usr/bin/env bash
# =============================================================================
# ThreatNexus BD — one-command publish to GitHub + Pages
#
#   ./tools/publish.sh
#
# Creates the repository, pushes this history, enables GitHub Pages with the
# Actions build source, waits for the first deploy and prints the live URL.
#
# The token is read into a shell variable only. It is never written to disk,
# never stored in .git/config, and never printed. The remote is left as a clean
# HTTPS URL with no embedded credentials.
# =============================================================================
set -euo pipefail

REPO_NAME="${REPO_NAME:-bangladesh-threat-intelligence}"
VISIBILITY="${VISIBILITY:-public}"
API="https://api.github.com"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()   { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

cd "$(dirname "$0")/.."
[ -d .git ] || die "no git repository here — run this from the project root"

# ---------------------------------------------------------------- credentials
bold "ThreatNexus BD — publish"
echo

if [ -n "${GITHUB_TOKEN:-}" ]; then
  TOKEN="$GITHUB_TOKEN"
  ok "using token from \$GITHUB_TOKEN"
else
  printf '  GitHub token (input hidden): '
  read -rs TOKEN
  echo
fi

# strip whitespace/newlines that survive a bad copy-paste
TOKEN="$(printf '%s' "$TOKEN" | tr -d '[:space:]')"
[ -n "$TOKEN" ] || die "no token supplied"

auth() { curl -sS -m 30 -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" "$@"; }

# ------------------------------------------------------------------- identity
USER_JSON="$(auth "$API/user" || true)"
LOGIN="$(printf '%s' "$USER_JSON" | sed -n 's/.*"login"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"

if [ -z "$LOGIN" ]; then
  echo
  die "GitHub rejected the token (401).
     · Generate a CLASSIC token at https://github.com/settings/tokens
     · Tick BOTH scopes:  repo   and   workflow
     · Copy it in one piece — a line break mid-token is the usual culprit
     · Tokens are shown once; if the page was closed early it will be partial"
fi
ok "authenticated as $LOGIN"

SCOPES="$(auth -D - -o /dev/null "$API/user" | tr -d '\r' | sed -n 's/^[Xx]-[Oo][Aa]uth-[Ss]copes:[[:space:]]*//p')"
case "$SCOPES" in
  *repo*) ok "scope 'repo' present" ;;
  *)      warn "scope 'repo' not detected (scopes: ${SCOPES:-none}) — repo creation may fail" ;;
esac
case "$SCOPES" in
  *workflow*) ok "scope 'workflow' present" ;;
  *)          warn "scope 'workflow' MISSING — the push will be rejected because it contains .github/workflows/" ;;
esac

# --------------------------------------------------------------- create repo
echo
bold "Repository"
EXISTING="$(auth -o /dev/null -w '%{http_code}' "$API/repos/$LOGIN/$REPO_NAME")"

if [ "$EXISTING" = "200" ]; then
  warn "$LOGIN/$REPO_NAME already exists — pushing into it"
else
  PRIVATE=false; [ "$VISIBILITY" = "private" ] && PRIVATE=true
  BODY=$(printf '{"name":"%s","description":"Bangladesh-focused cyber threat intelligence console — 19 sourced actor dossiers mapped to MITRE ATT&CK, national incident record, sector exposure, live feed, hunt packs, IOC enrichment and a STIX 2.1 / TAXII feed.","homepage":"https://%s.github.io/%s/","private":%s,"has_issues":true,"has_wiki":false,"has_projects":false}' \
        "$REPO_NAME" "$LOGIN" "$REPO_NAME" "$PRIVATE")
  CODE="$(auth -o /tmp/tnbd_create.json -w '%{http_code}' -X POST "$API/user/repos" -d "$BODY")"
  case "$CODE" in
    201) ok "created $LOGIN/$REPO_NAME ($VISIBILITY)" ;;
    *)   die "repo creation failed (HTTP $CODE): $(sed -n 's/.*"message"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /tmp/tnbd_create.json | head -1)" ;;
  esac
  rm -f /tmp/tnbd_create.json
fi

# ---------------------------------------------------------------------- push
echo
bold "Push"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$LOGIN/$REPO_NAME.git"
git branch -M main

# credentials passed in-memory for this invocation only
if git -c credential.helper= \
       -c "http.https://github.com/.extraheader=Authorization: Basic $(printf 'x-access-token:%s' "$TOKEN" | base64 | tr -d '\n')" \
       push -u origin main --quiet; then
  ok "pushed $(git rev-list --count HEAD) commits to origin/main"
else
  die "push failed — if the error mentions 'workflow', the token lacks the 'workflow' scope"
fi

# --------------------------------------------------------------------- pages
echo
bold "GitHub Pages"
PAGES_CODE="$(auth -o /tmp/tnbd_pages.json -w '%{http_code}' -X POST "$API/repos/$LOGIN/$REPO_NAME/pages" \
  -d '{"build_type":"workflow"}')"
case "$PAGES_CODE" in
  201|204) ok "Pages enabled with the Actions build source" ;;
  409)     ok "Pages already enabled" ;;
  *)       warn "could not enable Pages automatically (HTTP $PAGES_CODE)
     Enable it by hand: Settings → Pages → Source: GitHub Actions" ;;
esac
rm -f /tmp/tnbd_pages.json

# ------------------------------------------------------------- wait for build
echo
bold "First deployment"
echo "  workflow: https://github.com/$LOGIN/$REPO_NAME/actions"
printf '  waiting'
URL=""
for _ in $(seq 1 60); do
  sleep 10
  printf '.'
  STATE="$(auth "$API/repos/$LOGIN/$REPO_NAME/actions/runs?per_page=1" \
           | sed -n 's/.*"conclusion"[[:space:]]*:[[:space:]]*\("\([^"]*\)"\|null\).*/\2/p' | head -1)"
  case "$STATE" in
    success) URL="$(auth "$API/repos/$LOGIN/$REPO_NAME/pages" | sed -n 's/.*"html_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"; break ;;
    failure|cancelled|timed_out) echo; die "the deploy workflow ended with: $STATE — see the Actions tab" ;;
  esac
done
echo

if [ -n "$URL" ]; then
  ok "live at $URL"
else
  warn "still building — it usually completes within 2-3 minutes"
  echo "     https://$LOGIN.github.io/$REPO_NAME/"
fi

echo
bold "Done"
echo "  repo   https://github.com/$LOGIN/$REPO_NAME"
echo "  site   https://$LOGIN.github.io/$REPO_NAME/"
echo "  stix   https://$LOGIN.github.io/$REPO_NAME/api/stix.json"
echo
echo "  Revoke the token when finished: https://github.com/settings/tokens"
