#!/usr/bin/env bash
#
# apply-baseline.sh - apply the security baseline to a GitHub repository.
#
# Applies: General settings, Actions settings, security features
# (Dependabot, secret scanning, push protection, CodeQL default setup,
# private vulnerability reporting) and the three rulesets.
#
# Safe to run more than once: existing rulesets with the same name are
# updated instead of duplicated.
#
# Requirements: GitHub CLI (gh), logged in with `gh auth login`,
# and admin rights on the repository.
#
# Usage:
#   ./apply-baseline.sh OWNER/REPO [options]
#
# Options:
#   --check NAME      Required status check (CI job name). Default: check
#   --no-check        Don't require a status check
#   --no-codeql-gate  Don't block PRs on new CodeQL alerts
#   --team            Collaborator mode: 1 approval, code owner review,
#                     approval of the most recent push
#   --dry-run         Show what would be changed without changing anything
#   -h, --help        Show this help
#
# Examples:
#   ./apply-baseline.sh OWNER/REPO
#   ./apply-baseline.sh OWNER/REPO --check build
#   ./apply-baseline.sh OWNER/REPO --check build --dry-run

set -uo pipefail

# Ruleset names. Keep these the same as any rulesets created by hand,
# so the script updates them rather than creating duplicates.
RULESET_INTEGRITY="main – integrity"
RULESET_REVIEW="main – review"
RULESET_TAGS="release tags"

# GitHub Actions' app ID, so only GitHub Actions can report the status check.
GITHUB_ACTIONS_APP_ID=15368

REPO=""
CHECK="check"
CODEQL_GATE=1
TEAM=0
DRY=0
FAILED=()

usage() { sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die() { echo "Error: $*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --check) [[ $# -ge 2 ]] || die "--check needs a job name"; CHECK="$2"; shift 2 ;;
    --no-check) CHECK=""; shift ;;
    --no-codeql-gate) CODEQL_GATE=0; shift ;;
    --team) TEAM=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage 0 ;;
    -*) echo "Unknown option: $1" >&2; usage 1 ;;
    *) [[ -z $REPO ]] || die "Only one repository at a time"; REPO="$1"; shift ;;
  esac
done

[[ -n $REPO ]] || usage 1
[[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "Repository must look like OWNER/REPO"
[[ -z $CHECK || $CHECK =~ ^[A-Za-z0-9\ ._/()-]+$ ]] || die "Check name contains unsupported characters"
command -v gh >/dev/null || die "GitHub CLI (gh) is not installed"
gh auth status >/dev/null 2>&1 || die "Not logged in. Run: gh auth login"

# --- helpers ---------------------------------------------------------------

# api METHOD PATH [gh api args...]   (PATH is relative to repos/OWNER/REPO)
api() {
  local method=$1 path=$2; shift 2
  if ((DRY)); then
    echo "    would call: $method /repos/$REPO$path"
    if [[ " $* " == *" --input - "* ]]; then sed 's/^/      /'; fi
    return 0
  fi
  gh api -X "$method" "repos/$REPO$path" -H "Accept: application/vnd.github+json" "$@"
}

# step DESCRIPTION COMMAND...   Runs a command, reports success or failure, keeps going.
step() {
  local desc=$1 out; shift
  if out=$("$@" 2>&1); then
    if ((DRY)); then
      echo "  • $desc"
      [[ -n $out ]] && echo "$out"
    else
      echo "  ✓ $desc"
    fi
    return 0
  else
    echo "  ✗ $desc"
    echo "$out" | grep -v '^[[:space:]]*$' | head -3 | sed 's/^/      /'
    FAILED+=("$desc")
    return 1
  fi
}

# upsert_ruleset NAME   (ruleset JSON on stdin) - update if it exists, else create.
upsert_ruleset() {
  local name=$1 json id=""
  json=$(cat)
  if ! ((DRY)); then
    id=$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$name\") | .id" 2>/dev/null | head -1)
  fi
  if [[ -n $id ]]; then
    api PUT "/rulesets/$id" --input - <<<"$json"
  else
    api POST "/rulesets" --input - <<<"$json"
  fi
}

# --- checks ----------------------------------------------------------------

if ((DRY)); then
  echo "DRY RUN for $REPO: nothing will be changed."
  VISIBILITY="(not checked in dry run)"
else
  VISIBILITY=$(gh api "repos/$REPO" --jq '.visibility' 2>/dev/null) \
    || die "Can't read $REPO. Check the name and that you have admin access."
  ADMIN=$(gh api "repos/$REPO" --jq '.permissions.admin' 2>/dev/null)
  [[ $ADMIN == "true" ]] || die "You need admin access to $REPO"
fi

echo "Applying security baseline to $REPO (visibility: $VISIBILITY)"
if [[ $VISIBILITY == "private" ]]; then
  echo "  Note: on a free plan, rulesets and some security features aren't"
  echo "  available for private repositories. Those steps will show ✗."
fi

# --- 1. General ------------------------------------------------------------

echo
echo "General"
step "Features and pull request settings" api PATCH "" --input - <<'EOF'
{
  "has_issues": true,
  "has_wiki": false,
  "has_projects": false,
  "has_discussions": false,
  "allow_merge_commit": false,
  "allow_squash_merge": true,
  "allow_rebase_merge": false,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "PR_BODY",
  "allow_auto_merge": true,
  "allow_update_branch": true,
  "delete_branch_on_merge": true,
  "web_commit_signoff_required": false
}
EOF

# --- 2. Actions ------------------------------------------------------------

echo
echo "Actions"
step "Allow GitHub-owned and verified-creator actions only" \
  api PUT "/actions/permissions" --input - <<'EOF'
{ "enabled": true, "allowed_actions": "selected" }
EOF
step "Allowed actions list" api PUT "/actions/permissions/selected-actions" --input - <<'EOF'
{ "github_owned_allowed": true, "verified_allowed": true, "patterns_allowed": [] }
EOF
step "Workflow token read-only, can't approve PRs" \
  api PUT "/actions/permissions/workflow" --input - <<'EOF'
{ "default_workflow_permissions": "read", "can_approve_pull_request_reviews": false }
EOF
if [[ $VISIBILITY != "private" ]]; then
  step "Require approval for fork PR workflows from all external contributors" \
    api PUT "/actions/permissions/fork-pr-contributor-approval" --input - <<'EOF'
{ "approval_policy": "all_external_contributors" }
EOF
fi

# --- 3. Security features --------------------------------------------------

echo
echo "Security"
step "Private vulnerability reporting" api PUT "/private-vulnerability-reporting"
step "Dependabot alerts" api PUT "/vulnerability-alerts"
step "Dependabot security updates" api PUT "/automated-security-fixes"
step "Secret scanning and push protection" api PATCH "" --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF
CODEQL_OK=0
if step "CodeQL default setup" api PATCH "/code-scanning/default-setup" --input - <<'EOF'
{ "state": "configured" }
EOF
then CODEQL_OK=1; fi

# --- 4. Rulesets -----------------------------------------------------------

echo
echo "Rulesets"
step "$RULESET_INTEGRITY" upsert_ruleset "$RULESET_INTEGRITY" <<EOF
{
  "name": "$RULESET_INTEGRITY",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_signatures" },
    { "type": "required_linear_history" }
  ]
}
EOF

if ((TEAM)); then APPROVALS=1; TEAMFLAG=true; else APPROVALS=0; TEAMFLAG=false; fi

REVIEW_RULES='
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": '"$APPROVALS"',
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": '"$TEAMFLAG"',
        "require_last_push_approval": '"$TEAMFLAG"',
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash"] } }'

if [[ -n $CHECK ]]; then
  REVIEW_RULES+=',
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [ { "context": "'"$CHECK"'", "integration_id": '"$GITHUB_ACTIONS_APP_ID"' } ] } }'
fi

if ((CODEQL_GATE)) && { ((CODEQL_OK)) || ((DRY)); }; then
  REVIEW_RULES+=',
    { "type": "code_scanning", "parameters": {
        "code_scanning_tools": [ {
          "tool": "CodeQL",
          "security_alerts_threshold": "high_or_higher",
          "alerts_threshold": "errors" } ] } }'
elif ((CODEQL_GATE)); then
  echo "  - Skipping the CodeQL merge gate because CodeQL default setup failed"
fi

step "$RULESET_REVIEW" upsert_ruleset "$RULESET_REVIEW" <<EOF
{
  "name": "$RULESET_REVIEW",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [ $REVIEW_RULES
  ]
}
EOF

step "$RULESET_TAGS" upsert_ruleset "$RULESET_TAGS" <<EOF
{
  "name": "$RULESET_TAGS",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~ALL"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "update" },
    { "type": "required_signatures" }
  ]
}
EOF

# --- summary ---------------------------------------------------------------

echo
if ((DRY)); then
  echo "Dry run complete. Nothing was changed on $REPO."
  echo "Run the same command without --dry-run to apply these settings."
  exit 0
fi
if ((${#FAILED[@]})); then
  echo "Finished with ${#FAILED[@]} step(s) that didn't apply:"
  printf '  - %s\n' "${FAILED[@]}"
  echo "Set these by hand in the repository's Settings, or fix the cause and run again."
  exit 1
fi
echo "Done. All baseline settings applied to $REPO."
[[ -n $CHECK ]] && echo "Required status check: '$CHECK' (a CI job with this name must run on pull requests)."
echo
echo "Still manual (GitHub has no API for these). In Settings → Advanced Security:"
echo "  - Dependabot malware alerts: Enable"
echo "  - Grouped security updates: Enable"
echo "  - Copilot Autofix: On, if offered"
echo "  https://github.com/$REPO/settings/security_analysis"
